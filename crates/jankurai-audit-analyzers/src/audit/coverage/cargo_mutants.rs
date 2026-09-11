//! Decode the producer outcome list without recursively guessing mutation records.
use super::{build_mutation_report, normalize_rel_string, MutationOutcome, MutationReport};
use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
struct Report {
    outcomes: Vec<Outcome>,
    total_mutants: Option<usize>,
    caught: Option<usize>,
    missed: Option<usize>,
    timeout: Option<usize>,
    unviable: Option<usize>,
    success: Option<usize>,
}

#[derive(Deserialize)]
struct Outcome {
    #[serde(alias = "status", alias = "outcome", alias = "result")]
    summary: String,
    scenario: Option<Scenario>,
    mutant: Option<Mutant>,
    #[serde(alias = "file", alias = "filename", alias = "source_file")]
    path: Option<String>,
    #[serde(alias = "start_line")]
    line: Option<usize>,
    #[serde(alias = "description")]
    name: Option<String>,
}

#[derive(Deserialize)]
enum Scenario {
    Baseline,
    Mutant(Mutant),
}

#[derive(Deserialize)]
struct Mutant {
    #[serde(alias = "path", alias = "filename", alias = "source_file")]
    file: String,
    span: Option<Span>,
    line: Option<usize>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Span {
    start: Position,
}

#[derive(Deserialize)]
struct Position {
    line: usize,
}

pub(super) fn parse(text: &str) -> Result<MutationReport> {
    let report: Report = serde_json::from_str(text).context("parse cargo-mutants outcome list")?;
    let mut outcomes = Vec::new();
    let mut baseline_seen = false;
    for outcome in report.outcomes {
        if matches!(outcome.scenario, Some(Scenario::Baseline)) {
            if baseline_seen
                || outcome.summary != "Success"
                || outcome.mutant.is_some()
                || outcome.path.is_some()
            {
                bail!("cargo-mutants baseline is failed, duplicated or ambiguous");
            }
            baseline_seen = true;
            continue;
        }
        outcomes.push(outcome.normalize()?);
    }
    if outcomes.is_empty() {
        bail!("cargo-mutants report contains no mutation outcomes");
    }
    let parsed = build_mutation_report(outcomes);
    for (name, declared, actual) in [
        ("total_mutants", report.total_mutants, parsed.total),
        ("caught", report.caught, parsed.killed),
        ("missed", report.missed, parsed.survived),
        ("timeout", report.timeout, parsed.timeout),
        ("unviable", report.unviable, parsed.unviable),
        ("success", report.success, 0),
    ] {
        if declared.is_some_and(|count| count != actual) {
            bail!("incomplete cargo-mutants report: {name} disagrees with outcome records");
        }
    }
    Ok(parsed)
}

impl Outcome {
    fn normalize(self) -> Result<MutationOutcome> {
        let status = match self.summary.to_ascii_lowercase().as_str() {
            "caughtmutant" | "caught" | "killed" => "killed",
            "missedmutant" | "missed" | "survived" => "survived",
            "unviable" => "unviable",
            // Success can mean only cargo check/build ran; it is not a killed mutant.
            _ => bail!(
                "incomplete or unsupported cargo-mutants outcome: {}",
                self.summary
            ),
        };
        let scenario_mutant = match self.scenario {
            Some(Scenario::Mutant(mutant)) => Some(mutant),
            None => None,
            Some(Scenario::Baseline) => bail!("baseline is not a mutation outcome"),
        };
        if scenario_mutant.is_some() && self.mutant.is_some()
            || (scenario_mutant.is_some() || self.mutant.is_some()) && self.path.is_some()
        {
            bail!("ambiguous cargo-mutants source location");
        }
        let (path, line, name) = if let Some(mutant) = scenario_mutant.or(self.mutant) {
            let span_line = mutant.span.map(|span| span.start.line);
            if span_line.is_some() && mutant.line.is_some() && span_line != mutant.line {
                bail!("inconsistent cargo-mutants source lines");
            }
            (mutant.file, span_line.or(mutant.line), mutant.name)
        } else {
            (
                self.path
                    .context("cargo-mutants outcome lacks source path")?,
                self.line,
                self.name,
            )
        };
        if path.trim().is_empty() || line == Some(0) {
            bail!("invalid cargo-mutants source location");
        }
        Ok(MutationOutcome {
            path: normalize_rel_string(&path),
            line,
            status: status.into(),
            message: name.unwrap_or(self.summary),
        })
    }
}
