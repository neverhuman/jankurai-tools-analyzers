//! Read every declared Stryker mutant and reject ambiguous file inventories.
use super::{build_mutation_report, normalize_rel_string, MutationOutcome, MutationReport};
use anyhow::{bail, Context, Result};
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

#[derive(Deserialize)]
struct Report {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(deserialize_with = "unique_files")]
    files: BTreeMap<String, File>,
}

#[derive(Deserialize)]
struct File {
    mutants: Vec<Mutant>,
}

#[derive(Deserialize)]
struct Mutant {
    id: String,
    status: String,
    #[serde(rename = "mutatorName")]
    mutator_name: String,
    location: Location,
}

#[derive(Deserialize)]
struct Location {
    start: Position,
    end: Position,
}

#[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Position {
    line: usize,
    column: usize,
}

pub(super) fn parse(text: &str) -> Result<MutationReport> {
    let report: Report = serde_json::from_str(text).context("parse Stryker outcome inventory")?;
    let parts: Vec<_> = report.schema_version.split('.').collect();
    if !(1..=3).contains(&parts.len())
        || !matches!(parts[0], "1" | "2")
        || parts.iter().any(|part| part.parse::<u64>().is_err())
    {
        bail!("unsupported Stryker schema version");
    }
    let mut outcomes = Vec::new();
    for (path, file) in report.files {
        if path.trim().is_empty() {
            bail!("empty Stryker source path");
        }
        let mut ids = BTreeSet::new();
        for mutant in file.mutants {
            if mutant.id.is_empty() || !ids.insert(mutant.id.clone()) {
                bail!("empty or duplicate Stryker mutant id in {path}");
            }
            outcomes.push(mutant.normalize(&path)?);
        }
    }
    if outcomes.is_empty() {
        bail!("Stryker report contains no mutation outcomes");
    }
    Ok(build_mutation_report(outcomes))
}

impl Mutant {
    fn normalize(self, path: &str) -> Result<MutationOutcome> {
        let status = match self.status.as_str() {
            "Killed" => "killed",
            "Survived" | "NoCoverage" => "survived",
            "CompileError" => "unviable",
            "Ignored" => "skipped",
            _ => bail!("incomplete or unsupported Stryker outcome: {}", self.status),
        };
        if self.location.start.line == 0
            || self.location.end.line == 0
            || self.location.start.column == 0
            || self.location.end.column == 0
            || self.location.end < self.location.start
            || self.mutator_name.trim().is_empty()
        {
            bail!("invalid Stryker mutation location or name");
        }
        Ok(MutationOutcome {
            path: normalize_rel_string(path),
            line: Some(self.location.start.line),
            status: status.into(),
            message: self.mutator_name,
        })
    }
}

fn unique_files<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, File>, D::Error> {
    struct Files;
    impl<'de> Visitor<'de> for Files {
        type Value = BTreeMap<String, File>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a Stryker file inventory with unique paths")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut files = BTreeMap::new();
            while let Some((path, file)) = map.next_entry::<String, File>()? {
                if files.insert(path, file).is_some() {
                    return Err(de::Error::custom("duplicate Stryker source path"));
                }
            }
            Ok(files)
        }
    }
    deserializer.deserialize_map(Files)
}
