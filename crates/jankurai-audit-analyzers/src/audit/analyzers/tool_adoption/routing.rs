use super::shell;
use jankurai_audit_kernel::audit::helpers::AuditContext;
use jankurai_audit_kernel::model::FileInfo;
use serde_yaml::Value;
use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct Routes {
    declarations: Vec<Declaration>,
    pub incomplete: BTreeSet<String>,
}

struct Declaration {
    words: Vec<String>,
    location: String,
    uploads: BTreeSet<String>,
}

impl Routes {
    pub fn matching(&self, command: &str, artifacts: &[&str]) -> Option<(String, bool)> {
        let expected = shell::commands(command).ok()?;
        if expected.len() != 1 {
            return None;
        }
        let mut matches = self
            .declarations
            .iter()
            .filter(|route| route.words == expected[0].words);
        let first = matches.next()?;
        let uploaded =
            |route: &Declaration| artifacts.iter().all(|path| route.uploads.contains(*path));
        let chosen = if uploaded(first) {
            first
        } else {
            matches.find(|route| uploaded(route)).unwrap_or(first)
        };
        Some((chosen.location.clone(), uploaded(chosen)))
    }
}

pub(super) fn inspect(ctx: &AuditContext) -> Routes {
    let mut result = Routes::default();
    for file in ctx.all_files.iter().filter(|file| workflow(&file.rel_path)) {
        let declarations = read_workflow(ctx, file);
        match declarations {
            Ok(declarations) => result.declarations.extend(declarations),
            Err(reason) => {
                result
                    .incomplete
                    .insert(format!("{}: {reason}", file.rel_path));
            }
        }
    }
    result
}

fn workflow(path: &str) -> bool {
    path.strip_prefix(".github/workflows/").is_some_and(|name| {
        !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"))
    })
}

fn read_workflow(ctx: &AuditContext, file: &FileInfo) -> Result<Vec<Declaration>, String> {
    unique_file(ctx, &file.rel_path)?;
    if file.text.len() > 64 * 1024 {
        return Err("workflow exceeds byte limit".into());
    }
    // serde_yaml's Mapping deserializer rejects duplicate keys, including
    // nested job/step keys. Do not recover through the original raw text.
    let value: Value =
        serde_yaml::from_str(&file.text).map_err(|e| format!("invalid YAML: {e}"))?;
    plain_yaml(&value, 0)?;
    trigger(&value)?;
    defaults(&value)?;
    let workflow_bash = default_interpreter(&value, true);
    let jobs = value
        .get("jobs")
        .and_then(Value::as_mapping)
        .ok_or("workflow jobs mapping missing")?;
    if jobs.len() > 256 {
        return Err("workflow job count exceeds limit".into());
    }
    let mut declarations = Vec::new();
    for (name, job) in jobs {
        let name = name.as_str().ok_or("non-string job name")?;
        enabled(job)?;
        defaults(job)?;
        let job_bash = default_interpreter(job, workflow_bash);
        if job.get("strategy").is_some()
            || job.get("needs").is_some()
            || job.get("container").is_some()
            || job.get("uses").is_some()
            || !matches!(
                job.get("runs-on").and_then(Value::as_str),
                Some("ubuntu-latest" | "ubuntu-22.04" | "ubuntu-24.04")
            )
        {
            return Err(format!("unsupported execution profile for job {name}"));
        }
        let steps = job
            .get("steps")
            .and_then(Value::as_sequence)
            .ok_or("job steps sequence missing")?;
        if steps.len() > 256 {
            return Err("job step count exceeds limit".into());
        }
        let mut uploads = Vec::new();
        let mut pending = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            enabled(step)?;
            if step.get("run").is_some() && step.get("uses").is_some() {
                return Err("step has both run and uses".into());
            }
            if let Some(run) = step.get("run") {
                execution_settings(step)?;
                let run = run.as_str().ok_or("run must be a literal string")?;
                let location = format!("{} job={name} step={}", file.rel_path, index + 1);
                let mut visited = BTreeSet::new();
                let commands = follow(
                    ctx,
                    run,
                    &location,
                    &mut visited,
                    0,
                    interpreter(step, job_bash),
                )?;
                pending.extend(commands.into_iter().map(|command| (index, command)));
            } else if let Some(uses) = step.get("uses").and_then(Value::as_str) {
                if uses.contains("${{") || uses.starts_with("./") || uses.starts_with("docker://") {
                    return Err("unsupported dynamic or composite action".into());
                }
                if let Some(revision) = uses.strip_prefix("actions/upload-artifact@") {
                    if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err("upload action lacks immutable revision declaration".into());
                    }
                    let paths = step
                        .get("with")
                        .and_then(|with| with.get("path"))
                        .and_then(Value::as_str)
                        .ok_or("upload path must be a literal string")?;
                    let mut exact = BTreeSet::new();
                    for path in paths.lines().map(str::trim).filter(|path| !path.is_empty()) {
                        if !safe_relative(path) {
                            return Err("unsupported upload path expression".into());
                        }
                        exact.insert(path.to_string());
                    }
                    uploads.push((index, exact));
                }
            } else {
                return Err("step lacks supported run or uses".into());
            }
        }
        for (index, (words, location)) in pending {
            declarations.push(Declaration {
                words,
                location,
                uploads: uploads
                    .iter()
                    .filter(|(upload_index, _)| *upload_index > index)
                    .flat_map(|(_, paths)| paths.iter().cloned())
                    .collect(),
            });
        }
    }
    Ok(declarations)
}

fn enabled(value: &Value) -> Result<(), String> {
    if value.get("if").is_some_and(|v| v.as_bool() != Some(true)) {
        return Err("conditional or disabled route is incomplete".into());
    }
    if value
        .get("continue-on-error")
        .is_some_and(|v| v.as_bool() != Some(false))
    {
        return Err("continued or unknown failure policy is incomplete".into());
    }
    Ok(())
}

fn trigger(value: &Value) -> Result<(), String> {
    let events: Vec<&str> = match value.get("on") {
        Some(Value::String(event)) => vec![event],
        Some(Value::Sequence(events)) => events
            .iter()
            .map(|event| event.as_str().ok_or("nonliteral workflow trigger"))
            .collect::<Result<_, _>>()?,
        Some(Value::Mapping(events)) => events
            .iter()
            .map(|(event, options)| {
                if !options.is_null() && !options.as_mapping().is_some_and(|map| map.is_empty()) {
                    return Err("unsupported workflow trigger options");
                }
                event.as_str().ok_or("nonliteral workflow trigger")
            })
            .collect::<Result<_, _>>()?,
        _ => return Err("workflow trigger declaration missing or unsupported".into()),
    };
    let mut seen = BTreeSet::new();
    if events.is_empty()
        || events.iter().any(|event| {
            !matches!(*event, "push" | "pull_request" | "workflow_dispatch") || !seen.insert(*event)
        })
    {
        return Err("empty, repeated or unsupported workflow trigger".into());
    }
    Ok(())
}

fn interpreter(value: &Value, inherited_bash: bool) -> bool {
    value
        .get("shell")
        .and_then(Value::as_str)
        .map_or(inherited_bash, |shell| shell == "bash")
}

fn default_interpreter(value: &Value, inherited_bash: bool) -> bool {
    value
        .get("defaults")
        .and_then(|defaults| defaults.get("run"))
        .map_or(inherited_bash, |run| interpreter(run, inherited_bash))
}

fn defaults(value: &Value) -> Result<(), String> {
    if let Some(defaults) = value.get("defaults") {
        execution_settings(defaults.get("run").ok_or("unsupported defaults")?)?;
    }
    Ok(())
}

fn execution_settings(value: &Value) -> Result<(), String> {
    if value
        .get("shell")
        .is_some_and(|shell| !matches!(shell.as_str(), Some("bash" | "sh")))
        || value
            .get("working-directory")
            .is_some_and(|directory| directory.as_str() != Some("."))
    {
        return Err("unsupported shell or working directory".into());
    }
    Ok(())
}

fn plain_yaml(value: &Value, depth: usize) -> Result<(), String> {
    if depth > 32 {
        return Err("YAML depth exceeds limit".into());
    }
    match value {
        Value::Tagged(_) => return Err("tagged YAML is unsupported".into()),
        Value::Mapping(map) => {
            for (key, value) in map {
                if key.as_str() == Some("<<") || key.as_str().is_none() {
                    return Err("merged or non-string YAML key is unsupported".into());
                }
                plain_yaml(value, depth + 1)?;
            }
        }
        Value::Sequence(values) => {
            for value in values {
                plain_yaml(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn unique_file<'a>(ctx: &'a AuditContext, path: &str) -> Result<&'a FileInfo, String> {
    let mut files = ctx.all_files.iter().filter(|file| file.rel_path == path);
    let file = files
        .next()
        .ok_or_else(|| format!("not in source inventory: {path}"))?;
    if files.next().is_some() {
        return Err(format!("ambiguous source inventory path: {path}"));
    }
    Ok(file)
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

type LocatedCommand = (Vec<String>, String);

fn follow(
    ctx: &AuditContext,
    source: &str,
    location: &str,
    visited: &mut BTreeSet<String>,
    depth: usize,
    bash: bool,
) -> Result<Vec<LocatedCommand>, String> {
    if depth > 8 {
        return Err("script recursion depth exceeds limit".into());
    }
    let mut result = Vec::new();
    for command in shell::commands(source)? {
        let here = format!("{location} line={}", command.line);
        if command.words[0] == "set" && !bash {
            return Err("Bash pipefail prologue unsupported under sh".into());
        }
        if command.words[0] == "bash" || command.words[0] == "sh" {
            if command.words.len() != 2 {
                return Err("unsupported shell invocation".into());
            }
            let path = &command.words[1];
            if !safe_relative(path) || !path.starts_with("ops/ci/") || !path.ends_with(".sh") {
                return Err("unsupported script route path".into());
            }
            if visited.len() >= 64 || !visited.insert(path.clone()) {
                return Err("repeated or cyclic script route".into());
            }
            let file = unique_file(ctx, path)?;
            result.extend(follow(
                ctx,
                &file.text,
                &format!("{here} -> {path}"),
                visited,
                depth + 1,
                command.words[0] == "bash",
            )?);
        } else {
            result.push((command.words, here));
        }
    }
    Ok(result)
}
