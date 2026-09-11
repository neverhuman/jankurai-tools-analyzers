use jankurai_audit_analyzers::audit::analyzers::tool_adoption;
use jankurai_audit_kernel::audit::helpers::{AuditContext, TOOL_ADOPTION_CATALOG};
use jankurai_audit_kernel::model::{FileInfo, ToolAdoptionReadiness};
use std::fs;
use tempfile::{tempdir, TempDir};

const COMMAND: &str =
    "jankurai ux audit --config agent/ux-qa.toml --out target/jankurai/ux-qa.json";
const OUTPUT: &str = "target/jankurai/ux-qa.json";
const UPLOAD: &str = "      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567\n        with:\n          path: target/jankurai/ux-qa.json\n";

fn file(path: &str, text: &str) -> FileInfo {
    FileInfo {
        rel_path: path.into(),
        name: path.rsplit('/').next().unwrap().into(),
        suffix: path
            .rsplit_once('.')
            .map_or(String::new(), |(_, ext)| format!(".{ext}")),
        size: text.len() as u64,
        line_count: text.lines().count(),
        text: text.into(),
        is_generated: false,
        is_code: false,
    }
}

fn fixture(mode: &str, web: bool, mut files: Vec<FileInfo>) -> (TempDir, AuditContext) {
    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("agent")).unwrap();
    let mut policy = "schema_version = \"1.0.0\"\n".to_string();
    for entry in TOOL_ADOPTION_CATALOG {
        policy += &format!(
            "\n[[tools]]\nid = {:?}\nmode = {:?}\n",
            entry.id,
            if entry.id == "ux-qa" {
                mode
            } else {
                "disabled"
            }
        );
    }
    fs::write(root.path().join("agent/tool-adoption.toml"), policy).unwrap();
    files.push(file("AGENTS.md", "Read the repository contract."));
    if web {
        files.push(file("apps/web/src/main.tsx", "export const value = 1;"));
    }
    let ctx = AuditContext {
        root: root.path().into(),
        scope_paths: files.iter().map(|f| f.rel_path.clone()).collect(),
        scope_files: files.clone(),
        all_files: files,
        self_audit: false,
        boundary_reclassifications: vec![],
        copy_code: None,
    };
    (root, ctx)
}

fn workflow(run: &str, upload: &str) -> String {
    format!("name: ci\non: [push]\njobs:\n  ux:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n{}{}",
        run.lines().map(|line| format!("          {line}\n")).collect::<String>(), upload)
}

fn checked(
    ctx: &AuditContext,
    mode: &str,
    applicable: bool,
    routed: bool,
) -> ToolAdoptionReadiness {
    let report = tool_adoption::status(ctx);
    let ux = report.items.iter().find(|item| item.id == "ux-qa").unwrap();
    assert_eq!(
        ux.status,
        if !applicable {
            "not_applicable"
        } else if routed {
            "ci_evidence"
        } else {
            "configured"
        },
        "{:?}",
        report.evidence
    );
    assert_eq!(report.applicable_count, usize::from(applicable));
    assert_eq!(report.configured_count, usize::from(applicable));
    assert_eq!(report.ci_evidence_count, usize::from(routed));
    assert_eq!(report.artifact_verified_count, 0);
    assert_eq!(report.replaced_count, 0);
    assert_eq!(
        report.missing,
        if applicable { vec!["ux-qa"] } else { vec![] }
    );
    assert_eq!(
        tool_adoption::missing_required_ci_tools(ctx),
        if applicable && mode == "required" {
            vec!["ux-qa"]
        } else {
            vec![]
        }
    );
    assert_eq!(
        tool_adoption::analyze(ctx).score,
        if applicable { 30 } else { 90 }
    );
    if applicable {
        assert!(ux
            .evidence
            .iter()
            .any(|line| line == "execution_observation=UNVERIFIED"));
        assert!(ux
            .missing
            .iter()
            .any(|line| line == "admitted execution observation"));
    }
    assert_eq!(
        ux.evidence
            .iter()
            .any(|line| line.starts_with("CI_ROUTE_DECLARATION_ONLY:")),
        routed
    );
    report
}

fn assert_route(files: Vec<FileInfo>, expected: bool) -> ToolAdoptionReadiness {
    let (_root, ctx) = fixture("required", true, files);
    checked(&ctx, "required", true, expected)
}

fn assert_yaml(yaml: &str, expected: bool) -> ToolAdoptionReadiness {
    assert_route(vec![file(".github/workflows/ci.yml", yaml)], expected)
}

fn upload_declared(report: &ToolAdoptionReadiness) -> bool {
    report
        .items
        .iter()
        .find(|item| item.id == "ux-qa")
        .unwrap()
        .evidence
        .iter()
        .any(|line| line.starts_with("same-job artifact upload declared, not observed:"))
}

#[test]
fn literal_and_routed_declarations_never_establish_observed_execution() {
    let direct = assert_yaml(&workflow(COMMAND, UPLOAD), true);
    assert!(upload_declared(&direct));
    let routed = assert_route(
        vec![
            file(
                ".github/workflows/ci.yml",
                &workflow("bash ops/ci/ux.sh", UPLOAD),
            ),
            file(
                "ops/ci/ux.sh",
                &format!("#!/usr/bin/env bash\nset -euo pipefail\n{COMMAND}\n"),
            ),
        ],
        true,
    );
    assert!(upload_declared(&routed));
    assert!(routed
        .items
        .iter()
        .find(|i| i.id == "ux-qa")
        .unwrap()
        .evidence
        .iter()
        .any(|line| line.contains("ops/ci/ux.sh line=3")));
}

#[test]
fn comments_names_environment_and_printed_strings_are_not_routes() {
    for yaml in [
        format!("# {COMMAND}\n# actions/upload-artifact\n# {OUTPUT}\n"),
        format!("name: {COMMAND}\nenv:\n  LABEL: actions/upload-artifact {OUTPUT}\n"),
        workflow(&format!("echo '{COMMAND}'"), UPLOAD),
        workflow(&format!("printf '%s' '{COMMAND}'"), UPLOAD),
        workflow(&format!("'{COMMAND}'"), UPLOAD),
        workflow(&format!("CATALOG='{COMMAND}'"), UPLOAD),
        workflow(&format!("# {COMMAND}\ntrue"), UPLOAD),
    ] {
        assert_yaml(&yaml, false);
    }
}

#[test]
fn uncalled_scripts_and_unsupported_shell_bodies_cannot_supply_routes() {
    for text in [format!("# {COMMAND}"), COMMAND.to_string()] {
        assert_route(
            vec![
                file(".github/workflows/ci.yml", &workflow("true", UPLOAD)),
                file("ops/ci/ux.sh", &text),
            ],
            false,
        );
    }
    for text in [
        format!("# {COMMAND}"),
        format!("unused() {{\n{COMMAND}\n}}"),
        format!("if false; then\n{COMMAND}\nfi"),
        format!("cat <<'CATALOG'\n{COMMAND}\nCATALOG"),
        format!("exit 0\n{COMMAND}"),
        format!("false && {COMMAND}"),
        format!("eval '{COMMAND}'"),
        format!("echo $({COMMAND})"),
        format!("source ops/ci/lib.sh\n{COMMAND}"),
        format!("set -n\n{COMMAND}"),
        format!("set -o noexec\n{COMMAND}"),
        format!("set -euo pipefail -n\n{COMMAND}"),
    ] {
        assert_route(
            vec![
                file(
                    ".github/workflows/ci.yml",
                    &workflow("bash ops/ci/ux.sh", UPLOAD),
                ),
                file("ops/ci/ux.sh", &text),
            ],
            false,
        );
    }
}

#[test]
fn literal_quoting_continuations_and_exact_argv_are_distinguished() {
    for command in [
        COMMAND.to_string(),
        format!("{COMMAND} # audit declaration"),
        COMMAND.replace(" --out", " \\\n --out"),
        COMMAND.replace("agent/ux-qa.toml", "'agent/ux-qa.toml'"),
        format!("printf '%s' 'inert {COMMAND}';\n{COMMAND}"),
    ] {
        assert_yaml(&workflow(&command, UPLOAD), true);
    }
    for command in [
        COMMAND.replace("ux audit", "ux not-audit"),
        COMMAND.replace("jankurai", "not-jankurai"),
        COMMAND.replace("agent/ux-qa.toml", "agent/UX-QA.toml"),
        COMMAND.replace("jankurai", "$JANKURAI_BIN"),
        COMMAND.replace("agent/ux-qa.toml", "$CONFIG"),
    ] {
        assert_yaml(&workflow(&command, UPLOAD), false);
    }
}

#[test]
fn uploads_are_same_job_declarations_after_the_command_only() {
    let unrelated = format!(
        "{}  other:\n    runs-on: ubuntu-latest\n    steps:\n{}",
        workflow(COMMAND, ""),
        UPLOAD
    );
    assert!(!upload_declared(&assert_yaml(&unrelated, true)));
    let early = format!(
        "on: [push]\njobs:\n  ux:\n    runs-on: ubuntu-latest\n    steps:\n{UPLOAD}      - run: {COMMAND}\n"
    );
    assert!(!upload_declared(&assert_yaml(&early, true)));
    assert!(!upload_declared(&assert_yaml(
        &workflow(COMMAND, &UPLOAD.replace(OUTPUT, "target/wrong.json")),
        true
    )));
    assert!(!upload_declared(&assert_yaml(&workflow(COMMAND, ""), true)));
    for upload in [
        UPLOAD.replace(OUTPUT, "${{ inputs.artifact }}"),
        UPLOAD.replace("0123456789abcdef0123456789abcdef01234567", "v7"),
    ] {
        assert_yaml(&workflow(COMMAND, &upload), false);
    }
}

#[test]
fn disabled_conditional_and_unsupported_execution_profiles_are_incomplete() {
    let original = workflow(COMMAND, UPLOAD);
    for trigger in ["", "on: []\n", "on: false\n", "on: {}\n", "on: unknown\n"] {
        assert_yaml(&original.replace("on: [push]\n", trigger), false);
    }
    for trigger in [
        "on: push\n",
        "on: {push: null}\n",
        "on: [push, pull_request, workflow_dispatch]\n",
    ] {
        assert_yaml(&original.replace("on: [push]\n", trigger), true);
    }
    for yaml in [
        original.replace("    runs-on:", "    if: false\n    runs-on:"),
        original.replace("    runs-on:", "    if: ${{ inputs.run }}\n    runs-on:"),
        original.replace("      - run:", "      - if: false\n        run:"),
        original.replace(
            "      - run:",
            "      - continue-on-error: true\n        run:",
        ),
        original.replace("ubuntu-latest", "windows-latest"),
        original.replace("    runs-on:", "    needs: missing\n    runs-on:"),
        original.replace("    runs-on:", "    needs: ux\n    runs-on:"),
        original.replace(
            "    runs-on:",
            "    strategy: {matrix: {os: [ubuntu-latest]}}\n    runs-on:",
        ),
        original.replace("      - run:", "      - shell: pwsh\n        run:"),
        original.replace(
            "      - run:",
            "      - working-directory: other\n        run:",
        ),
        format!("defaults:\n  run:\n    working-directory: other\n{original}"),
    ] {
        let report = assert_yaml(&yaml, false);
        assert!(!report.evidence["route_assessment_incomplete"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    assert_yaml(
        &original.replace("    runs-on:", "    if: true\n    runs-on:"),
        true,
    );
    for prologue in ["", "set -euo pipefail\n"] {
        let run = format!("{prologue}{COMMAND}");
        let yaml = workflow(&run, UPLOAD);
        assert_yaml(
            &yaml.replace("      - run:", "      - shell: sh\n        run:"),
            prologue.is_empty(),
        );
        assert_yaml(
            &format!("defaults:\n  run:\n    shell: sh\n{yaml}"),
            prologue.is_empty(),
        );
        assert_route(
            vec![
                file(
                    ".github/workflows/ci.yml",
                    &workflow("sh ops/ci/ux.sh", UPLOAD),
                ),
                file("ops/ci/ux.sh", &run),
            ],
            prologue.is_empty(),
        );
    }
}

#[test]
fn duplicate_keys_malformed_merged_and_tagged_yaml_are_rejected() {
    let original = workflow(COMMAND, UPLOAD);
    for yaml in [
        format!("jobs: [\n# {COMMAND}\n# upload-artifact {OUTPUT}"),
        original.replace("jobs:", "jobs: {}\njobs:"),
        original.replace("    runs-on:", "    runs-on: windows-latest\n    runs-on:"),
        original.replace("      - run:", "      - run: true\n        run:"),
        original.replace(
            "          path:",
            "          path: target/wrong.json\n          path:",
        ),
        original.replace("    runs-on:", "    <<: {if: false}\n    runs-on:"),
        original.replace("name: ci", "name: !custom ci"),
    ] {
        let report = assert_yaml(&yaml, false);
        assert!(!report.evidence["route_assessment_incomplete"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn inventory_lookup_never_falls_back_to_filesystem_or_ambiguous_paths() {
    let route = file(
        ".github/workflows/ci.yml",
        &workflow("bash ops/ci/ux.sh", UPLOAD),
    );
    let script = file("ops/ci/ux.sh", COMMAND);
    assert_route(vec![route.clone(), script.clone(), script.clone()], false);
    assert_route(vec![route.clone(), route.clone(), script.clone()], false);
    for path in [
        "ops/ci/../ux.sh",
        "/ops/ci/ux.sh",
        "ops/ci/$LANE.sh",
        "scripts/ci-local.sh",
    ] {
        assert_route(
            vec![
                file(
                    ".github/workflows/ci.yml",
                    &workflow(&format!("bash {path}"), UPLOAD),
                ),
                file(path, COMMAND),
            ],
            false,
        );
    }
    let (root, ctx) = fixture("required", true, vec![route]);
    fs::create_dir_all(root.path().join("ops/ci")).unwrap();
    fs::write(root.path().join("ops/ci/ux.sh"), COMMAND).unwrap();
    checked(&ctx, "required", true, false);
    assert_route(
        vec![
            file(
                ".github/workflows/ci.yml",
                &workflow("bash ops/ci/ux.sh", UPLOAD),
            ),
            file("ops/ci/ux.sh", "bash ops/ci/ux.sh"),
        ],
        false,
    );
}

#[test]
fn modes_applicability_and_scoring_weights_remain_unchanged() {
    for (mode, web, applicable) in [
        ("disabled", true, false),
        ("auto", false, false),
        ("auto", true, true),
        ("advisory", false, true),
        ("required", false, true),
    ] {
        for route in [false, true] {
            let yaml = workflow(if route { COMMAND } else { "true" }, UPLOAD);
            let (_root, ctx) = fixture(mode, web, vec![file(".github/workflows/ci.yml", &yaml)]);
            checked(&ctx, mode, applicable, applicable && route);
        }
    }
}

#[test]
fn output_presence_and_self_asserted_receipts_do_not_become_observations() {
    let (root, mut ctx) = fixture(
        "required",
        true,
        vec![file(
            ".github/workflows/ci.yml",
            &workflow("bash ops/ci/ux.sh", UPLOAD),
        )],
    );
    let sentinel = root.path().join("executed");
    ctx.all_files.push(file(
        "ops/ci/ux.sh",
        &format!("touch {}\n{COMMAND}", sentinel.display()),
    ));
    fs::create_dir_all(root.path().join("target/jankurai")).unwrap();
    let claimed = format!(
        r#"{{"passed":true,"exit_code":0,"command":{COMMAND:?},"artifact_verified":true}}"#
    );
    fs::write(root.path().join(OUTPUT), &claimed).unwrap();
    ctx.all_files.push(file(OUTPUT, &claimed));
    checked(&ctx, "required", true, true);
    assert!(
        !sentinel.exists(),
        "static audit must never execute a repository script"
    );
}

#[test]
fn bounded_inputs_and_script_depth_refuse_without_granting_declarations() {
    let huge = format!("{}\n{COMMAND}", "#".repeat(65 * 1024));
    assert_yaml(&workflow(COMMAND, UPLOAD).repeat(1024), false);
    assert_route(
        vec![
            file(
                ".github/workflows/ci.yml",
                &workflow("bash ops/ci/ux.sh", UPLOAD),
            ),
            file("ops/ci/ux.sh", &huge),
        ],
        false,
    );
    for depth in [8, 9] {
        let mut files = vec![file(
            ".github/workflows/ci.yml",
            &workflow("bash ops/ci/1.sh", UPLOAD),
        )];
        for index in 1..=depth {
            files.push(file(
                &format!("ops/ci/{index}.sh"),
                &if index == depth {
                    COMMAND.to_string()
                } else {
                    format!("bash ops/ci/{}.sh", index + 1)
                },
            ));
        }
        assert_route(files, depth == 8);
    }
}
