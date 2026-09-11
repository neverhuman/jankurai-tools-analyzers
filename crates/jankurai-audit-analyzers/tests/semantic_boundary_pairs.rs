use jankurai_audit_analyzers::audit::{analyzers::ast, web_security};
use jankurai_audit_kernel::{audit::helpers::AuditContext, model::FileInfo};
use std::path::PathBuf;

fn context(path: &str, source: &str) -> AuditContext {
    let file = FileInfo {
        rel_path: path.into(),
        name: path.rsplit('/').next().unwrap().into(),
        suffix: format!(".{}", path.rsplit('.').next().unwrap()),
        size: source.len() as u64,
        line_count: source.lines().count(),
        text: source.into(),
        is_generated: false,
        is_code: true,
    };
    AuditContext {
        root: PathBuf::from("/nonexistent/jankurai-semantic-pairs"),
        all_files: vec![file.clone()],
        scope_files: vec![file],
        scope_paths: vec![],
        self_audit: false,
        boundary_reclassifications: vec![],
        copy_code: None,
    }
}

#[test]
fn rust_multiline_grouped_imports_and_public_reexports_keep_domain_boundaries() {
    for source in [
        "use std::fs;",
        "pub use std::fs;",
        "pub(crate) use std::{\n fs,\n net\n};",
        "mod nested { pub use std::fs as filesystem; }",
    ] {
        let hits = ast::run_ast_pilot(&context("crates/domain/src/lib.rs", source)).unwrap();
        assert!(!hits.is_empty(), "{source}");
        assert!(hits
            .iter()
            .any(|hit| hit.matched_term.as_deref() == Some("std::fs")));
    }
    for source in [
        "use std::fmt;",
        "mod std { pub mod filesystem {} } use std::filesystem;",
        "/* use std::fs; */\nconst S: &str = r#\"pub use std::net;\"#;",
        "/* outer /* use std::fs; */ comment */ pub fn pure() {}",
    ] {
        assert!(
            ast::run_ast_pilot(&context("crates/domain/src/lib.rs", source))
                .unwrap()
                .is_empty(),
            "{source}"
        );
    }
}

#[test]
fn typescript_imports_reexports_and_jsx_components_share_boundary_decisions() {
    for path in [
        "apps/web/Widget.tsx",
        "packages/ui/Widget.tsx",
        "src/Widget.tsx",
        "frontend/Widget.jsx",
    ] {
        for source in [
            "import { Database } from '@app/backend/db';",
            "import {\n Database\n} from\n '@app/backend/db';",
            "export { Database as Db } from '@app/backend/db';",
            "export * from '@app/backend/db';",
            "const load = () => import('@app/backend/db');",
            "import { Database } from '@app/backend/db'; export const View = () => <div />;",
        ] {
            assert!(
                !ast::run_ast_pilot(&context(path, source))
                    .unwrap()
                    .is_empty(),
                "{path}: {source}"
            );
        }
    }
    for source in [
        "import { Client } from '@app/api/client';",
        "import { Client } from '@app/backendless-client';",
        "/* import { Db } from '@app/backend/db'; */ export const View = () => <div/>;",
        "const note = \"import { Db } from '@app/backend/db'\";",
        r"const pattern = /import.*from '@app\/backend\/db'/;",
    ] {
        assert!(
            ast::run_ast_pilot(&context("apps/web/Widget.tsx", source))
                .unwrap()
                .is_empty(),
            "{source}"
        );
    }
}

#[test]
fn malformed_import_inputs_fail_without_erasing_previous_graph_evidence() {
    let mut graph = ast::DependencyGraph::default();
    ast::parse_typescript_imports("src/a.ts", "import 'first';", &mut graph).unwrap();
    assert!(ast::parse_typescript_imports("src/b.ts", "import {", &mut graph).is_err());
    assert!(ast::parse_rust_imports("src/c.rs", "pub use std::{fs", &mut graph).is_err());
    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.edges[0].target_module, "first");
    assert!(ast::run_ast_pilot(&context("src/b.ts", "import {")).is_err());
}

fn vite_hits(path: &str, source: &str) -> Vec<usize> {
    let ctx = context(path, source);
    web_security::validate_inputs(&ctx).unwrap();
    web_security::findings(&ctx)
        .iter()
        .filter(|hit| hit.matched_term == "websec.vite.public-dev-server")
        .map(|hit| hit.line.unwrap())
        .collect()
}

#[test]
fn vite_property_syntax_and_whitespace_cannot_hide_public_exposure() {
    for property in [
        "host:'0.0.0.0'",
        "host: \"::\"",
        "host:\n true",
        "'host': `0.0.0.0`",
        "['host']:true",
        "allowedHosts:\n true",
        "cors : true",
        "fs:{strict:\n false}",
    ] {
        let source = format!("export default defineConfig({{\n server:{{{property}}}\n}});");
        assert!(!vite_hits("vite.config.ts", &source).is_empty(), "{source}");
    }
    assert_eq!(
        vite_hits(
            "vite.config.mts",
            "export default {\n preview: {\n host: true\n }\n};"
        ),
        [3]
    );
    assert!(!vite_hits("vite.config.cjs", "module.exports = {server:{host:true}};").is_empty());
}

#[test]
fn vite_safe_values_comments_strings_and_unrelated_objects_are_inert() {
    for source in [
        "export default {server:{host:'127.0.0.1',allowedHosts:['example.test'],cors:false,fs:{strict:true}}};",
        "const note = 'Never set allowedHosts: true'; export default {};",
        "/* server: { host:true } */ export default {};",
        "const unrelated = {server:{host:true}}; export default {};",
        "export default {plugins:[plugin({server:{host:true}})]};",
        "export default {server:{host:'true',strict:false},other:{fs:{strict:false}}};",
    ] {
        assert!(vite_hits("vite.config.ts", source).is_empty(), "{source}");
    }
}

#[test]
fn malformed_vite_config_blocks_complete_analysis_and_retains_diagnostic_findings() {
    let ctx = context("vite.config.ts", "export default { server: { host: ");
    assert!(web_security::validate_inputs(&ctx).is_err());
    assert!(ast::run_ast_pilot(&ctx).is_err());
    assert!(web_security::findings(&ctx)
        .iter()
        .any(|hit| hit.matched_term == "websec.input.incomplete"));
}

#[test]
fn valid_but_truncated_prefixes_cannot_report_complete_analysis() {
    for (path, source) in [
        ("src/a.ts", "export const safe = true;"),
        ("src/lib.rs", "pub fn safe() {}"),
        ("vite.config.ts", "export default {};"),
    ] {
        let mut ctx = context(path, source);
        assert!(ast::run_ast_pilot(&ctx).is_ok());
        ctx.all_files[0].size += 1;
        ctx.scope_files[0].size += 1;
        let error = ast::run_ast_pilot(&ctx).unwrap_err();
        assert!(error.to_string().contains("incomplete analysis"), "{path}");
        if path == "vite.config.ts" {
            assert!(web_security::validate_inputs(&ctx).is_err());
            assert!(web_security::findings(&ctx)
                .iter()
                .any(|hit| hit.matched_term == "websec.input.incomplete"));
        }
    }
}
