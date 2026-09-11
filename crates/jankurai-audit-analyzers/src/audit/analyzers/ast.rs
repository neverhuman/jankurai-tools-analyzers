use anyhow::Result;
use jankurai_audit_kernel::audit::helpers::product_code_files;
use jankurai_audit_kernel::audit::helpers::AuditContext;
use jankurai_audit_kernel::audit::scan::FindingHit;

mod rust_imports;
mod typescript_imports;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct ImportEdge {
    pub source_file: String,
    pub target_module: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub edges: Vec<ImportEdge>,
    // source file -> target modules
    pub adjacency: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    pub fn add_edge(&mut self, edge: ImportEdge) {
        self.adjacency
            .entry(edge.source_file.clone())
            .or_default()
            .insert(edge.target_module.clone());
        self.edges.push(edge);
    }
}

pub fn parse_rust_imports(file_path: &str, text: &str, graph: &mut DependencyGraph) -> Result<()> {
    rust_imports::parse(file_path, text, graph)
}

pub fn parse_typescript_imports(
    file_path: &str,
    text: &str,
    graph: &mut DependencyGraph,
) -> Result<()> {
    typescript_imports::parse(file_path, text, graph)
}

pub fn run_ast_pilot(ctx: &AuditContext) -> Result<Vec<FindingHit>> {
    crate::audit::web_security::validate_inputs(ctx)?;
    let mut graph = DependencyGraph::default();

    for file in product_code_files(ctx) {
        if file.suffix == ".rs" {
            crate::audit::syntax::require_complete(file)?;
            parse_rust_imports(&file.rel_path, &file.text, &mut graph)?;
        } else if matches!(
            file.suffix.as_str(),
            ".ts" | ".tsx" | ".mts" | ".cts" | ".js" | ".jsx" | ".mjs" | ".cjs"
        ) {
            crate::audit::syntax::require_complete(file)?;
            parse_typescript_imports(&file.rel_path, &file.text, &mut graph)?;
        }
    }

    let mut hits = Vec::new();
    let domain_forbidden = jankurai_audit_kernel::boundaries::rust::DOMAIN_FORBIDDEN_IMPORTS;

    for edge in graph.edges {
        // Rust domain impurity check
        if edge.source_file.starts_with("crates/domain/") || edge.source_file.starts_with("domain/")
        {
            for forbidden in domain_forbidden {
                if edge.target_module == *forbidden
                    || edge.target_module.starts_with(&format!("{forbidden}::"))
                {
                    hits.push(FindingHit {
                        path: edge.source_file.clone(),
                        line: Some(edge.line_number),
                        text: format!("use {}", edge.target_module),
                        matched_term: Some(forbidden.to_string()),
                        agent_fix: "extract IO/database operations to adapters and use dependency injection or generic traits".to_string(),
                        problem: format!("domain logic imports forbidden IO/DB module `{}`", edge.target_module),
                    });
                }
            }
        }

        // TypeScript UI layer checking for backend imports
        if is_ui_source(&edge.source_file) && is_backend_module(&edge.target_module) {
            hits.push(FindingHit {
                path: edge.source_file.clone(),
                line: Some(edge.line_number),
                text: format!("import ... from '{}'", edge.target_module),
                matched_term: Some(edge.target_module.clone()),
                agent_fix:
                    "use HTTP/API clients instead of directly importing backend code in the UI"
                        .to_string(),
                problem: format!(
                    "UI layer directly imports backend module `{}`",
                    edge.target_module
                ),
            });
        }
    }

    Ok(hits)
}

fn is_ui_source(path: &str) -> bool {
    [
        "apps/web/",
        "frontend/",
        "ui/",
        "packages/web/",
        "packages/ui/",
        "src/components/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
        || path.ends_with(".tsx")
        || path.ends_with(".jsx")
}

fn is_backend_module(module: &str) -> bool {
    let segments: Vec<_> = module.split('/').collect();
    segments.contains(&"backend") || segments.windows(2).any(|pair| pair == ["adapters", "db"])
}
