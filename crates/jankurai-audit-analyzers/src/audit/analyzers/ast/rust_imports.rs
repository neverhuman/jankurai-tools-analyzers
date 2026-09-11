use super::{DependencyGraph, ImportEdge};
use anyhow::{Context, Result};
use syn::visit::Visit;

pub(super) fn parse(path: &str, source: &str, graph: &mut DependencyGraph) -> Result<()> {
    let file = syn::parse_file(source)
        .with_context(|| format!("incomplete analysis: invalid Rust syntax in {path}"))?;
    let mut visitor = Imports {
        path,
        edges: Vec::new(),
    };
    visitor.visit_file(&file);
    for edge in visitor.edges {
        graph.add_edge(edge);
    }
    Ok(())
}

struct Imports<'a> {
    path: &'a str,
    edges: Vec<ImportEdge>,
}

impl<'ast> Visit<'ast> for Imports<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        expand(&item.tree, "", &mut paths);
        for target in paths {
            self.edges.push(ImportEdge {
                source_file: self.path.to_owned(),
                target_module: target,
                line_number: item.use_token.span.start().line,
            });
        }
    }
}

fn expand(tree: &syn::UseTree, prefix: &str, output: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            expand(&path.tree, &format!("{prefix}{}::", path.ident), output)
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                expand(item, prefix, output);
            }
        }
        syn::UseTree::Name(name) => output.push(if name.ident == "self" {
            prefix.trim_end_matches("::").to_owned()
        } else {
            format!("{prefix}{}", name.ident)
        }),
        syn::UseTree::Rename(rename) => output.push(format!("{prefix}{}", rename.ident)),
        syn::UseTree::Glob(_) => output.push(format!("{prefix}*")),
    }
}
