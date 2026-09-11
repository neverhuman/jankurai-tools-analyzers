use super::{DependencyGraph, ImportEdge};
use crate::audit::syntax;
use anyhow::Result;
use oxc_ast::ast::{
    ExportAllDeclaration, ExportFromDeclaration, Expression, ImportDeclaration, ImportExpression,
};
use oxc_ast_visit::{walk, Visit};

pub(super) fn parse(path: &str, source: &str, graph: &mut DependencyGraph) -> Result<()> {
    let edges = syntax::javascript(path, source, |program| {
        let mut visitor = Imports {
            path,
            source,
            edges: Vec::new(),
        };
        visitor.visit_program(program);
        visitor.edges
    })?;
    for edge in edges {
        graph.add_edge(edge);
    }
    Ok(())
}

struct Imports<'a> {
    path: &'a str,
    source: &'a str,
    edges: Vec<ImportEdge>,
}

impl Imports<'_> {
    fn edge(&mut self, module: &str, offset: u32) {
        self.edges.push(ImportEdge {
            source_file: self.path.to_owned(),
            target_module: module.to_owned(),
            line_number: syntax::line(self.source, offset),
        });
    }
}

impl<'a> Visit<'a> for Imports<'_> {
    fn visit_import_declaration(&mut self, node: &ImportDeclaration<'a>) {
        self.edge(node.source.value.as_str(), node.span.start);
    }
    fn visit_export_from_declaration(&mut self, node: &ExportFromDeclaration<'a>) {
        self.edge(node.source.value.as_str(), node.span.start);
    }
    fn visit_export_all_declaration(&mut self, node: &ExportAllDeclaration<'a>) {
        self.edge(node.source.value.as_str(), node.span.start);
    }
    fn visit_import_expression(&mut self, node: &ImportExpression<'a>) {
        if let Expression::StringLiteral(source) = node.source.get_inner_expression() {
            self.edge(source.value.as_str(), node.span.start);
        }
        walk::walk_import_expression(self, node);
    }
}
