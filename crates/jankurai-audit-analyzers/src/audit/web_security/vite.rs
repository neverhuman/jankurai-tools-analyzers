use super::{finding, nearby_allow, FileInfo, LanguageFinding, ProofWindow, HLT_RULE_ID};
use crate::audit::syntax;
use anyhow::Result;
use oxc_ast::ast::{AssignmentTarget, Expression, ObjectProperty, Statement};
use oxc_ast_visit::{walk, Visit};

pub(super) fn findings(file: &FileInfo) -> Result<Vec<LanguageFinding>> {
    syntax::require_complete(file)?;
    syntax::javascript(&file.rel_path, &file.text, |program| {
        let mut visitor = Properties {
            file,
            path: Vec::new(),
            hits: Vec::new(),
        };
        for statement in &program.body {
            if let Statement::ExportDefaultDeclaration(export) = statement {
                visitor.visit_export_default_declaration(export);
            }
            if let Statement::ExpressionStatement(statement) = statement {
                if let Expression::AssignmentExpression(assignment) = &statement.expression {
                    if let AssignmentTarget::StaticMemberExpression(member) = &assignment.left {
                        let exported = matches!(&member.object,
                            Expression::Identifier(name) if
                            (name.name == "module" && member.property.name == "exports") ||
                            (name.name == "exports" && member.property.name == "default"));
                        if exported {
                            visitor.visit_expression(&assignment.right);
                        }
                    }
                }
            }
        }
        visitor.hits
    })
}

struct Properties<'f> {
    file: &'f FileInfo,
    path: Vec<String>,
    hits: Vec<LanguageFinding>,
}

impl<'a> Visit<'a> for Properties<'_> {
    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        let key = property.key.static_name().map(|key| key.into_owned());
        let value = property.value.get_inner_expression();
        let server = self.path.len() == 1 && matches!(self.path[0].as_str(), "server" | "preview");
        let fs = self.path.len() == 2 && self.path[0] == "server" && self.path[1] == "fs";
        let unsafe_value = match (key.as_deref(), value) {
            (Some("allowedHosts" | "cors" | "host"), Expression::BooleanLiteral(value)) => {
                server && value.value
            }
            (Some("host"), Expression::StringLiteral(value)) => {
                server && matches!(value.value.as_str(), "0.0.0.0" | "::")
            }
            (Some("host"), Expression::TemplateLiteral(value)) => {
                server
                    && value
                        .single_quasi()
                        .is_some_and(|host| matches!(host.as_str(), "0.0.0.0" | "::"))
            }
            (Some("strict"), Expression::BooleanLiteral(value)) => fs && !value.value,
            _ => false,
        };
        let line = syntax::line(&self.file.text, property.span.start);
        if unsafe_value && !nearby_allow(&self.file.text, line, "websec.vite.public-dev-server") {
            self.hits.push(finding(
                HLT_RULE_ID, "websec.vite.public-dev-server", self.file, line,
                "Vite dev or preview server is configured with broad network exposure",
                "Vite dev-server exposure can disclose source or enable host-header and CORS abuse",
                "bind Vite to localhost, use explicit allowedHosts and origins, and keep server.fs.strict enabled",
                ProofWindow::None,
            ));
        }
        self.path.push(key.unwrap_or_default());
        walk::walk_object_property(self, property);
        self.path.pop();
    }
}
