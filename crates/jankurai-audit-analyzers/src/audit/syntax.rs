use anyhow::{bail, Context, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::Program;
use oxc_parser::Parser;
use oxc_span::SourceType;

/// Consumers only receive a complete parsed program. Returned observations
/// own their data and cannot retain references into the parser arena.
pub(super) fn javascript<R>(
    path: &str,
    source: &str,
    inspect: impl for<'a> FnOnce(&Program<'a>) -> R,
) -> Result<R> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .with_context(|| format!("incomplete analysis: unsupported JavaScript source {path}"))?;
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        bail!(
            "incomplete analysis: invalid JavaScript/TypeScript syntax in {path}: {:?}",
            parsed.diagnostics
        );
    }
    Ok(inspect(&parsed.program))
}

pub(super) fn line(source: &str, offset: u32) -> usize {
    source.as_bytes()[..offset as usize]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}
