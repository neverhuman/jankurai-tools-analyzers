//! Recognizes storage operations and simple aliases conservatively.
//! Names carry possible credential evidence, not a proof of value origin or CSRF purpose.
//! Alias facts are file-wide and monotone; opaque helpers, destructuring, dynamic members,
//! reassignment/scope precision and arbitrary JavaScript value flow are outside this grammar.

use super::storage_tokens::{at, closing, expression_end, tokens, Kind, Token};
use super::HLT_RULE_ID;
use jankurai_audit_kernel::audit::language_rules::common::{finding, nearby_allow};
use jankurai_audit_kernel::audit::language_rules::{LanguageFinding, ProofWindow};
use jankurai_audit_kernel::model::FileInfo;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const DETECTOR: &str = "websec.storage.token";

pub(super) fn findings(file: &FileInfo) -> Vec<LanguageFinding> {
    let (tokens, complete) = tokens(&file.text);
    let (stores, credentials) = aliases(&tokens);
    let mut lines = BTreeSet::new();
    for start in 0..tokens.len() {
        let Some(end) = storage_base(&tokens, start, &stores) else {
            continue;
        };
        let Some((member, next)) = member(&tokens, end) else {
            continue;
        };
        let next = skip_non_null(&tokens, next);
        let call = if at(&tokens, next, "?") && at(&tokens, next + 1, ".") {
            next + 2
        } else {
            next
        };
        let evidence = if at(&tokens, call, "(") {
            // Removal is only about this operation, never the whole line.
            if !matches!(member.text.as_str(), "setItem" | "getItem") {
                continue;
            }
            let end = closing(&tokens, call).unwrap_or(tokens.len());
            &tokens[call + 1..end]
        } else if let Some(rhs) = assignment_rhs(&tokens, next) {
            &tokens[rhs..expression_end(&tokens, rhs)]
        } else {
            &[]
        };
        if sensitive(member, &credentials) || evidence.iter().any(|t| sensitive(t, &credentials)) {
            lines.insert(tokens[start].line);
        }
    }
    if !complete || file.rel_path.to_ascii_lowercase().ends_with(".html") {
        // A malformed literal or dynamic template must not erase an old positive.
        // HTML attributes contain executable event handlers, so quoted values there
        // are not JavaScript data literals. Retain conservative scanning until parsed.
        for (idx, line) in file.text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if (lower.contains("sessionstorage") || lower.contains("localstorage"))
                && sensitive_text(&lower)
            {
                lines.insert(idx + 1);
            }
        }
    }
    lines.into_iter().filter(|line| !nearby_allow(&file.text, *line, DETECTOR)).map(|line| {
        finding(
            HLT_RULE_ID,
            DETECTOR,
            file,
            line,
            "sensitive token or session material is stored in browser-accessible storage",
            "localStorage and sessionStorage are readable by injected JavaScript",
            "prefer HttpOnly Secure SameSite cookies or a bounded in-memory token flow with documented threat model",
            ProofWindow::None,
        )
    }).collect()
}

fn sensitive_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "token",
        "jwt",
        "session",
        "secret",
        "password",
        "authorization",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn sensitive(token: &Token, credentials: &BTreeSet<String>) -> bool {
    token.kind != Kind::Punctuation
        && !matches!(token.text.as_str(), "sessionStorage" | "localStorage")
        && (sensitive_text(&token.text)
            || token.kind == Kind::Identifier && credentials.contains(&token.text))
}

fn member(tokens: &[Token], start: usize) -> Option<(&Token, usize)> {
    let mut i = skip_non_null(tokens, start);
    if at(tokens, i, "?") && at(tokens, i + 1, ".") {
        i += 2;
    } else if at(tokens, i, ".") {
        i += 1;
    } else if !at(tokens, i, "[") {
        return None;
    }
    if at(tokens, i, "[") {
        let key = tokens.get(i + 1)?;
        return (key.kind == Kind::String && at(tokens, i + 2, "]")).then_some((key, i + 3));
    }
    let key = tokens.get(i)?;
    (key.kind == Kind::Identifier).then_some((key, i + 1))
}

fn skip_non_null(tokens: &[Token], mut index: usize) -> usize {
    while at(tokens, index, "!") && !at(tokens, index + 1, "=") {
        index += 1;
    }
    index
}

fn storage_base(tokens: &[Token], start: usize, aliases: &BTreeSet<String>) -> Option<usize> {
    let first = tokens.get(start)?;
    if first.kind != Kind::Identifier {
        return None;
    }
    // Avoid interpreting a member of an unrelated object as a browser global.
    if start > 0 && (at(tokens, start - 1, ".") || at(tokens, start - 1, "?")) {
        return None;
    }
    if aliases.contains(&first.text) {
        return Some(start + 1);
    }
    if matches!(first.text.as_str(), "window" | "globalThis" | "self") {
        let (key, end) = member(tokens, start + 1)?;
        if matches!(key.text.as_str(), "sessionStorage" | "localStorage") {
            return Some(end);
        }
    }
    None
}

fn aliases(tokens: &[Token]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut stores = BTreeSet::from(["sessionStorage".into(), "localStorage".into()]);
    let mut credentials = BTreeSet::new();
    let mut store_edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut credential_edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, start) in assignments(tokens) {
        let rhs = &tokens[start..expression_end(tokens, start)];
        let base_end = storage_base(tokens, start, &stores);
        if base_end.is_some_and(|end| alias_ends(tokens, end)) {
            stores.insert(name.clone());
        } else if tokens
            .get(start)
            .is_some_and(|t| t.kind == Kind::Identifier)
            && alias_ends(tokens, start + 1)
        {
            store_edges
                .entry(tokens[start].text.clone())
                .or_default()
                .push(name.clone());
        }
        for token in rhs {
            if sensitive(token, &BTreeSet::new()) {
                credentials.insert(name.clone());
            }
            if token.kind == Kind::Identifier {
                credential_edges
                    .entry(token.text.clone())
                    .or_default()
                    .push(name.clone());
            }
        }
    }
    propagate(&mut stores, &store_edges);
    propagate(&mut credentials, &credential_edges);
    (stores, credentials)
}

fn assignments(tokens: &[Token]) -> Vec<(String, usize)> {
    let mut targets = BTreeMap::new();
    // Bind the declared identifier, not the final identifier in its TS annotation.
    for i in 0..tokens.len().saturating_sub(1) {
        if !matches!(tokens[i].text.as_str(), "const" | "let" | "var")
            || tokens[i].kind != Kind::Identifier
            || tokens[i + 1].kind != Kind::Identifier
        {
            continue;
        }
        let mut operator = i + 2;
        if at(tokens, operator, ":") {
            operator += 1;
            while operator < tokens.len()
                && !at(tokens, operator, "=")
                && !at(tokens, operator, ";")
                && !at(tokens, operator, "{")
            {
                operator += 1;
            }
        }
        if let Some(rhs) = assignment_rhs(tokens, operator) {
            targets.insert(rhs, tokens[i + 1].text.clone());
        }
    }
    for i in 0..tokens.len() {
        if tokens[i].kind == Kind::Identifier {
            if let Some(rhs) = assignment_rhs(tokens, i + 1) {
                targets.entry(rhs).or_insert_with(|| tokens[i].text.clone());
            }
        }
    }
    targets.into_iter().map(|(rhs, name)| (name, rhs)).collect()
}

fn alias_ends(tokens: &[Token], end: usize) -> bool {
    let end = skip_non_null(tokens, end);
    let Some(next) = tokens.get(end) else {
        return true;
    };
    if [";", ",", ")", "}"].iter().any(|p| at(tokens, end, p)) {
        return true;
    }
    // A following identifier on a fresh line can start a new ASI statement.
    // Member/call/operator continuations must not turn a property read into an alias.
    end > 0
        && next.line > tokens[end - 1].line
        && next.kind == Kind::Identifier
        && !matches!(next.text.as_str(), "as" | "satisfies" | "in" | "instanceof")
}

fn assignment_rhs(tokens: &[Token], start: usize) -> Option<usize> {
    let mut operator = String::new();
    for (i, token) in tokens.iter().enumerate().skip(start).take(4) {
        if token.kind != Kind::Punctuation {
            return None;
        }
        operator.push_str(&token.text);
        if token.text == "=" {
            if at(tokens, i + 1, "=") || at(tokens, i + 1, ">") {
                return None;
            }
            return matches!(
                operator.as_str(),
                "=" | "+="
                    | "-="
                    | "*="
                    | "/="
                    | "%="
                    | "**="
                    | "<<="
                    | ">>="
                    | ">>>="
                    | "&="
                    | "^="
                    | "|="
                    | "&&="
                    | "||="
                    | "??="
            )
            .then_some(i + 1);
        }
    }
    None
}

fn propagate(names: &mut BTreeSet<String>, edges: &BTreeMap<String, Vec<String>>) {
    let mut queue: VecDeque<_> = names.iter().cloned().collect();
    while let Some(name) = queue.pop_front() {
        for next in edges.get(&name).into_iter().flatten() {
            if names.insert(next.clone()) {
                queue.push_back(next.clone());
            }
        }
    }
}
