//! Small lexical input for storage operations, not a JavaScript parser.
//! Dynamic template expressions and incomplete literals retain conservative fallback scanning.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Identifier,
    String,
    Punctuation,
}

#[derive(Clone, Debug)]
pub(super) struct Token {
    pub text: String,
    pub kind: Kind,
    pub line: usize,
}

pub(super) fn tokens(source: &str) -> (Vec<Token>, bool) {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1;
    let mut complete = true;
    while i < chars.len() {
        let ch = chars[i];
        if ch.is_whitespace() {
            line += usize::from(ch == '\n');
            i += 1;
            continue;
        }
        if ch == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                line += usize::from(chars[i] == '\n');
                i += 1;
            }
            if i == chars.len() {
                complete = false;
                break;
            }
            i += 2;
            continue;
        }
        let start_line = line;
        if matches!(ch, '\'' | '"' | '`') {
            let quote = ch;
            i += 1;
            let mut text = String::new();
            let mut closed = false;
            while i < chars.len() {
                let current = chars[i];
                i += 1;
                line += usize::from(current == '\n');
                if current == quote {
                    closed = true;
                    break;
                }
                if current == '\\' {
                    if let Some(escaped) = chars.get(i) {
                        text.push(*escaped);
                        line += usize::from(*escaped == '\n');
                        i += 1;
                    }
                } else {
                    if quote == '`' && current == '$' && chars.get(i) == Some(&'{') {
                        complete = false;
                    }
                    text.push(current);
                }
            }
            complete &= closed;
            out.push(Token {
                text,
                kind: Kind::String,
                line: start_line,
            });
            continue;
        }
        if ch.is_ascii_alphabetic() || matches!(ch, '_' | '$') {
            let start = i;
            i += 1;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '_' | '$'))
            {
                i += 1;
            }
            out.push(Token {
                text: chars[start..i].iter().collect(),
                kind: Kind::Identifier,
                line,
            });
            continue;
        }
        out.push(Token {
            text: ch.to_string(),
            kind: Kind::Punctuation,
            line,
        });
        i += 1;
    }
    (out, complete)
}

pub(super) fn at(tokens: &[Token], index: usize, text: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.kind == Kind::Punctuation && token.text == text)
}

pub(super) fn closing(tokens: &[Token], start: usize) -> Option<usize> {
    let expected = match tokens.get(start)?.text.as_str() {
        "(" => ")",
        "[" => "]",
        "{" => "}",
        _ => return None,
    };
    let mut stack = vec![expected];
    for (i, token) in tokens.iter().enumerate().skip(start + 1) {
        if token.kind != Kind::Punctuation {
            continue;
        }
        match token.text.as_str() {
            "(" => stack.push(")"),
            "[" => stack.push("]"),
            "{" => stack.push("}"),
            ")" | "]" | "}" => {
                if stack.pop() != Some(token.text.as_str()) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn expression_end(tokens: &[Token], start: usize) -> usize {
    let mut i = start;
    while i < tokens.len() {
        if i > start && fresh_statement(&tokens[i - 1], &tokens[i]) {
            return i;
        }
        if tokens[i].kind == Kind::Punctuation {
            if matches!(tokens[i].text.as_str(), ";" | "," | ")" | "]" | "}") {
                return i;
            }
            if matches!(tokens[i].text.as_str(), "(" | "[" | "{") {
                let Some(end) = closing(tokens, i) else {
                    return tokens.len();
                };
                i = end;
            }
        }
        i += 1;
    }
    i
}

fn fresh_statement(previous: &Token, next: &Token) -> bool {
    // A newline after a completed operand can start an identifier statement.
    // Keep multiline operators, groups, members and TS assertions in the RHS.
    next.line > previous.line
        && next.kind == Kind::Identifier
        && !matches!(next.text.as_str(), "as" | "satisfies" | "in" | "instanceof")
        && (previous.kind != Kind::Identifier
            || !matches!(
                previous.text.as_str(),
                "await"
                    | "yield"
                    | "new"
                    | "typeof"
                    | "void"
                    | "delete"
                    | "as"
                    | "satisfies"
                    | "in"
                    | "instanceof"
            ))
        && (previous.kind != Kind::Punctuation || matches!(previous.text.as_str(), ")" | "]" | "}"))
}
