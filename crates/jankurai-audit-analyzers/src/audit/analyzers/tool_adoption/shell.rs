#[derive(Clone)]
pub(super) struct Command {
    pub words: Vec<String>,
    pub line: usize,
}

const MAX_BYTES: usize = 64 * 1024;
const MAX_COMMANDS: usize = 256;

// Read a deliberately small literal command language. Unsupported Bash syntax
// invalidates the whole input: its interior text cannot become route evidence.
// This reader never executes commands or expands repository-controlled values.
pub(super) fn commands(source: &str) -> Result<Vec<Command>, String> {
    if source.len() > MAX_BYTES {
        return Err("shell source exceeds byte limit".into());
    }
    let chars: Vec<_> = source.chars().collect();
    let (mut at, mut line, mut command_line) = (0, 1, 1);
    let mut quote = None;
    let mut active = false;
    let mut word = String::new();
    let mut words = Vec::new();
    let mut result = Vec::new();
    while let Some(&ch) = chars.get(at) {
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else if ch == '\\' && delimiter == '"' {
                let Some(&next) = chars.get(at + 1) else {
                    return Err("unterminated shell escape".into());
                };
                if next == '\n' {
                    line += 1;
                } else {
                    if !matches!(next, '$' | '`' | '"' | '\\') {
                        word.push('\\');
                    }
                    word.push(next);
                }
                at += 1;
            } else if delimiter == '"' && matches!(ch, '$' | '`') {
                return Err("dynamic double-quoted shell value".into());
            } else {
                word.push(ch);
                if ch == '\n' {
                    line += 1;
                }
            }
        } else {
            match ch {
                '#' if !active => {
                    while chars.get(at).is_some_and(|ch| *ch != '\n') {
                        at += 1;
                    }
                    continue;
                }
                '\\' => {
                    let Some(&next) = chars.get(at + 1) else {
                        return Err("unterminated shell escape".into());
                    };
                    if next == '\n' {
                        line += 1;
                    } else {
                        begin(&mut active, &words, &mut command_line, line);
                        word.push(next);
                    }
                    at += 1;
                }
                '\'' | '"' => {
                    begin(&mut active, &words, &mut command_line, line);
                    quote = Some(ch);
                }
                '\n' | ';' => {
                    finish_word(&mut active, &mut word, &mut words);
                    finish_command(&mut words, command_line, &mut result)?;
                    if ch == '\n' {
                        line += 1;
                    }
                }
                ch if ch.is_whitespace() => {
                    finish_word(&mut active, &mut word, &mut words);
                }
                '$' | '`' | '|' | '&' | '(' | ')' | '{' | '}' | '<' | '>' | '*' | '?' | '['
                | ']' => return Err("unsupported shell expansion or control syntax".into()),
                _ => {
                    begin(&mut active, &words, &mut command_line, line);
                    word.push(ch);
                }
            }
        }
        at += 1;
    }
    if quote.is_some() {
        return Err("unterminated shell quote".into());
    }
    finish_word(&mut active, &mut word, &mut words);
    finish_command(&mut words, command_line, &mut result)?;
    Ok(result)
}

fn begin(active: &mut bool, words: &[String], command_line: &mut usize, line: usize) {
    if !*active && words.is_empty() {
        *command_line = line;
    }
    *active = true;
}

fn finish_word(active: &mut bool, word: &mut String, words: &mut Vec<String>) {
    if *active {
        words.push(std::mem::take(word));
        *active = false;
    }
}

fn finish_command(
    words: &mut Vec<String>,
    line: usize,
    commands: &mut Vec<Command>,
) -> Result<(), String> {
    let Some(first) = words.first() else {
        return Ok(());
    };
    if [
        "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
        "function", "select", "in", "exit", "return", "false", "break", "continue", "exec", "eval",
        "source", ".", "alias", "unalias", "trap", "export", "readonly", "declare", "local",
        "unset", "enable", "builtin", "command", "env", "!",
    ]
    .contains(&first.as_str())
    {
        return Err(format!(
            "unsupported shell command or control word: {first}"
        ));
    }
    if first.contains('=') {
        // A literal assignment contains data, not an invocation. Prefix
        // assignments combined with commands need a separate execution model.
        if words.len() != 1 {
            return Err("unsupported shell assignment prefix".into());
        }
        words.clear();
        return Ok(());
    }
    if first == "set" && words.as_slice() != ["set", "-euo", "pipefail"] {
        return Err("unsupported shell execution-mode mutation".into());
    }
    if first == "cd" && words.as_slice() != ["cd", "."] {
        return Err("unsupported shell working directory".into());
    }
    if commands.len() == MAX_COMMANDS {
        return Err("shell command count exceeds limit".into());
    }
    commands.push(Command {
        words: std::mem::take(words),
        line,
    });
    Ok(())
}
