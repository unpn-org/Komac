//! Declaration syntax for the NSIS System plugin.
//!
//! <https://github.com/NSIS-Dev/nsis/blob/master/Contrib/System/Source/System.c>

use crate::analysis::installers::nsis::{Variables, strings::PredefinedVar};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Void,
    Int,
    Long,
    Pointer,
    Ansi,
    Wide,
    Text,
    Guid,
    Callback,
    RegisterMemory,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Io {
    #[default]
    None,
    Stack,
    Register(usize),
    Literal(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub kind: Kind,
    pub kind_specified: bool,
    pub reference: bool,
    pub array: Option<usize>,
    pub aligned: bool,
    pub input: Io,
    pub output: Io,
}

impl Default for Parameter {
    fn default() -> Self {
        Self {
            kind: Kind::Void,
            kind_specified: false,
            reference: false,
            array: None,
            aligned: false,
            input: Io::None,
            output: Io::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub status: bool,
    pub last_error: bool,
    pub syntax2: bool,
    pub never_redefine: bool,
    pub changed: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    pub target: String,
    pub parameters: Vec<Parameter>,
    pub result: Parameter,
    pub options: Options,
    pub has_signature: bool,
    pub has_result: bool,
}

pub fn register(token: &str) -> Option<usize> {
    let (prefix, digits) = token.split_at_checked(1)?;
    match prefix {
        "r" | "R" => {
            let value = digits.parse::<usize>().ok()?;
            let value = if prefix == "R" && value < 10 {
                value + 10
            } else {
                value
            };
            (value < 4096).then_some(value)
        }
        _ if digits.is_empty() => {
            let var = match prefix.to_ascii_lowercase().as_str() {
                "c" => PredefinedVar::CmdLine,
                "d" => PredefinedVar::InstDir,
                "o" => PredefinedVar::OutDir,
                "e" => PredefinedVar::ExeDir,
                "a" => PredefinedVar::Language,
                _ => return None,
            };
            Some(Variables::NUM_REGISTERS + var as usize)
        }
        _ => None,
    }
}

fn quoted(input: &str) -> Option<(String, &str)> {
    let quote = input.chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }
    let mut output = String::new();
    let mut chars = input[quote.len_utf8()..].char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if character == quote {
            if chars.peek().is_some_and(|(_, next)| *next == quote) {
                chars.next();
                output.push(quote);
            } else {
                return Some((
                    output,
                    &input[quote.len_utf8() + index + quote.len_utf8()..],
                ));
            }
        } else {
            output.push(character);
        }
    }
    None
}

fn selector(input: &str) -> Option<(Io, &str)> {
    let input = input.trim_start();
    if input.starts_with(['\'', '"', '`']) {
        let (value, rest) = quoted(input)?;
        return Some((Io::Literal(value), rest));
    }
    let first = input.chars().next()?;
    if matches!(first, 's' | 'S') {
        return Some((Io::Stack, &input[1..]));
    }
    if matches!(first, 'r' | 'R') {
        let end = input[1..]
            .find(|c: char| !c.is_ascii_digit())
            .map_or(input.len(), |n| n + 1);
        return Some((Io::Register(register(&input[..end])?), &input[end..]));
    }
    if matches!(first.to_ascii_lowercase(), 'c' | 'd' | 'o' | 'e' | 'a') {
        return Some((Io::Register(register(&input[..1])?), &input[1..]));
    }
    let end = input
        .find(|c: char| !(c.is_ascii_hexdigit() || matches!(c, '-' | '+' | 'x' | 'X' | '|')))
        .unwrap_or(input.len());
    if end == 0 {
        return None;
    }
    Some((Io::Literal(input[..end].to_owned()), &input[end..]))
}

fn io(input: &str, parameter: &mut Parameter) -> Option<()> {
    let mut rest = input.trim();
    let mut position = 0usize;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('.') {
            position += 1;
            rest = after.trim_start();
            continue;
        }
        let (value, after) = selector(rest)?;
        if position == 1 {
            if matches!(value, Io::Literal(_)) {
                return None;
            }
            parameter.output = value;
        } else if position == 0 {
            parameter.input = value;
        }
        position += 1;
        rest = after.trim_start();
    }
    Some(())
}

fn parameter(input: &str) -> Option<Parameter> {
    let mut rest = input.trim();
    if rest.is_empty() {
        return Some(Parameter::default());
    }
    let mut parameter = Parameter::default();
    if let Some(after) = rest.strip_prefix('*') {
        parameter.reference = true;
        rest = after.trim_start();
    }
    let array = rest.starts_with('&');
    if array {
        rest = rest[1..].trim_start();
    }
    let code = rest.chars().next()?;
    parameter.aligned = code.is_ascii_uppercase();
    parameter.kind = match code.to_ascii_lowercase() {
        'v' => Kind::Void,
        'i' | 'b' | 'h' => Kind::Int,
        'l' => Kind::Long,
        'p' => Kind::Pointer,
        'm' => Kind::Ansi,
        'w' => Kind::Wide,
        't' => Kind::Text,
        'g' => Kind::Guid,
        'k' => Kind::Callback,
        '@' => Kind::RegisterMemory,
        _ => {
            io(input, &mut parameter)?;
            return Some(parameter);
        }
    };
    parameter.kind_specified = true;
    rest = &rest[code.len_utf8()..];
    if array {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        parameter.array = Some(if end == 0 && parameter.kind == Kind::Long {
            0
        } else {
            rest[..end].parse().ok()?
        });
        rest = &rest[end..];
    } else if code.eq_ignore_ascii_case(&'b') {
        parameter.array = Some(1);
    } else if code.eq_ignore_ascii_case(&'h') {
        parameter.array = Some(2);
    }
    io(rest, &mut parameter)?;
    Some(parameter)
}

fn group(input: &str) -> Option<(&str, &str)> {
    let input = input.strip_prefix('(')?;
    let mut quote = None;
    let mut depth = 1;
    let mut chars = input.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if let Some(q) = quote {
            if character == q {
                if chars.peek().is_some_and(|(_, next)| *next == q) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
        } else if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
        } else if character == '(' {
            depth += 1;
        } else if character == ')' {
            depth -= 1;
            if depth == 0 {
                return Some((&input[..index], &input[index + 1..]));
            }
        }
    }
    None
}

fn split(input: &str) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut chars = input.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if let Some(q) = quote {
            if character == q {
                if chars.peek().is_some_and(|(_, next)| *next == q) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
        } else if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
        } else if character == ',' {
            parts.push(input[start..index].trim());
            start = index + 1;
        }
    }
    if quote.is_some() {
        return None;
    }
    if !input.is_empty() {
        parts.push(input[start..].trim());
    }
    (parts.len() <= 99).then_some(parts)
}

impl Declaration {
    pub fn parse(input: &str) -> Option<Self> {
        if input.len() > 32768 {
            return None;
        }
        let input = input.trim();
        let first = input.find('(');
        let target = input[..first.unwrap_or_else(|| input.find('?').unwrap_or(input.len()))]
            .trim()
            .to_owned();
        if target.is_empty() {
            return None;
        }
        let mut declaration = Self {
            target,
            parameters: Vec::new(),
            result: Parameter::default(),
            options: Options::default(),
            has_signature: first.is_some(),
            has_result: false,
        };
        let Some(first) = first else {
            if let Some((_, flags)) = input.split_once('?') {
                declaration.options = Options::parse(flags)?;
            }
            return Some(declaration);
        };
        let (params, suffix) = group(&input[first..])?;
        declaration.parameters = split(params)?
            .into_iter()
            .map(parameter)
            .collect::<Option<_>>()?;
        let mut suffix = suffix.trim_start();
        let result_end = suffix.find(['(', '?']).unwrap_or(suffix.len());
        declaration.result = parameter(&suffix[..result_end])?;
        declaration.has_result = !suffix[..result_end].trim().is_empty();
        suffix = suffix[result_end..].trim_start();
        if suffix.starts_with('(') {
            let (arguments, rest) = group(suffix)?;
            let arguments = split(arguments)?;
            if arguments.len() > declaration.parameters.len() {
                return None;
            }
            for (arg, parameter) in arguments.into_iter().zip(&mut declaration.parameters) {
                io(arg, parameter)?;
            }
            suffix = rest.trim_start();
            if suffix.starts_with('.') {
                let end = suffix.find('?').unwrap_or(suffix.len());
                io(&suffix[..end], &mut declaration.result)?;
                suffix = suffix[end..].trim_start();
            }
        }
        if let Some(flags) = suffix.strip_prefix('?') {
            declaration.options = Options::parse(flags)?;
        } else if !suffix.is_empty() {
            return None;
        }
        Some(declaration)
    }
}

impl Options {
    fn parse(flags: &str) -> Option<Self> {
        let mut options = Self::default();
        let mut enabled = true;
        for character in flags.chars().filter(|c| !c.is_ascii_whitespace()) {
            match character {
                '!' => {
                    enabled = !enabled;
                    continue;
                }
                'r' => {
                    options.status = enabled;
                    options.changed |= 1;
                }
                'e' => {
                    options.last_error = enabled;
                    options.changed |= 2;
                }
                '2' => {
                    options.syntax2 = enabled;
                    options.changed |= 4;
                }
                'n' => {
                    options.never_redefine = enabled;
                    options.changed |= 8;
                }
                'c' | 's' | 'u' => {}
                _ => return None,
            }
            enabled = true;
        }
        Some(options)
    }

    pub fn inherit(mut self, previous: Self) -> Self {
        if self.changed & 1 == 0 {
            self.status = previous.status;
        }
        if self.changed & 2 == 0 {
            self.last_error = previous.last_error;
        }
        if self.changed & 4 == 0 {
            self.syntax2 = previous.syntax2;
        }
        if self.changed & 8 == 0 {
            self.never_redefine = previous.never_redefine;
        }
        self
    }
}

impl Parameter {
    pub fn inherit(mut self, previous: &Self) -> Self {
        if !self.kind_specified {
            self.kind = previous.kind;
            self.kind_specified = previous.kind_specified;
            self.reference = previous.reference;
            self.array = previous.array;
            self.aligned = previous.aligned;
            if self.input == Io::None {
                self.input = previous.input.clone();
            }
            if self.output == Io::None {
                self.output = previous.output.clone();
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inline_and_legacy_syntax_without_splitting_quoted_arguments() {
        let inline =
            Declaration::parse("kernel32::SetEnvironmentVariable(t 'a,b', t `x(y)`)i.r0?e")
                .unwrap();
        assert_eq!(inline.parameters[0].input, Io::Literal("a,b".to_owned()));
        assert_eq!(inline.parameters[1].input, Io::Literal("x(y)".to_owned()));
        let legacy =
            Declaration::parse("kernel32::SetEnvironmentVariable(t,t)i ('a,b', `x(y)`).r0?e")
                .unwrap();
        assert_eq!(inline, legacy);
    }

    #[test]
    fn parses_in_out_structures_stack_and_register_aliases() {
        let value = Declaration::parse("*123(i.s,i.r1,&t128.s,&i2.R9,&l.r0)p?2").unwrap();
        assert_eq!(value.parameters[3].output, Io::Register(19));
        assert_eq!(value.parameters[4].array, Some(0));
        assert!(value.options.syntax2);
        let call = Declaration::parse("kernel32::IsWow64Process2(ps,*i0s,*i)i.r1").unwrap();
        assert_eq!(call.parameters[1].input, Io::Literal("0".to_owned()));
        assert_eq!(call.parameters[1].output, Io::Stack);
        assert!(Declaration::parse("x::f(t 'unterminated)i").is_none());
        assert!(Declaration::parse("x::f(q)i").is_none());
    }
}
