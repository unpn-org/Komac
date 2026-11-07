use super::variables::MAX_STRING_LENGTH;

/// Formats an integer using the subset of `wsprintf` formats supported by `IntFmt`.
///
/// Returns [`None`] for unsupported formats or missing arguments.
pub fn format_integer(format: &str, value: i64, wide: bool) -> Option<String> {
    let mut chars = format.chars().peekable();
    let mut output = String::new();
    let mut used_value = false;
    while let Some(c) = chars.next() {
        if c != '%' {
            output.push(c);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            output.push('%');
            continue;
        }
        if used_value {
            return None;
        }
        used_value = true;
        let (mut left, mut zero, mut alternate) = (false, false, false);
        loop {
            match chars.peek()? {
                '-' => left = true,
                '0' => zero = true,
                '#' => alternate = true,
                _ => break,
            }
            chars.next();
        }
        let mut width = 0usize;
        while let Some(digit) = chars.peek().and_then(|c| c.to_digit(10)) {
            width = width.checked_mul(10)?.checked_add(digit as usize)?;
            if width > MAX_STRING_LENGTH {
                return None;
            }
            chars.next();
        }
        if chars.peek() == Some(&'l') {
            chars.next();
        }
        let conversion = chars.next()?;
        let signed_value = if wide { value } else { i64::from(value as i32) };
        let unsigned_value = if wide {
            value as u64
        } else {
            u64::from(value as u32)
        };
        let signed = matches!(conversion, 'd' | 'i');
        let digits = match conversion {
            'd' | 'i' => signed_value.unsigned_abs().to_string(),
            'u' => unsigned_value.to_string(),
            'x' => format!("{unsigned_value:x}"),
            'X' => format!("{unsigned_value:X}"),
            _ => return None,
        };
        let sign = if signed && signed_value < 0 { "-" } else { "" };
        // wsprintf has fewer conversions/flags than C printf. Keep ambiguous
        // combinations explicit instead of silently applying printf semantics.
        if left && zero || alternate && (!matches!(conversion, 'x' | 'X') || unsigned_value == 0) {
            return None;
        }
        let prefix = if alternate && unsigned_value != 0 {
            match conversion {
                'x' => "0x",
                'X' => "0X",
                _ => "",
            }
        } else {
            ""
        };
        let padding = width.saturating_sub(sign.len() + prefix.len() + digits.len());
        if !left && !zero {
            output.push_str(&" ".repeat(padding));
        }
        output.push_str(sign);
        output.push_str(prefix);
        if !left && zero {
            output.push_str(&"0".repeat(padding));
        }
        output.push_str(&digits);
        if left {
            output.push_str(&" ".repeat(padding));
        }
        if output.len() > MAX_STRING_LENGTH {
            return None;
        }
    }
    (output.len() <= MAX_STRING_LENGTH).then_some(output)
}

#[cfg(test)]
mod tests {
    use super::format_integer;

    #[test]
    fn bounded_windows_integer_formats() {
        for (format, value, wide, expected) in [
            ("v%02u", 7, false, "v07"),
            ("0x%08X", 255, false, "0x000000FF"),
            ("%05d", -12, false, "-0012"),
            ("%u", -1, false, "4294967295"),
            ("%#x", 16, false, "0x10"),
            ("%% %d", 42, false, "% 42"),
            ("%u", 4294967296, true, "4294967296"),
        ] {
            assert_eq!(
                format_integer(format, value, wide).as_deref(),
                Some(expected)
            );
        }
        assert_eq!(format_integer("%999999999d", 0, false), None);
        assert_eq!(format_integer("%d %d", 0, false), None);
        assert_eq!(format_integer("%s", 0, false), None);
        assert_eq!(format_integer("%o", 0, false), None);
        assert_eq!(format_integer("%+d", 0, false), None);
    }
}
