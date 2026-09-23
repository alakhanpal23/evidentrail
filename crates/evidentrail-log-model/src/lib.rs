//! Shared parsing and stable log-template normalization.
//! Original source bytes remain in the corpus; this parser produces only
//! advisory grouping metadata and never authorizes source access.

use serde_json::Value;

#[derive(Clone, Debug)]
pub struct ParsedEvent {
    pub id: String,
    pub raw: String,
    pub service: String,
    pub role: &'static str,
    pub fingerprint: String,
    pub timestamp: Option<i64>,
}

fn valid_service(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub fn parse_event(line: usize, raw: &str) -> ParsedEvent {
    let parsed = serde_json::from_str::<Value>(raw).ok();
    let timestamp = parsed.as_ref().and_then(|value| {
        value
            .get("timestamp")
            .and_then(|timestamp| {
                timestamp
                    .as_i64()
                    .or_else(|| timestamp.as_str()?.parse::<i64>().ok())
            })
            .or_else(|| {
                value
                    .get("timeUnixNano")
                    .and_then(Value::as_str)
                    .and_then(|nanos| nanos.parse::<i64>().ok())
                    .map(|nanos| nanos / 1_000_000_000)
            })
    });
    let message = parsed
        .as_ref()
        .and_then(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| value.get("body").and_then(Value::as_str))
                .or_else(|| value.pointer("/body/stringValue").and_then(Value::as_str))
        })
        .unwrap_or(raw);
    let service = parsed
        .as_ref()
        .and_then(|value| {
            value
                .get("service")
                .and_then(Value::as_str)
                .or_else(|| {
                    value
                        .pointer("/resource/service.name")
                        .and_then(Value::as_str)
                })
                .or_else(|| value.get("service.name").and_then(Value::as_str))
                .or_else(|| otel_resource_service(value))
        })
        .filter(|name| valid_service(name))
        .map(str::to_owned)
        .or_else(|| bracketed_service(raw).map(str::to_owned))
        .or_else(|| field_value(raw, "service="))
        .unwrap_or_else(|| "unknown".to_owned());
    let level = parsed
        .as_ref()
        .and_then(|value| {
            value
                .get("severity_text")
                .or_else(|| value.get("severityText"))
                .or_else(|| value.get("level"))
                .and_then(Value::as_str)
        })
        .map(str::to_owned)
        .or_else(|| {
            parsed
                .as_ref()?
                .get("severityNumber")?
                .as_u64()
                .and_then(|number| match number {
                    21..=24 => Some("critical"),
                    17..=20 => Some("error"),
                    13..=16 => Some("warning"),
                    _ => None,
                })
                .map(str::to_owned)
        })
        .or_else(|| bracketed_level(raw).map(str::to_owned))
        .or_else(|| field_value(raw, "level="))
        .unwrap_or_default();
    let role = classify_role(&level, message);
    let fingerprint = if parsed.is_some() {
        let mut tokens = message.split_ascii_whitespace().collect::<Vec<_>>();
        if tokens.first().is_some_and(|token| looks_like_date(token)) {
            tokens.remove(0);
            if tokens.first().is_some_and(|token| looks_like_time(token)) {
                tokens.remove(0);
            }
        }
        if tokens
            .first()
            .is_some_and(|token| token.starts_with("ts=") && looks_like_iso_timestamp(&token[3..]))
        {
            tokens.remove(0);
        }
        tokens
            .into_iter()
            .map(normalize_fingerprint_token)
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        raw.split_ascii_whitespace()
            .filter(|token| {
                !token.starts_with("service=")
                    && !token.starts_with("level=")
                    && !token.starts_with("timestamp=")
                    && !looks_like_iso_timestamp(token)
            })
            .map(normalize_fingerprint_token)
            .collect::<Vec<_>>()
            .join(" ")
    };
    ParsedEvent {
        id: format!("L{line}"),
        raw: raw.to_owned(),
        service,
        role,
        fingerprint,
        timestamp,
    }
}

fn bracketed_service(raw: &str) -> Option<&str> {
    let (name, _) = raw.strip_prefix('[')?.split_once(']')?;
    valid_service(name).then_some(name)
}

fn bracketed_level(raw: &str) -> Option<&str> {
    let (_, suffix) = raw.strip_prefix('[')?.split_once(']')?;
    let level = suffix
        .split_ascii_whitespace()
        .next()?
        .trim_end_matches(':');
    matches!(
        level.to_ascii_lowercase().as_str(),
        "fatal" | "critical" | "panic" | "error" | "err" | "warn" | "warning" | "info" | "debug"
    )
    .then_some(level)
}

fn otel_resource_service(value: &Value) -> Option<&str> {
    let attributes = value.pointer("/resource/attributes")?;
    if let Some(items) = attributes.as_array() {
        return items.iter().find_map(|item| {
            (item.get("key")?.as_str()? == "service.name")
                .then(|| item.pointer("/value/stringValue")?.as_str())
                .flatten()
        });
    }
    attributes
        .get("service.name")
        .and_then(|item| item.as_str().or_else(|| item.get("stringValue")?.as_str()))
}

fn normalize_fingerprint_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    let trimmed = lower.trim_matches(|character: char| {
        matches!(
            character,
            ',' | ';' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}'
        )
    });
    if let Some((key, value)) = trimmed.split_once(['=', ':']) {
        if matches!(
            key,
            "request_id"
                | "request-id"
                | "requestid"
                | "x-request-id"
                | "trace_id"
                | "trace-id"
                | "span_id"
                | "span-id"
                | "correlation_id"
                | "correlation-id"
        ) && !value.is_empty()
        {
            return format!("{key}=<id>");
        }
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return "<uuid>".to_owned();
    }
    if bytes.len() >= 32 && bytes.iter().all(u8::is_ascii_hexdigit) {
        return "<hex-id>".to_owned();
    }
    normalize_temporal_fragments(&lower)
}

pub fn normalize_temporal_fragments(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let before_digit = index > 0 && bytes[index - 1].is_ascii_digit();
        if !before_digit
            && bytes.len() >= index + 10
            && bytes[index + 4] == b'-'
            && bytes[index + 7] == b'-'
            && (0..10)
                .all(|offset| matches!(offset, 4 | 7) || bytes[index + offset].is_ascii_digit())
            && bytes
                .get(index + 10)
                .is_none_or(|byte| !byte.is_ascii_digit())
        {
            output.extend_from_slice(b"<date>");
            index += 10;
            continue;
        }
        if !before_digit
            && (index == 0 || bytes[index - 1] != b':')
            && bytes.len() >= index + 8
            && bytes[index + 2] == b':'
            && bytes[index + 5] == b':'
            && (0..8)
                .all(|offset| matches!(offset, 2 | 5) || bytes[index + offset].is_ascii_digit())
        {
            let mut end = index + 8;
            if bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_digit) {
                end += 1;
                while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                    end += 1;
                }
            }
            if bytes
                .get(end)
                .is_none_or(|byte| !byte.is_ascii_digit() && *byte != b':')
            {
                output.extend_from_slice(b"<time>");
                index = end;
                continue;
            }
        }
        if bytes[index].is_ascii_digit() && !before_digit {
            let mut end = index + 1;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            if end - index == 13 {
                output.extend_from_slice(b"<epoch_ms>");
            } else {
                output.extend_from_slice(&bytes[index..end]);
            }
            index = end;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(output).expect("UTF-8 input with ASCII-only replacements")
}

fn looks_like_date(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}

fn looks_like_time(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 8
        && bytes[2] == b':'
        && bytes[5] == b':'
        && bytes[..2].iter().all(u8::is_ascii_digit)
        && bytes[3..5].iter().all(u8::is_ascii_digit)
        && bytes[6..8].iter().all(u8::is_ascii_digit)
}

fn looks_like_iso_timestamp(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes[..4].iter().all(u8::is_ascii_digit)
}

fn field_value(raw: &str, prefix: &str) -> Option<String> {
    raw.split_ascii_whitespace().find_map(|token| {
        token.strip_prefix(prefix).and_then(|value| {
            let value = value.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.')
            });
            valid_service(value).then(|| value.to_owned())
        })
    })
}

fn classify_role(level: &str, message: &str) -> &'static str {
    let lower_level = level.to_ascii_lowercase();
    if matches!(lower_level.as_str(), "fatal" | "critical" | "panic") {
        return "critical";
    }
    if matches!(lower_level.as_str(), "error" | "err") {
        return "error";
    }
    if matches!(lower_level.as_str(), "warn" | "warning") {
        return "warning";
    }
    let mut previous_is_negation = false;
    for token in message.split(|character: char| !character.is_ascii_alphanumeric()) {
        let token = token.to_ascii_lowercase();
        if !previous_is_negation
            && matches!(
                token.as_str(),
                "error" | "failed" | "failure" | "panic" | "exception"
            )
        {
            return "error";
        }
        previous_is_negation = matches!(token.as_str(), "no" | "without" | "zero");
    }
    let lower = message.to_ascii_lowercase();
    if [
        "deploy",
        "restart",
        "migration",
        "config changed",
        "rollout",
    ]
    .iter()
    .any(|term| lower.contains(term))
    {
        "change"
    } else {
        "context"
    }
}
