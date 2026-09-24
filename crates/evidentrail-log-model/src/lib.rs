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

/// Extracts only an explicitly named peer service. This is relationship
/// evidence, not a verified dependency direction or a causal assertion.
pub fn explicit_peer_service(raw: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(raw).ok()?;
    [
        "peer.service",
        "peer_service",
        "target_service",
        "downstream_service",
    ]
    .iter()
    .find_map(|key| value.get(*key).and_then(Value::as_str))
    .or_else(|| value.pointer("/peer/service").and_then(Value::as_str))
    .or_else(|| {
        value
            .pointer("/attributes/attributes/peer.service")
            .and_then(Value::as_str)
    })
    .or_else(|| {
        value
            .pointer("/attributes/attributes/peer/service")
            .and_then(Value::as_str)
    })
    .filter(|name| valid_service(name))
    .map(str::to_owned)
}

pub fn parse_event(line: usize, raw: &str) -> ParsedEvent {
    let parsed = serde_json::from_str::<Value>(raw).ok();
    let bgl = parsed.is_none().then(|| parse_bgl_record(raw)).flatten();
    let timestamp = parsed
        .as_ref()
        .and_then(|value| {
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
        })
        .or_else(|| bgl.as_ref().map(|record| record.epoch_seconds));
    let message = parsed
        .as_ref()
        .and_then(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
                .or_else(|| value.get("title").and_then(Value::as_str))
                .or_else(|| value.get("body").and_then(Value::as_str))
                .or_else(|| value.pointer("/body/stringValue").and_then(Value::as_str))
                .or_else(|| value.pointer("/attributes/message").and_then(Value::as_str))
        })
        .or_else(|| bgl.as_ref().map(|record| record.message.as_str()))
        .unwrap_or(raw);
    let spring = parse_spring_boot_message(message);
    let fingerprint_message = spring.map_or(message, |(_, body)| body);
    let http_access = parse_http_access_message(fingerprint_message);
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
                .or_else(|| value.pointer("/attributes/service").and_then(Value::as_str))
                .or_else(|| otel_resource_service(value))
        })
        .filter(|name| valid_service(name))
        .map(str::to_owned)
        .or_else(|| {
            parsed
                .as_ref()?
                .get("projectID")?
                .as_str()
                .filter(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
                .map(|id| format!("sentry-project-{id}"))
        })
        .or_else(|| bgl.as_ref().map(|record| record.service.clone()))
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
                .or_else(|| value.get("status"))
                .or_else(|| value.pointer("/attributes/status"))
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
        .or_else(|| bgl.as_ref().map(|record| record.level.clone()))
        .or_else(|| spring.map(|(level, _)| level.to_owned()))
        .or_else(|| http_access.as_ref().map(|(_, level)| (*level).to_owned()))
        .unwrap_or_default();
    let role = classify_role(&level, fingerprint_message);
    let fingerprint = if let Some((fingerprint, _)) = http_access {
        fingerprint
    } else if parsed.is_some() || bgl.is_some() {
        let mut tokens = fingerprint_message
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
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

/// Spring Boot's timestamp, tracing tuple, thread, and logger identify one
/// occurrence, not the message template. Strip them only for this complete
/// preamble shape; raw source bytes remain untouched.
fn parse_spring_boot_message(message: &str) -> Option<(&str, &str)> {
    let (prefix, body) = message.split_once(" : ")?;
    if body.is_empty() {
        return None;
    }
    let fields = prefix.split_ascii_whitespace().collect::<Vec<_>>();
    let [date, time, level, trace, pid, divider, thread, logger] = fields.as_slice() else {
        return None;
    };
    if !looks_like_date(date)
        || !looks_like_time(time)
        || !matches!(
            *level,
            "FATAL" | "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE"
        )
        || !trace.starts_with('[')
        || !trace.ends_with(']')
        || !trace.contains(',')
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || *divider != "---"
        || !thread.starts_with('[')
        || !thread.ends_with(']')
        || logger.is_empty()
    {
        return None;
    }
    Some((level, body))
}

/// Preserve HTTP method, route, and status while grouping variable request
/// latency and response size in the common seven-field access-log format.
fn parse_http_access_message(message: &str) -> Option<(String, &'static str)> {
    let mut fields = message.split_ascii_whitespace();
    let method = fields.next()?;
    let path = fields.next()?;
    let status = fields.next()?;
    let duration = fields.next()?;
    let unit = fields.next()?;
    let dash = fields.next()?;
    let bytes = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    if !matches!(
        method,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) || !path.starts_with('/')
        || path.len() > 512
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
        || unit != "ms"
        || dash != "-"
        || !bytes.bytes().all(|byte| byte.is_ascii_digit())
        || !duration
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || duration
            .parse::<f64>()
            .ok()
            .is_none_or(|value| !value.is_finite())
    {
        return None;
    }
    let status_number = status.parse::<u16>().ok()?;
    if !(100..=599).contains(&status_number) {
        return None;
    }
    let level = if status_number >= 500 {
        "error"
    } else if status_number >= 400 {
        "warning"
    } else {
        "info"
    };
    Some((
        format!(
            "{} {path} {status} <latency> ms - <bytes>",
            method.to_ascii_lowercase()
        ),
        level,
    ))
}

struct BglRecord {
    epoch_seconds: i64,
    service: String,
    level: String,
    message: String,
}

/// Recognize only the full BGL/LogHub preamble; generic unstructured lines
/// continue through the conservative raw-line parser.
fn parse_bgl_record(raw: &str) -> Option<BglRecord> {
    if !raw.contains(" RAS ") {
        return None;
    }
    let tokens = raw.split_ascii_whitespace().collect::<Vec<_>>();
    if tokens.len() < 10
        || tokens[1].len() != 10
        || !tokens[1].bytes().all(|byte| byte.is_ascii_digit())
        || !looks_like_dotted_date(tokens[2])
        || tokens[3] != tokens[5]
        || !tokens[4].starts_with(&tokens[2].replace('.', "-"))
        || tokens[6] != "RAS"
        || !valid_service(tokens[7])
        || !matches!(
            tokens[8],
            "FATAL" | "ERROR" | "WARN" | "WARNING" | "INFO" | "DEBUG"
        )
    {
        return None;
    }
    Some(BglRecord {
        epoch_seconds: tokens[1].parse().ok()?,
        service: tokens[7].to_ascii_lowercase(),
        level: tokens[8].to_ascii_lowercase(),
        message: tokens[9..].join(" "),
    })
}

fn looks_like_dotted_date(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'.'
        && bytes[7] == b'.'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
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
    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && host.split('.').count() == 4
            && host.split('.').all(|octet| octet.parse::<u8>().is_ok())
        {
            return format!("{host}:<port>");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentry_error_event_uses_title_and_project_without_changing_source_bytes() {
        let raw = r#"{"eventID":"0123456789abcdef0123456789abcdef","projectID":"42","message":"","title":"Checkout TypeError","level":"error"}"#;
        let parsed = parse_event(1, raw);
        assert_eq!(parsed.service, "sentry-project-42");
        assert_eq!(parsed.role, "error");
        assert!(parsed.fingerprint.contains("checkout typeerror"));
        assert_eq!(parsed.raw, raw);
    }

    #[test]
    fn datadog_source_record_groups_by_nested_message_and_explicit_peer() {
        let raw = r#"{"id":"evt-1","type":"log","attributes":{"service":"checkout","status":"error","message":"inventory reservation failed","attributes":{"peer.service":"database"}}}"#;
        let event = parse_event(1, raw);
        assert_eq!(event.service, "checkout");
        assert_eq!(event.role, "error");
        assert_eq!(event.fingerprint, "inventory reservation failed");
        assert_eq!(explicit_peer_service(raw).as_deref(), Some("database"));
        let unrelated = r#"{"id":"evt-2","type":"log","attributes":{"service":"checkout","message":"database is mentioned only in text"}}"#;
        assert_eq!(explicit_peer_service(unrelated), None);
    }

    #[test]
    fn top_level_log_status_controls_role_even_without_error_words() {
        let raw = r#"{"service":"billing","status":"error","message":"downstream call blocked"}"#;
        assert_eq!(parse_event(1, raw).role, "error");
    }

    #[test]
    fn bgl_preamble_does_not_fragment_a_repeated_alert_template() {
        let first = "APPREAD 1117869872 2005.06.04 R04-M1-N4-I:J18-U11 2005-06-04-00.24.32.432192 R04-M1-N4-I:J18-U11 RAS APP FATAL worker failed to read control stream from 172.16.96.116:33569";
        let second = "APPREAD 1117869876 2005.06.04 R27-M1-N4-I:J18-U01 2005-06-04-00.24.36.222560 R27-M1-N4-I:J18-U01 RAS APP FATAL worker failed to read control stream from 172.16.96.116:33370";
        let first = parse_event(1, first);
        let second = parse_event(2, second);
        assert_eq!(first.service, "app");
        assert_eq!(first.role, "critical");
        assert_eq!(first.timestamp, Some(1_117_869_872));
        assert_eq!(first.fingerprint, second.fingerprint);
        assert!(first.raw.contains(":33569"));
        assert!(second.raw.contains(":33370"));
    }

    #[test]
    fn spring_boot_trace_preamble_does_not_fragment_warning_template() {
        let first = r#"{"service":"carts","message":"2024-11-22 02:51:59.404  WARN [carts,37dd0e6423df9dc9,37dd0e6423df9dc9,false] 7 --- [nio-80-exec-17] o.s.web.servlet.PageNotFound : Request method 'POST' not supported"}"#;
        let second = r#"{"service":"carts","message":"2024-11-22 05:44:56.787  WARN [carts,4f69084c4e2a939e,4f69084c4e2a939e,false] 7 --- [nio-80-exec-1] o.s.web.servlet.PageNotFound : Request method 'POST' not supported"}"#;
        let a = parse_event(1, first);
        let b = parse_event(2, second);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.role, "warning");
        assert_eq!(a.raw, first);
        let different = first.replace("'POST'", "'GET'");
        assert_ne!(a.fingerprint, parse_event(3, &different).fingerprint);
        assert!(
            parse_spring_boot_message(
                "2024-11-22 02:51:59 WARN [broken] x --- [thread] logger : failure"
            )
            .is_none()
        );
    }

    #[test]
    fn http_access_latency_and_bytes_do_not_fragment_status_and_route() {
        let first = parse_event(
            1,
            r#"{"service":"front-end","message":"POST /cart 500 72.969 ms - 70"}"#,
        );
        let second = parse_event(
            2,
            r#"{"service":"front-end","message":"POST /cart 500 54.305 ms - 82"}"#,
        );
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.role, "error");
        assert_ne!(
            first.fingerprint,
            parse_event(
                3,
                r#"{"service":"front-end","message":"POST /cart 200 54.305 ms - 82"}"#
            )
            .fingerprint
        );
        assert_ne!(
            first.fingerprint,
            parse_event(
                4,
                r#"{"service":"front-end","message":"POST /checkout 500 54.305 ms - 82"}"#
            )
            .fingerprint
        );
    }
}
