//! Project-scoped Sentry error events. Structured Explore logs are not an export API.

use std::io::Read as _;
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, LINK};
use serde_json::{Value, value::RawValue};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    HistoryPageSourceV1, HistoryPageV1, HistoryPartitionV1, HistoryRecordV1, HistorySyncErrorV1,
};

const PAGE_LIMIT: usize = 10; // Sentry caps full=1 pages at ten events.
const MAX_RESPONSE_BYTES: u64 = 12 * 1024 * 1024;

pub struct SentryErrorHistorySourceV1 {
    client: Client,
    endpoint: String,
    organization: String,
    project: String,
    expected_project_id: Option<String>,
    token: Zeroizing<String>,
}

impl SentryErrorHistorySourceV1 {
    pub fn connect(
        region: &str,
        organization: &str,
        project: &str,
        token: String,
    ) -> Result<Self, HistorySyncErrorV1> {
        let endpoint = match region {
            "global" => "https://sentry.io",
            "us" => "https://us.sentry.io",
            "de" => "https://de.sentry.io",
            _ => return Err(HistorySyncErrorV1::InvalidConfiguration),
        };
        Self::from_endpoint(endpoint, organization, project, token)
    }

    fn from_endpoint(
        endpoint: &str,
        organization: &str,
        project: &str,
        token: String,
    ) -> Result<Self, HistorySyncErrorV1> {
        if !valid_slug(organization) || !valid_slug(project) || token.is_empty() {
            return Err(HistorySyncErrorV1::InvalidConfiguration);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?;
        Ok(Self {
            client,
            endpoint: endpoint.to_owned(),
            organization: organization.to_owned(),
            project: project.to_owned(),
            expected_project_id: None,
            token: Zeroizing::new(token),
        })
    }

    pub fn bind_project_id(&mut self, id: &str) -> Result<(), HistorySyncErrorV1> {
        if id.is_empty() || id.len() > 32 || !id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(HistorySyncErrorV1::InvalidConfiguration);
        }
        self.expected_project_id = Some(id.to_owned());
        Ok(())
    }

    fn url(&self) -> String {
        format!(
            "{}/api/0/projects/{}/{}/",
            self.endpoint, self.organization, self.project
        )
    }

    fn bearer(&self) -> Result<HeaderValue, HistorySyncErrorV1> {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", self.token.as_str()))
            .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?;
        value.set_sensitive(true);
        Ok(value)
    }

    /// A stable project ID prevents a reused slug from adopting an old corpus.
    /// `hasAccess` must be affirmative; an omitted field is not proof.
    pub fn current_project_id(&self) -> Result<String, HistorySyncErrorV1> {
        let response = self
            .client
            .get(self.url())
            .header(AUTHORIZATION, self.bearer()?)
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| HistorySyncErrorV1::Network)?;
        let bytes = checked_body(response, MAX_RESPONSE_BYTES)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or(HistorySyncErrorV1::InvalidPage)?;
        if value.get("hasAccess") != Some(&Value::Bool(true))
            || value.get("slug").and_then(Value::as_str) != Some(self.project.as_str())
            || value.pointer("/organization/slug").and_then(Value::as_str)
                != Some(self.organization.as_str())
        {
            return Err(HistorySyncErrorV1::AccessScopeUnverifiable);
        }
        Ok(id.to_owned())
    }
}

impl HistoryPageSourceV1 for SentryErrorHistorySourceV1 {
    fn fetch_page(
        &mut self,
        partition: HistoryPartitionV1,
        next_token: Option<&[u8]>,
    ) -> Result<HistoryPageV1, HistorySyncErrorV1> {
        if partition.start_millis < 0 || partition.start_millis >= partition.end_millis {
            return Err(HistorySyncErrorV1::InvalidConfiguration);
        }
        let cursor = next_token
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|_| HistorySyncErrorV1::InvalidPage)?;
        if cursor.is_some_and(|cursor| cursor.is_empty() || cursor.len() > 512) {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        let start = format_millis(partition.start_millis)?;
        let end = format_millis(partition.end_millis)?;
        let mut url = Url::parse(&format!("{}events/", self.url()))
            .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("start", &start);
            query.append_pair("end", &end);
            query.append_pair("full", "1");
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, self.bearer()?)
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| HistorySyncErrorV1::Network)?;
        let next = response
            .headers()
            .get(LINK)
            .ok_or(HistorySyncErrorV1::InvalidPage)?
            .to_str()
            .map_err(|_| HistorySyncErrorV1::InvalidPage)
            .and_then(parse_next_cursor)?;
        let bytes = checked_body(response, MAX_RESPONSE_BYTES)?;
        parse_error_page(&bytes, partition, next, self.expected_project_id.as_deref())
    }
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn format_millis(millis: i64) -> Result<String, HistorySyncErrorV1> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?
        .format(&Rfc3339)
        .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)
}

fn checked_body(
    response: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, HistorySyncErrorV1> {
    match response.status().as_u16() {
        200 => {}
        401 => return Err(HistorySyncErrorV1::AuthenticationChanged),
        403 | 404 => return Err(HistorySyncErrorV1::PermissionDenied),
        429 => return Err(HistorySyncErrorV1::Throttled),
        _ => return Err(HistorySyncErrorV1::Provider),
    }
    let mut bytes = Vec::new();
    response
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HistorySyncErrorV1::Network)?;
    if bytes.len() as u64 > max_bytes {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    Ok(bytes)
}

fn parse_next_cursor(link: &str) -> Result<Option<String>, HistorySyncErrorV1> {
    let mut next = None;
    let mut found = false;
    for entry in link.split(',') {
        if !entry.contains("rel=\"next\"") {
            continue;
        }
        if found {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        found = true;
        if entry.contains("results=\"false\"") {
            continue;
        }
        if !entry.contains("results=\"true\"") {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        let encoded = entry
            .trim()
            .strip_prefix('<')
            .and_then(|part| part.split_once('>'))
            .map(|(url, _)| url)
            .ok_or(HistorySyncErrorV1::InvalidPage)?;
        let url = Url::parse(encoded).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
        let cursor = url
            .query_pairs()
            .find(|(key, _)| key == "cursor")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(HistorySyncErrorV1::InvalidPage)?;
        next = Some(cursor);
    }
    if found {
        Ok(next)
    } else {
        Err(HistorySyncErrorV1::InvalidPage)
    }
}

fn parse_error_page(
    bytes: &[u8],
    partition: HistoryPartitionV1,
    next: Option<String>,
    expected_project_id: Option<&str>,
) -> Result<HistoryPageV1, HistorySyncErrorV1> {
    let rows: Vec<Box<RawValue>> =
        serde_json::from_slice(bytes).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
    if rows.len() > PAGE_LIMIT {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let mut records = Vec::with_capacity(rows.len());
    for raw in rows {
        let value: Value =
            serde_json::from_str(raw.get()).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
        let id = value
            .get("eventID")
            .and_then(Value::as_str)
            .filter(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(HistorySyncErrorV1::InvalidPage)?;
        if expected_project_id.is_some_and(|expected| {
            value.get("projectID").and_then(Value::as_str) != Some(expected)
        }) {
            return Err(HistorySyncErrorV1::AccessScopeUnverifiable);
        }
        let date = value
            .get("dateCreated")
            .and_then(Value::as_str)
            .ok_or(HistorySyncErrorV1::InvalidPage)?;
        let timestamp =
            OffsetDateTime::parse(date, &Rfc3339).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
        let millis = i64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| HistorySyncErrorV1::InvalidPage)?;
        if millis < partition.start_millis || millis > partition.end_millis {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        records.push(HistoryRecordV1 {
            native_id: id.as_bytes().to_vec(),
            event_timestamp_millis: millis,
            bytes: raw.get().as_bytes().to_vec(),
        });
    }
    Ok(HistoryPageV1 {
        records,
        next_token: next.map(String::into_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn page_preserves_exact_event_and_rejects_project_mismatch() {
        let raw = r#"[{"eventID":"0123456789abcdef0123456789abcdef", "dateCreated":"2024-01-01T00:00:01Z", "message":"boom"}]"#;
        let partition = HistoryPartitionV1 {
            start_millis: 0,
            end_millis: 2_000_000_000_000,
        };
        let page = parse_error_page(raw.as_bytes(), partition, None, None).unwrap();
        assert_eq!(page.records[0].bytes, br#"{"eventID":"0123456789abcdef0123456789abcdef", "dateCreated":"2024-01-01T00:00:01Z", "message":"boom"}"#);
        assert_eq!(
            page.records[0].native_id,
            b"0123456789abcdef0123456789abcdef"
        );
        let full = format!(
            "[{}]",
            [raw.trim_start_matches('[').trim_end_matches(']'); 10].join(",")
        );
        assert!(parse_error_page(full.as_bytes(), partition, None, Some("42")).is_err());
        assert!(parse_error_page(full.as_bytes(), partition, None, None).is_ok());
    }

    #[test]
    fn sentry_link_cursor_requires_positive_next_page() {
        let link = r#"<https://sentry.io/api/0/projects/o/p/events/?cursor=0%3A10%3A0>; rel="next"; results="true""#;
        assert_eq!(parse_next_cursor(link).unwrap().as_deref(), Some("0:10:0"));
        assert_eq!(
            parse_next_cursor(link.replace("true", "false").as_str()).unwrap(),
            None
        );
        assert!(parse_next_cursor(r#"<https://sentry.io/>; rel="next"; results="true""#).is_err());
        assert!(parse_next_cursor(&format!("{link}, {}", link.replace("true", "false"))).is_err());
    }

    #[test]
    fn project_identity_and_full_error_event_page_use_read_only_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for expected in [
                "/api/0/projects/acme/shop/ ",
                "/api/0/projects/acme/shop/events/?",
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("GET "));
                assert!(request.contains(expected));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer test-token")
                );
                if expected.contains("events") {
                    assert!(request.contains("full=1"));
                }
                let body = if expected.contains("events") {
                    r#"[{"eventID":"0123456789abcdef0123456789abcdef","dateCreated":"2024-01-01T00:00:01Z","projectID":"42","title":"Checkout failure","message":""}]"#
                } else {
                    r#"{"id":"42","slug":"shop","hasAccess":true,"organization":{"slug":"acme"}}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLink: <http://localhost/?cursor=0%3A0%3A0>; rel=\"next\"; results=\"false\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let mut source = SentryErrorHistorySourceV1::from_endpoint(
            &endpoint,
            "acme",
            "shop",
            "test-token".to_owned(),
        )
        .unwrap();
        assert_eq!(source.current_project_id().unwrap(), "42");
        source.bind_project_id("42").unwrap();
        let page = source
            .fetch_page(
                HistoryPartitionV1 {
                    start_millis: 0,
                    end_millis: 2_000_000_000_000,
                },
                None,
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(
            page.records[0].native_id,
            b"0123456789abcdef0123456789abcdef"
        );
        assert!(page.next_token.is_none());
        server.join().unwrap();
    }
}
