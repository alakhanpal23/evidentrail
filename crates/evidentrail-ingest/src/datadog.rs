//! Datadog Logs Search full-history pages for one storage tier.
//! Internal time partitions come from the shared synchronizer, never a task.

use std::io::Read as _;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    HistoryPageSourceV1, HistoryPageV1, HistoryPartitionV1, HistoryRecordV1, HistorySyncErrorV1,
};

const PAGE_LIMIT: usize = 100;
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_IDENTITY_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatadogSiteV1 {
    Us1,
    Us3,
    Us5,
    Eu1,
    Ap1,
    Ap2,
    Uk1,
    Us1Fed,
    Us2Fed,
}

impl DatadogSiteV1 {
    const fn endpoint(self) -> &'static str {
        match self {
            Self::Us1 => "https://api.datadoghq.com",
            Self::Us3 => "https://api.us3.datadoghq.com",
            Self::Us5 => "https://api.us5.datadoghq.com",
            Self::Eu1 => "https://api.datadoghq.eu",
            Self::Ap1 => "https://api.ap1.datadoghq.com",
            Self::Ap2 => "https://api.ap2.datadoghq.com",
            Self::Uk1 => "https://api.uk1.datadoghq.com",
            Self::Us1Fed => "https://api.ddog-gov.com",
            Self::Us2Fed => "https://api.us2.ddog-gov.com",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatadogStorageTierV1 {
    Indexes,
    OnlineArchives,
    Flex,
}

impl DatadogStorageTierV1 {
    const fn api_value(self) -> &'static str {
        match self {
            Self::Indexes => "indexes",
            Self::OnlineArchives => "online-archives",
            Self::Flex => "flex",
        }
    }
}

pub struct DatadogHistorySourceV1 {
    client: Client,
    endpoint: String,
    tier: DatadogStorageTierV1,
    api_key: Zeroizing<String>,
    application_key: Zeroizing<String>,
}

impl DatadogHistorySourceV1 {
    /// One source covers one tier across all indexes. The caller must run each
    /// authorized tier and report tiers that are inaccessible or unavailable.
    pub fn connect(
        site: DatadogSiteV1,
        tier: DatadogStorageTierV1,
        api_key: String,
        application_key: String,
    ) -> Result<Self, HistorySyncErrorV1> {
        Self::from_endpoint(site.endpoint().to_owned(), tier, api_key, application_key)
    }

    fn from_endpoint(
        endpoint: String,
        tier: DatadogStorageTierV1,
        api_key: String,
        application_key: String,
    ) -> Result<Self, HistorySyncErrorV1> {
        if api_key.is_empty() || application_key.is_empty() {
            return Err(HistorySyncErrorV1::InvalidConfiguration);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?;
        Ok(Self {
            client,
            endpoint,
            tier,
            api_key: Zeroizing::new(api_key),
            application_key: Zeroizing::new(application_key),
        })
    }

    fn credential_headers(&self) -> Result<(HeaderValue, HeaderValue), HistorySyncErrorV1> {
        let mut api_header = HeaderValue::from_str(&self.api_key)
            .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?;
        let mut app_header = HeaderValue::from_str(&self.application_key)
            .map_err(|_| HistorySyncErrorV1::InvalidConfiguration)?;
        api_header.set_sensitive(true);
        app_header.set_sensitive(true);
        Ok((api_header, app_header))
    }

    /// Verify the organization associated with these credentials. This must
    /// be checked against the immutable connection descriptor before pages
    /// are accepted into a source corpus.
    pub fn current_org_id(&self) -> Result<String, HistorySyncErrorV1> {
        let (api_header, app_header) = self.credential_headers()?;
        let response = self
            .client
            .get(format!("{}/api/v2/current_user", self.endpoint))
            .header("DD-API-KEY", api_header)
            .header("DD-APPLICATION-KEY", app_header)
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| HistorySyncErrorV1::Network)?;
        match response.status().as_u16() {
            200 => {}
            401 => return Err(HistorySyncErrorV1::AuthenticationChanged),
            403 => return Err(HistorySyncErrorV1::PermissionDenied),
            429 => return Err(HistorySyncErrorV1::Throttled),
            _ => return Err(HistorySyncErrorV1::Provider),
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(MAX_IDENTITY_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| HistorySyncErrorV1::Network)?;
        if bytes.len() as u64 > MAX_IDENTITY_RESPONSE_BYTES {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        parse_current_org_id(&bytes)
    }
}

#[derive(Deserialize)]
struct CurrentUserResponse {
    data: CurrentUserData,
}

#[derive(Deserialize)]
struct CurrentUserData {
    relationships: CurrentUserRelationships,
}

#[derive(Deserialize)]
struct CurrentUserRelationships {
    org: CurrentUserOrg,
}

#[derive(Deserialize)]
struct CurrentUserOrg {
    data: CurrentOrgIdentity,
}

#[derive(Deserialize)]
struct CurrentOrgIdentity {
    #[serde(rename = "type")]
    resource_type: String,
    id: String,
}

fn parse_current_org_id(bytes: &[u8]) -> Result<String, HistorySyncErrorV1> {
    let body: CurrentUserResponse =
        serde_json::from_slice(bytes).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
    if body.data.relationships.org.data.resource_type != "orgs" {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let id = body.data.relationships.org.data.id;
    if id.len() != 36
        || !id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    Ok(id.to_ascii_lowercase())
}

impl HistoryPageSourceV1 for DatadogHistorySourceV1 {
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
        if cursor.is_some_and(str::is_empty) {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        let (api_header, app_header) = self.credential_headers()?;
        let body = serde_json::json!({
            "filter": {
                "from": partition.start_millis.to_string(),
                "to": partition.end_millis.to_string(),
                "indexes": ["*"],
                "query": "*",
                "storage_tier": self.tier.api_value(),
            },
            "page": { "limit": PAGE_LIMIT, "cursor": cursor },
            "sort": "timestamp"
        });
        let response = self
            .client
            .post(format!("{}/api/v2/logs/events/search", self.endpoint))
            .header("DD-API-KEY", api_header)
            .header("DD-APPLICATION-KEY", app_header)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .map_err(|_| HistorySyncErrorV1::Network)?;
        match response.status().as_u16() {
            200 => {}
            401 => return Err(HistorySyncErrorV1::AuthenticationChanged),
            403 => return Err(HistorySyncErrorV1::PermissionDenied),
            429 => return Err(HistorySyncErrorV1::Throttled),
            _ => return Err(HistorySyncErrorV1::Provider),
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| HistorySyncErrorV1::Network)?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        parse_page(&bytes, partition)
    }
}

#[derive(Deserialize)]
struct SearchResponse {
    data: Option<Vec<Box<RawValue>>>,
    meta: Option<SearchMeta>,
    links: Option<SearchLinks>,
}

#[derive(Deserialize)]
struct SearchMeta {
    page: Option<SearchPage>,
    status: Option<String>,
    warnings: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct SearchPage {
    after: Option<String>,
}

#[derive(Deserialize)]
struct SearchLinks {
    next: Option<String>,
}

fn parse_page(
    bytes: &[u8],
    partition: HistoryPartitionV1,
) -> Result<HistoryPageV1, HistorySyncErrorV1> {
    let response: SearchResponse =
        serde_json::from_slice(bytes).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
    let meta = response.meta.ok_or(HistorySyncErrorV1::InvalidPage)?;
    if meta
        .status
        .as_deref()
        .is_some_and(|status| status != "done")
        || meta.warnings.is_some_and(|warnings| !warnings.is_empty())
    {
        return Err(HistorySyncErrorV1::Provider);
    }
    let cursor = meta.page.and_then(|page| page.after);
    if cursor.as_deref() == Some("")
        || (response.links.and_then(|links| links.next).is_some() && cursor.is_none())
    {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let data = response.data.ok_or(HistorySyncErrorV1::InvalidPage)?;
    if data.len() > PAGE_LIMIT {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let mut records = Vec::with_capacity(data.len());
    for raw in data {
        let event: Value =
            serde_json::from_str(raw.get()).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
        let id = event
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or(HistorySyncErrorV1::InvalidPage)?;
        if event.get("type").and_then(Value::as_str) != Some("log")
            || event
                .pointer("/attributes/message")
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        let timestamp = event
            .pointer("/attributes/timestamp")
            .and_then(Value::as_str)
            .ok_or(HistorySyncErrorV1::InvalidPage)?;
        let timestamp = OffsetDateTime::parse(timestamp, &Rfc3339)
            .map_err(|_| HistorySyncErrorV1::InvalidPage)?;
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
        next_token: cursor.map(String::into_bytes),
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    const PARTITION: HistoryPartitionV1 = HistoryPartitionV1 {
        start_millis: 0,
        end_millis: 10,
    };

    #[test]
    fn current_user_org_identity_is_required_and_normalized() {
        let response = br#"{"data":{"relationships":{"org":{"data":{"type":"orgs","id":"A1234567-1234-1234-1234-123456789ABC"}}}}}"#;
        assert_eq!(
            parse_current_org_id(response).unwrap(),
            "a1234567-1234-1234-1234-123456789abc"
        );
        for invalid in [
            br#"{"data":{"relationships":{"org":{"data":{"type":"users","id":"a1234567-1234-1234-1234-123456789abc"}}}}}"#.as_slice(),
            br#"{"data":{"relationships":{"org":{"data":{"type":"orgs","id":"wrong"}}}}}"#.as_slice(),
            br#"{"data":{}}"#.as_slice(),
        ] {
            assert_eq!(parse_current_org_id(invalid), Err(HistorySyncErrorV1::InvalidPage));
        }
    }

    #[test]
    fn current_user_request_binds_credentials_to_org() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let count = socket.read(&mut chunk).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(headers.starts_with("get /api/v2/current_user http/1.1"));
            assert!(headers.contains("dd-api-key: api-test"));
            assert!(headers.contains("dd-application-key: app-test"));
            let body = r#"{"data":{"relationships":{"org":{"data":{"type":"orgs","id":"a1234567-1234-1234-1234-123456789abc"}}}}}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            socket.flush().unwrap();
        });
        let source = DatadogHistorySourceV1::from_endpoint(
            endpoint,
            DatadogStorageTierV1::Indexes,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        assert_eq!(
            source.current_org_id().unwrap(),
            "a1234567-1234-1234-1234-123456789abc"
        );
        server.join().unwrap();
    }

    #[test]
    fn source_record_is_exact_api_json_and_partial_results_fail_closed() {
        let raw = r#"{"id":"id-1", "type":"log", "attributes":{"message":"original line","timestamp":"1970-01-01T00:00:00.005Z","service":"checkout"}}"#;
        let body = format!(r#"{{"data":[{raw}],"meta":{{"status":"done"}}}}"#);
        let page = parse_page(body.as_bytes(), PARTITION).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].native_id, b"id-1");
        assert_eq!(page.records[0].event_timestamp_millis, 5);
        assert_eq!(page.records[0].bytes, raw.as_bytes());
        assert_eq!(
            parse_page(
                br#"{"data":[],"meta":{"status":"done","warnings":[{"code":"partial"}]}}"#,
                PARTITION
            ),
            Err(HistorySyncErrorV1::Provider)
        );
        assert_eq!(
            parse_page(br#"{"data":[],"meta":{"status":"timeout"}}"#, PARTITION),
            Err(HistorySyncErrorV1::Provider)
        );
        assert_eq!(
            parse_page(
                br#"{"data":[],"meta":{"status":"done"},"links":{"next":"https://example"}}"#,
                PARTITION
            ),
            Err(HistorySyncErrorV1::InvalidPage)
        );
    }

    #[test]
    fn http_search_uses_all_indexes_and_follows_empty_page_cursor() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut bodies = Vec::new();
            for index in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut chunk = [0u8; 4096];
                    let count = socket.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&chunk[..count]);
                    if let Some(position) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                assert!(headers.contains("dd-api-key: api-test"));
                assert!(headers.contains("dd-application-key: app-test"));
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse::<usize>()
                    .unwrap();
                while request.len() - header_end < length {
                    let mut chunk = [0u8; 4096];
                    let count = socket.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&chunk[..count]);
                }
                bodies.push(
                    serde_json::from_slice::<Value>(&request[header_end..header_end + length])
                        .unwrap(),
                );
                let body = if index == 0 {
                    r#"{"data":[],"meta":{"status":"done","page":{"after":"next"}}}"#
                } else {
                    r#"{"data":[{"id":"id-1","type":"log","attributes":{"timestamp":"1970-01-01T00:00:00.005Z","message":"line"}}],"meta":{"status":"done"}}"#
                };
                write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
                socket.flush().unwrap();
            }
            bodies
        });
        let mut source = DatadogHistorySourceV1::from_endpoint(
            endpoint,
            DatadogStorageTierV1::Flex,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        let first = source.fetch_page(PARTITION, None).unwrap();
        assert!(first.records.is_empty());
        assert_eq!(first.next_token.as_deref(), Some(b"next".as_slice()));
        let second = source
            .fetch_page(PARTITION, first.next_token.as_deref())
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(second.next_token.is_none());
        let bodies = server.join().unwrap();
        assert_eq!(bodies[0]["filter"]["indexes"], serde_json::json!(["*"]));
        assert_eq!(bodies[0]["filter"]["query"], "*");
        assert_eq!(bodies[0]["filter"]["storage_tier"], "flex");
        assert_eq!(bodies[0]["filter"]["from"], "0");
        assert_eq!(bodies[0]["filter"]["to"], "10");
        assert_eq!(bodies[1]["page"]["cursor"], "next");
    }
}
