//! Datadog Logs Search full-history pages for one storage tier.
//! Internal time partitions come from the shared synchronizer, never a task.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::thread;
use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    HistoryPageSourceV1, HistoryPageV1, HistoryPartitionV1, HistoryRecordV1, HistorySyncErrorV1,
};

const PAGE_LIMIT: usize = 100;
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_IDENTITY_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_RATE_LIMIT_RETRIES: usize = 2;
const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(2);

fn send_with_rate_limit_retry(
    mut send: impl FnMut() -> Result<Response, reqwest::Error>,
) -> Result<Response, HistorySyncErrorV1> {
    for attempt in 0..=MAX_RATE_LIMIT_RETRIES {
        let response = send().map_err(|_| HistorySyncErrorV1::Network)?;
        if response.status().as_u16() != 429 {
            return Ok(response);
        }
        if attempt == MAX_RATE_LIMIT_RETRIES {
            return Err(HistorySyncErrorV1::Throttled);
        }
        let wait = response
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_millis(250 * (attempt as u64 + 1)));
        if wait > MAX_RATE_LIMIT_WAIT {
            return Err(HistorySyncErrorV1::Throttled);
        }
        drop(response);
        thread::sleep(wait);
    }
    Err(HistorySyncErrorV1::Throttled)
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatadogAccessIdentityV1 {
    pub org_id: String,
    pub user_id: String,
    pub role_ids: Vec<String>,
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
    pub fn current_access_identity(&self) -> Result<DatadogAccessIdentityV1, HistorySyncErrorV1> {
        let (api_header, app_header) = self.credential_headers()?;
        let response = send_with_rate_limit_retry(|| {
            self.client
                .get(format!("{}/api/v2/current_user", self.endpoint))
                .header("DD-API-KEY", api_header.clone())
                .header("DD-APPLICATION-KEY", app_header.clone())
                .header(ACCEPT, "application/json")
                .send()
        })?;
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
        parse_current_access_identity(&bytes)
    }

    pub fn current_org_id(&self) -> Result<String, HistorySyncErrorV1> {
        self.current_access_identity()
            .map(|identity| identity.org_id)
    }

    /// Fingerprint the effective restriction queries for this user. A cached
    /// corpus must not be served after these rules change. This endpoint
    /// requires Datadog's read-only `logs_read_config` permission.
    pub fn current_restriction_query_digest(
        &self,
        user_id: &str,
    ) -> Result<[u8; 32], HistorySyncErrorV1> {
        if !valid_uuid(user_id) {
            return Err(HistorySyncErrorV1::InvalidConfiguration);
        }
        let (api_header, app_header) = self.credential_headers()?;
        let response = send_with_rate_limit_retry(|| {
            self.client
                .get(format!(
                    "{}/api/v2/logs/config/restriction_queries/user/{user_id}",
                    self.endpoint
                ))
                .header("DD-API-KEY", api_header.clone())
                .header("DD-APPLICATION-KEY", app_header.clone())
                .header(ACCEPT, "application/json")
                .send()
        })?;
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
        parse_restriction_query_digest(&bytes)
    }

    /// Bind cached logs to the effective restriction queries and the user's
    /// effective global permissions. Scoped index grants cannot currently be
    /// fingerprinted, so refuse the indexed tier when they are present.
    /// Data Access Control policies still require separate checks.
    pub fn current_access_scope_digest(
        &self,
        identity: &DatadogAccessIdentityV1,
    ) -> Result<[u8; 32], HistorySyncErrorV1> {
        if identity.role_ids.is_empty()
            || identity.role_ids.len() > 128
            || identity.role_ids.iter().any(|id| !valid_uuid(id))
            || identity.role_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(HistorySyncErrorV1::InvalidConfiguration);
        }
        let restrictions = self.current_restriction_query_digest(&identity.user_id)?;
        let (permissions, has_log_read, unrestricted_index_read) =
            self.current_user_permissions_digest(&identity.user_id)?;
        if !has_log_read {
            return Err(HistorySyncErrorV1::PermissionDenied);
        }
        if self.tier == DatadogStorageTierV1::Indexes && !unrestricted_index_read {
            return Err(HistorySyncErrorV1::AccessScopeUnverifiable);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"evidentrail/datadog-access-scope/v2\0");
        hasher.update(restrictions);
        hasher.update(permissions);
        for role_id in &identity.role_ids {
            hasher.update(role_id.as_bytes());
        }
        Ok(hasher.finalize().into())
    }

    fn current_user_permissions_digest(
        &self,
        user_id: &str,
    ) -> Result<([u8; 32], bool, bool), HistorySyncErrorV1> {
        if !valid_uuid(user_id) {
            return Err(HistorySyncErrorV1::InvalidConfiguration);
        }
        let (api_header, app_header) = self.credential_headers()?;
        let response = send_with_rate_limit_retry(|| {
            self.client
                .get(format!(
                    "{}/api/v2/users/{user_id}/permissions",
                    self.endpoint
                ))
                .header("DD-API-KEY", api_header.clone())
                .header("DD-APPLICATION-KEY", app_header.clone())
                .header(ACCEPT, "application/json")
                .send()
        })?;
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
        parse_user_permissions_digest(&bytes)
    }
}

#[derive(Deserialize)]
struct UserPermissionsResponse {
    data: Vec<UserPermissionData>,
}

#[derive(Deserialize)]
struct UserPermissionData {
    #[serde(rename = "type")]
    resource_type: String,
    id: String,
    attributes: UserPermissionAttributes,
}

#[derive(Deserialize)]
struct UserPermissionAttributes {
    name: Option<String>,
    restricted: bool,
}

fn parse_user_permissions_digest(
    bytes: &[u8],
) -> Result<([u8; 32], bool, bool), HistorySyncErrorV1> {
    let response: UserPermissionsResponse =
        serde_json::from_slice(bytes).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
    if response.data.len() > 10_000 {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let mut permissions = Vec::with_capacity(response.data.len());
    for item in response.data {
        if item.resource_type != "permissions"
            || item.id.is_empty()
            || item.id.len() > 128
            || item
                .attributes
                .name
                .as_ref()
                .is_none_or(|name| name.is_empty() || name.len() > 256)
        {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        permissions.push((
            item.id,
            item.attributes.name.expect("checked"),
            item.attributes.restricted,
        ));
    }
    permissions.sort();
    if permissions.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let has_log_read = permissions
        .iter()
        .any(|(_, name, _)| name == "logs_read_data");
    let unrestricted_index_read = permissions
        .iter()
        .any(|(_, name, restricted)| name == "logs_read_index_data" && !*restricted);
    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail/datadog-user-permissions/v1\0");
    for (id, name, restricted) in permissions {
        for value in [&id, &name] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.update([u8::from(restricted)]);
    }
    Ok((
        hasher.finalize().into(),
        has_log_read,
        unrestricted_index_read,
    ))
}

#[derive(Deserialize)]
struct RestrictionQueryResponse {
    data: Vec<RestrictionQueryData>,
}

#[derive(Deserialize)]
struct RestrictionQueryData {
    #[serde(rename = "type")]
    resource_type: String,
    id: String,
    attributes: RestrictionQueryAttributes,
}

#[derive(Deserialize)]
struct RestrictionQueryAttributes {
    restriction_query: String,
}

fn parse_restriction_query_digest(bytes: &[u8]) -> Result<[u8; 32], HistorySyncErrorV1> {
    let response: RestrictionQueryResponse =
        serde_json::from_slice(bytes).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
    if response.data.len() > 10_000 {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let mut rules = Vec::with_capacity(response.data.len());
    for item in response.data {
        if item.resource_type != "logs_restriction_queries"
            || !valid_uuid(&item.id)
            || item.attributes.restriction_query.len() > 8192
        {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        rules.push((
            item.id.to_ascii_lowercase(),
            item.attributes.restriction_query,
        ));
    }
    rules.sort();
    if rules.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"evidentrail/datadog-restriction-queries/v1\0");
    for (id, query) in rules {
        hasher.update((id.len() as u64).to_be_bytes());
        hasher.update(id.as_bytes());
        hasher.update((query.len() as u64).to_be_bytes());
        hasher.update(query.as_bytes());
    }
    Ok(hasher.finalize().into())
}

#[derive(Deserialize)]
struct CurrentUserResponse {
    data: CurrentUserData,
}

#[derive(Deserialize)]
struct CurrentUserData {
    #[serde(rename = "type")]
    resource_type: String,
    id: String,
    relationships: CurrentUserRelationships,
}

#[derive(Deserialize)]
struct CurrentUserRelationships {
    org: CurrentUserOrg,
    roles: CurrentUserRoles,
}

#[derive(Deserialize)]
struct CurrentUserRoles {
    data: Vec<CurrentRoleIdentity>,
}

#[derive(Deserialize)]
struct CurrentRoleIdentity {
    #[serde(rename = "type")]
    resource_type: String,
    id: String,
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

fn valid_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn parse_current_access_identity(
    bytes: &[u8],
) -> Result<DatadogAccessIdentityV1, HistorySyncErrorV1> {
    let body: CurrentUserResponse =
        serde_json::from_slice(bytes).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
    if body.data.resource_type != "users"
        || !valid_uuid(&body.data.id)
        || body.data.relationships.org.data.resource_type != "orgs"
    {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let org_id = body.data.relationships.org.data.id;
    if !valid_uuid(&org_id) {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let roles = body.data.relationships.roles.data;
    if roles.is_empty()
        || roles.len() > 128
        || roles
            .iter()
            .any(|role| role.resource_type != "roles" || !valid_uuid(&role.id))
    {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let role_ids = roles
        .into_iter()
        .map(|role| role.id.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    Ok(DatadogAccessIdentityV1 {
        org_id: org_id.to_ascii_lowercase(),
        user_id: body.data.id.to_ascii_lowercase(),
        role_ids: role_ids.into_iter().collect(),
    })
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
        let response = send_with_rate_limit_retry(|| {
            self.client
                .post(format!("{}/api/v2/logs/events/search", self.endpoint))
                .header("DD-API-KEY", api_header.clone())
                .header("DD-APPLICATION-KEY", app_header.clone())
                .header(ACCEPT, "application/json")
                .header(CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
        })?;
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
    #[serde(default, deserialize_with = "present_raw_data")]
    data: Option<Box<RawValue>>,
    meta: Option<SearchMeta>,
    links: Option<SearchLinks>,
}

fn present_raw_data<'de, D>(deserializer: D) -> Result<Option<Box<RawValue>>, D::Error>
where
    D: Deserializer<'de>,
{
    // Preserve an explicit null, which Datadog documents as terminal, while
    // a missing field defaults to None and remains invalid.
    Box::<RawValue>::deserialize(deserializer).map(Some)
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
    let has_next_link = response.links.and_then(|links| links.next).is_some();
    if cursor.as_deref() == Some("") || (has_next_link && cursor.is_none()) {
        return Err(HistorySyncErrorV1::InvalidPage);
    }
    let data = response.data.ok_or(HistorySyncErrorV1::InvalidPage)?;
    if data.get() == "null" {
        if has_next_link {
            return Err(HistorySyncErrorV1::InvalidPage);
        }
        return Ok(HistoryPageV1 {
            records: Vec::new(),
            next_token: None,
        });
    }
    let data: Vec<Box<RawValue>> =
        serde_json::from_str(data.get()).map_err(|_| HistorySyncErrorV1::InvalidPage)?;
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
            || !event.get("attributes").is_some_and(Value::is_object)
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
    fn current_user_access_identity_is_required_and_normalized() {
        let response = br#"{"data":{"type":"users","id":"B1234567-1234-1234-1234-123456789ABC","relationships":{"org":{"data":{"type":"orgs","id":"A1234567-1234-1234-1234-123456789ABC"}},"roles":{"data":[{"type":"roles","id":"C1234567-1234-1234-1234-123456789ABC"}]}}}}"#;
        assert_eq!(
            parse_current_access_identity(response).unwrap(),
            DatadogAccessIdentityV1 {
                org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
                user_id: "b1234567-1234-1234-1234-123456789abc".to_owned(),
                role_ids: vec!["c1234567-1234-1234-1234-123456789abc".to_owned()],
            }
        );
        for invalid in [
            br#"{"data":{"type":"users","id":"b1234567-1234-1234-1234-123456789abc","relationships":{"org":{"data":{"type":"users","id":"a1234567-1234-1234-1234-123456789abc"}},"roles":{"data":[]}}}}"#.as_slice(),
            br#"{"data":{"type":"users","id":"b1234567-1234-1234-1234-123456789abc","relationships":{"org":{"data":{"type":"orgs","id":"wrong"}},"roles":{"data":[]}}}}"#.as_slice(),
            br#"{"data":{}}"#.as_slice(),
        ] {
            assert_eq!(parse_current_access_identity(invalid), Err(HistorySyncErrorV1::InvalidPage));
        }
    }

    #[test]
    fn restriction_query_fingerprint_detects_rule_changes() {
        let first = br#"{"data":[{"type":"logs_restriction_queries","id":"a1234567-1234-1234-1234-123456789abc","attributes":{"restriction_query":"team:payments"}},{"type":"logs_restriction_queries","id":"b1234567-1234-1234-1234-123456789abc","attributes":{"restriction_query":"env:prod"}}]}"#;
        let reordered = br#"{"data":[{"type":"logs_restriction_queries","id":"b1234567-1234-1234-1234-123456789abc","attributes":{"restriction_query":"env:prod"}},{"type":"logs_restriction_queries","id":"a1234567-1234-1234-1234-123456789abc","attributes":{"restriction_query":"team:payments"}}]}"#;
        let narrowed = br#"{"data":[{"type":"logs_restriction_queries","id":"a1234567-1234-1234-1234-123456789abc","attributes":{"restriction_query":"team:payments AND env:prod"}},{"type":"logs_restriction_queries","id":"b1234567-1234-1234-1234-123456789abc","attributes":{"restriction_query":"env:prod"}}]}"#;
        assert_eq!(
            parse_restriction_query_digest(first),
            parse_restriction_query_digest(reordered)
        );
        assert_ne!(
            parse_restriction_query_digest(first),
            parse_restriction_query_digest(narrowed)
        );
        assert_eq!(
            parse_restriction_query_digest(br#"{"data":[{"type":"wrong","id":"a1234567-1234-1234-1234-123456789abc","attributes":{"restriction_query":"*"}}]}"#),
            Err(HistorySyncErrorV1::InvalidPage)
        );
    }

    #[test]
    fn user_permission_fingerprint_detects_global_grant_changes() {
        let first = br#"{"data":[{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data","restricted":false}},{"type":"permissions","id":"p2","attributes":{"name":"logs_read_index_data","restricted":true}}]}"#;
        let reordered = br#"{"data":[{"type":"permissions","id":"p2","attributes":{"name":"logs_read_index_data","restricted":true}},{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data","restricted":false}}]}"#;
        let narrowed = br#"{"data":[{"type":"permissions","id":"p2","attributes":{"name":"logs_read_index_data","restricted":true}}]}"#;
        assert_eq!(
            parse_user_permissions_digest(first),
            parse_user_permissions_digest(reordered)
        );
        assert_ne!(
            parse_user_permissions_digest(first),
            parse_user_permissions_digest(narrowed)
        );
        assert!(parse_user_permissions_digest(first).unwrap().1);
        assert!(!parse_user_permissions_digest(first).unwrap().2);
        assert_eq!(
            parse_user_permissions_digest(
                br#"{"data":[{"type":"permissions","id":"p1","attributes":{"restricted":false}}]}"#
            ),
            Err(HistorySyncErrorV1::InvalidPage)
        );
        let global = br#"{"data":[{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data","restricted":true}},{"type":"permissions","id":"p2","attributes":{"name":"logs_read_index_data","restricted":false}}]}"#;
        assert!(parse_user_permissions_digest(global).unwrap().2);
        assert_eq!(
            parse_user_permissions_digest(br#"{"data":[{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data"}}]}"#),
            Err(HistorySyncErrorV1::InvalidPage)
        );
    }

    #[test]
    fn access_scope_requests_restrictions_and_effective_user_permissions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let identity = DatadogAccessIdentityV1 {
            org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
            user_id: "b1234567-1234-1234-1234-123456789abc".to_owned(),
            role_ids: vec!["c1234567-1234-1234-1234-123456789abc".to_owned()],
        };
        let user_id = identity.user_id.clone();
        let server = thread::spawn(move || {
            for (path, body) in [
                (
                    format!("/api/v2/logs/config/restriction_queries/user/{user_id}"),
                    r#"{"data":[]}"#,
                ),
                (
                    format!("/api/v2/users/{user_id}/permissions"),
                    r#"{"data":[{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data","restricted":false}},{"type":"permissions","id":"p2","attributes":{"name":"logs_read_index_data","restricted":false}}]}"#,
                ),
            ] {
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
                assert!(headers.starts_with(&format!("get {path} http/1.1")));
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                socket.flush().unwrap();
            }
        });
        let source = DatadogHistorySourceV1::from_endpoint(
            endpoint,
            DatadogStorageTierV1::Indexes,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        assert!(source.current_access_scope_digest(&identity).is_ok());
        server.join().unwrap();
    }

    #[test]
    fn scoped_or_missing_index_permission_cannot_authorize_cached_indexed_logs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let identity = DatadogAccessIdentityV1 {
            org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
            user_id: "b1234567-1234-1234-1234-123456789abc".to_owned(),
            role_ids: vec!["c1234567-1234-1234-1234-123456789abc".to_owned()],
        };
        let server = thread::spawn(move || {
            for permissions in [
                r#"{"data":[{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data","restricted":false}},{"type":"permissions","id":"p2","attributes":{"name":"logs_read_index_data","restricted":true}}]}"#,
                r#"{"data":[{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data","restricted":false}},{"type":"permissions","id":"p2","attributes":{"name":"logs_read_index_data","restricted":true}}]}"#,
                r#"{"data":[{"type":"permissions","id":"p1","attributes":{"name":"logs_read_data","restricted":false}}]}"#,
            ] {
                for body in [r#"{"data":[]}"#, permissions] {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = [0u8; 4096];
                    assert!(socket.read(&mut request).unwrap() > 0);
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                    socket.flush().unwrap();
                }
            }
        });
        let indexed = DatadogHistorySourceV1::from_endpoint(
            endpoint.clone(),
            DatadogStorageTierV1::Indexes,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        assert_eq!(
            indexed.current_access_scope_digest(&identity),
            Err(HistorySyncErrorV1::AccessScopeUnverifiable)
        );
        let archived = DatadogHistorySourceV1::from_endpoint(
            endpoint.clone(),
            DatadogStorageTierV1::OnlineArchives,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        assert!(archived.current_access_scope_digest(&identity).is_ok());
        let missing_grant = DatadogHistorySourceV1::from_endpoint(
            endpoint,
            DatadogStorageTierV1::Indexes,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        assert_eq!(
            missing_grant.current_access_scope_digest(&identity),
            Err(HistorySyncErrorV1::AccessScopeUnverifiable)
        );
        server.join().unwrap();
    }

    #[test]
    fn access_scope_fails_closed_when_user_permissions_cannot_be_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let identity = DatadogAccessIdentityV1 {
            org_id: "a1234567-1234-1234-1234-123456789abc".to_owned(),
            user_id: "b1234567-1234-1234-1234-123456789abc".to_owned(),
            role_ids: vec!["c1234567-1234-1234-1234-123456789abc".to_owned()],
        };
        let server = thread::spawn(move || {
            for authorized in [true, false] {
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
                if authorized {
                    write!(socket, "HTTP/1.1 200 OK\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{{\"data\":[]}}").unwrap();
                } else {
                    write!(
                        socket,
                        "HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .unwrap();
                }
                socket.flush().unwrap();
            }
        });
        let source = DatadogHistorySourceV1::from_endpoint(
            endpoint,
            DatadogStorageTierV1::Indexes,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        assert_eq!(
            source.current_access_scope_digest(&identity),
            Err(HistorySyncErrorV1::PermissionDenied)
        );
        server.join().unwrap();
    }

    #[test]
    fn restriction_query_request_requires_read_config_access() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let user = "b1234567-1234-1234-1234-123456789abc";
        let body = r#"{"data":[]}"#;
        let server = thread::spawn(move || {
            for authorized in [true, false] {
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
                assert!(headers.starts_with(&format!(
                    "get /api/v2/logs/config/restriction_queries/user/{user} http/1.1"
                )));
                assert!(headers.contains("dd-api-key: api-test"));
                assert!(headers.contains("dd-application-key: app-test"));
                if authorized {
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                } else {
                    write!(
                        socket,
                        "HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .unwrap();
                }
                socket.flush().unwrap();
            }
        });
        let source = DatadogHistorySourceV1::from_endpoint(
            endpoint,
            DatadogStorageTierV1::Indexes,
            "api-test".to_owned(),
            "app-test".to_owned(),
        )
        .unwrap();
        assert_eq!(
            source.current_restriction_query_digest(user),
            parse_restriction_query_digest(body.as_bytes())
        );
        assert_eq!(
            source.current_restriction_query_digest(user),
            Err(HistorySyncErrorV1::PermissionDenied)
        );
        server.join().unwrap();
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
            let body = r#"{"data":{"type":"users","id":"b1234567-1234-1234-1234-123456789abc","relationships":{"org":{"data":{"type":"orgs","id":"a1234567-1234-1234-1234-123456789abc"}},"roles":{"data":[{"type":"roles","id":"c1234567-1234-1234-1234-123456789abc"}]}}}}"#;
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
    fn short_rate_limit_reset_retries_but_long_reset_stays_throttled() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0u8; 1024];
                assert!(socket.read(&mut request).unwrap() > 0);
                if index == 0 {
                    write!(socket, "HTTP/1.1 429 Too Many Requests\r\nx-ratelimit-reset: 0\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").unwrap();
                } else {
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .unwrap();
                }
                socket.flush().unwrap();
            }
        });
        let client = Client::new();
        let response = send_with_rate_limit_retry(|| client.get(&endpoint).send()).unwrap();
        assert_eq!(response.status().as_u16(), 200);
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0u8; 1024];
            assert!(socket.read(&mut request).unwrap() > 0);
            write!(socket, "HTTP/1.1 429 Too Many Requests\r\nx-ratelimit-reset: 60\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").unwrap();
            socket.flush().unwrap();
        });
        assert_eq!(
            send_with_rate_limit_retry(|| client.get(&endpoint).send()).err(),
            Some(HistorySyncErrorV1::Throttled)
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
        let no_message = br#"{"data":[{"id":"id-2","type":"log","attributes":{"timestamp":"1970-01-01T00:00:00.006Z","service":"checkout"}}],"meta":{"status":"done"}}"#;
        let page = parse_page(no_message, PARTITION).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].native_id, b"id-2");
        assert_eq!(page.records[0].event_timestamp_millis, 6);
        let terminal = parse_page(
            br#"{"data":null,"meta":{"status":"done","page":{"after":"stale"}}}"#,
            PARTITION,
        )
        .unwrap();
        assert!(terminal.records.is_empty());
        assert!(terminal.next_token.is_none());
        assert_eq!(
            parse_page(br#"{"meta":{"status":"done"}}"#, PARTITION),
            Err(HistorySyncErrorV1::InvalidPage)
        );
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
