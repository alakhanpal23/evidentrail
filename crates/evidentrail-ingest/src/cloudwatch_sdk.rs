//! AWS SDK transport for the bounded CloudWatch history source.

use aws_config::{BehaviorVersion, Region};
use aws_sdk_cloudwatchlogs::error::{ProvideErrorMetadata as _, SdkError};
use aws_sdk_cloudwatchlogs::operation::filter_log_events::FilterLogEventsError;
use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
use tokio::runtime::{Builder, Runtime};

use crate::{
    CloudWatchEventV1, CloudWatchFilterRequestV1, CloudWatchPageV1, CloudWatchPlanV1,
    CloudWatchTransportErrorV1, CloudWatchTransportV1,
};

pub struct AwsCloudWatchTransportV1 {
    binding: CloudWatchPlanV1,
    expected_caller_account: String,
    caller_arn: String,
    runtime: Runtime,
    logs: aws_sdk_cloudwatchlogs::Client,
    sts: aws_sdk_sts::Client,
}

impl AwsCloudWatchTransportV1 {
    /// Bind one read-only connection to a log group and AWS caller account.
    /// A source-account ARN is required for cross-account observability.
    pub fn connect(
        binding: CloudWatchPlanV1,
        expected_caller_account: &str,
        expected_caller_arn: Option<&str>,
        profile: Option<&str>,
    ) -> Result<Self, CloudWatchTransportErrorV1> {
        if !valid_scope(&binding, expected_caller_account) || profile.is_some_and(str::is_empty) {
            return Err(CloudWatchTransportErrorV1::ProviderFailure);
        }
        let region = std::str::from_utf8(binding.region())
            .map_err(|_| CloudWatchTransportErrorV1::ProviderFailure)?;
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|_| CloudWatchTransportErrorV1::ProviderFailure)?;
        let mut loader =
            aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region.to_owned()));
        if let Some(profile) = profile {
            loader = loader.profile_name(profile);
        }
        let config = runtime.block_on(loader.load());
        let transport = Self {
            binding,
            expected_caller_account: expected_caller_account.to_owned(),
            caller_arn: String::new(),
            logs: aws_sdk_cloudwatchlogs::Client::new(&config),
            sts: aws_sdk_sts::Client::new(&config),
            runtime,
        };
        let caller_arn = transport.current_caller_arn()?;
        if expected_caller_arn.is_some_and(|expected| expected != caller_arn) {
            return Err(CloudWatchTransportErrorV1::AuthenticationChanged);
        }
        let mut transport = transport;
        transport.caller_arn = caller_arn;
        Ok(transport)
    }

    #[must_use]
    pub fn caller_arn(&self) -> &str {
        &self.caller_arn
    }

    fn current_caller_arn(&self) -> Result<String, CloudWatchTransportErrorV1> {
        let output = self
            .runtime
            .block_on(self.sts.get_caller_identity().send())
            .map_err(classify_sts_error)?;
        if output.account() != Some(self.expected_caller_account.as_str()) {
            return Err(CloudWatchTransportErrorV1::AuthenticationChanged);
        }
        let arn = output
            .arn()
            .filter(|arn| !arn.is_empty())
            .ok_or(CloudWatchTransportErrorV1::ProviderFailure)?;
        Ok(arn.to_owned())
    }

    fn verify_caller(&self) -> Result<(), CloudWatchTransportErrorV1> {
        if self.current_caller_arn()? != self.caller_arn {
            return Err(CloudWatchTransportErrorV1::AuthenticationChanged);
        }
        Ok(())
    }
}

impl CloudWatchTransportV1 for AwsCloudWatchTransportV1 {
    fn filter_log_events(
        &self,
        request: &CloudWatchFilterRequestV1,
    ) -> Result<CloudWatchPageV1, CloudWatchTransportErrorV1> {
        let plan = request.plan();
        if plan.account() != self.binding.account()
            || plan.region() != self.binding.region()
            || plan.log_group() != self.binding.log_group()
            || !plan.log_streams().is_empty()
            || plan.filter_pattern().is_some()
            || plan.start_time_millis().is_none()
            || plan.end_time_millis().is_none()
        {
            return Err(CloudWatchTransportErrorV1::ProviderFailure);
        }
        let group = std::str::from_utf8(plan.log_group())
            .map_err(|_| CloudWatchTransportErrorV1::ProviderFailure)?;
        let token = request
            .next_token()
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|_| CloudWatchTransportErrorV1::TokenExpired)?;
        self.verify_caller()?;
        let mut query = self
            .logs
            .filter_log_events()
            .start_time(plan.start_time_millis().expect("checked"))
            .end_time(plan.end_time_millis().expect("checked"))
            .limit(plan.caps().max_records().min(10_000) as i32)
            .set_next_token(token.map(str::to_owned));
        query = if group.starts_with("arn:") {
            query.log_group_identifier(group)
        } else {
            query.log_group_name(group)
        };
        let output = self
            .runtime
            .block_on(query.send())
            .map_err(classify_logs_error)?;
        let events = output
            .events()
            .iter()
            .map(|event| {
                let log_stream = event
                    .log_stream_name()
                    .ok_or(CloudWatchTransportErrorV1::ProviderFailure)?;
                let event_id = event
                    .event_id()
                    .ok_or(CloudWatchTransportErrorV1::ProviderFailure)?;
                let timestamp = event
                    .timestamp()
                    .ok_or(CloudWatchTransportErrorV1::ProviderFailure)?;
                let ingestion_time = event
                    .ingestion_time()
                    .ok_or(CloudWatchTransportErrorV1::ProviderFailure)?;
                let message = event
                    .message()
                    .ok_or(CloudWatchTransportErrorV1::ProviderFailure)?;
                Ok(CloudWatchEventV1 {
                    log_stream: log_stream.as_bytes().to_vec(),
                    event_id: event_id.as_bytes().to_vec(),
                    event_timestamp_millis: timestamp,
                    ingestion_timestamp_millis: ingestion_time,
                    message: message.as_bytes().to_vec(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CloudWatchPageV1::new(
            events,
            output.next_token().map(|token| token.as_bytes().to_vec()),
        ))
    }
}

fn valid_scope(binding: &CloudWatchPlanV1, caller_account: &str) -> bool {
    let Ok(account) = std::str::from_utf8(binding.account()) else {
        return false;
    };
    let Ok(region) = std::str::from_utf8(binding.region()) else {
        return false;
    };
    let Ok(group) = std::str::from_utf8(binding.log_group()) else {
        return false;
    };
    if !valid_account(account)
        || !valid_account(caller_account)
        || region.is_empty()
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || group.is_empty()
        || !binding.log_streams().is_empty()
        || binding.filter_pattern().is_some()
        || binding.start_time_millis().is_some()
        || binding.end_time_millis().is_some()
    {
        return false;
    }
    if !group.starts_with("arn:") {
        return account == caller_account && valid_log_group_name(group);
    }
    let parts = group.splitn(7, ':').collect::<Vec<_>>();
    parts.len() == 7
        && parts[0] == "arn"
        && !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && parts[2] == "logs"
        && parts[3] == region
        && parts[4] == account
        && parts[5] == "log-group"
        && valid_log_group_name(parts[6].strip_suffix(":*").unwrap_or(parts[6]))
}

fn valid_log_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 512
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/' | b'#')
        })
}

fn valid_account(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn classify_code(code: Option<&str>) -> CloudWatchTransportErrorV1 {
    match code {
        Some("AccessDeniedException" | "AccessDenied" | "UnauthorizedOperation") => {
            CloudWatchTransportErrorV1::PermissionDenied
        }
        Some("ExpiredTokenException" | "ExpiredToken") => CloudWatchTransportErrorV1::TokenExpired,
        Some(
            "UnrecognizedClientException" | "InvalidClientTokenId" | "InvalidSignatureException",
        ) => CloudWatchTransportErrorV1::AuthenticationChanged,
        Some("ThrottlingException" | "Throttling" | "TooManyRequestsException") => {
            CloudWatchTransportErrorV1::ThrottlingExhausted
        }
        _ => CloudWatchTransportErrorV1::ProviderFailure,
    }
}

fn classify_logs_error(error: SdkError<FilterLogEventsError>) -> CloudWatchTransportErrorV1 {
    match error {
        SdkError::DispatchFailure(_) | SdkError::TimeoutError(_) => {
            CloudWatchTransportErrorV1::NetworkFailure
        }
        _ => classify_code(error.as_service_error().and_then(|service| service.code())),
    }
}

fn classify_sts_error(error: SdkError<GetCallerIdentityError>) -> CloudWatchTransportErrorV1 {
    match error {
        SdkError::DispatchFailure(_) | SdkError::TimeoutError(_) => {
            CloudWatchTransportErrorV1::NetworkFailure
        }
        _ => classify_code(error.as_service_error().and_then(|service| service.code())),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::{
        CloudWatchCapsV1, CloudWatchHistorySourceV1, HistoryPageSourceV1, HistoryPartitionV1,
    };

    fn binding(account: &str, region: &str, group: &str) -> CloudWatchPlanV1 {
        CloudWatchPlanV1::new(
            account.as_bytes(),
            region.as_bytes(),
            group.as_bytes(),
            [],
            None,
            None,
            None,
            CloudWatchCapsV1::new(10_000, 1_000_000, 100, 1_000_000).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn scope_requires_exact_account_region_and_cross_account_arn() {
        assert!(valid_scope(
            &binding("123456789012", "us-east-1", "/aws/app"),
            "123456789012"
        ));
        assert!(!valid_scope(
            &binding("123456789012", "us-east-1", "/aws/app"),
            "999999999999"
        ));
        let arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/app";
        assert!(valid_scope(
            &binding("123456789012", "us-east-1", arn),
            "999999999999"
        ));
        assert!(valid_scope(
            &binding("123456789012", "us-east-1", &format!("{arn}:*")),
            "999999999999"
        ));
        assert!(!valid_scope(
            &binding("123456789012", "us-west-2", arn),
            "999999999999"
        ));
        assert!(!valid_scope(
            &binding("999999999999", "us-east-1", arn),
            "999999999999"
        ));
        for invalid in [
            format!("{arn}:log-stream:only-one"),
            format!("{arn}:*:*"),
            "arn:aws:logs:us-east-1:123456789012:log-group:bad:name".to_owned(),
            "arn:aws:logs:us-east-1:123456789012:log-group:bad*".to_owned(),
        ] {
            assert!(!valid_scope(
                &binding("123456789012", "us-east-1", &invalid),
                "999999999999"
            ));
        }
        assert!(!valid_scope(
            &binding("123456789012", "us-east-1", "bad:name"),
            "123456789012"
        ));
    }

    #[test]
    fn provider_errors_are_typed_without_revealing_payloads() {
        assert_eq!(
            classify_code(Some("AccessDeniedException")),
            CloudWatchTransportErrorV1::PermissionDenied
        );
        assert_eq!(
            classify_code(Some("ExpiredTokenException")),
            CloudWatchTransportErrorV1::TokenExpired
        );
        assert_eq!(
            classify_code(Some("ThrottlingException")),
            CloudWatchTransportErrorV1::ThrottlingExhausted
        );
    }

    #[test]
    fn sdk_maps_empty_continuation_page_and_original_event_over_signed_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut bodies = Vec::new();
            for index in 0..5 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut chunk = [0u8; 4096];
                    let read = socket.read(&mut chunk).unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(position) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                assert!(headers.contains("authorization: aws4-hmac-sha256"));
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map(|value| value.trim().parse::<usize>().unwrap())
                    .unwrap_or(0);
                while request.len() - header_end < length {
                    let mut chunk = [0u8; 4096];
                    let read = socket.read(&mut chunk).unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&chunk[..read]);
                }
                bodies.push(
                    String::from_utf8_lossy(&request[header_end..header_end + length]).to_string(),
                );
                let (content_type, body) = if index == 4 {
                    (
                        "text/xml",
                        "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/different</Arn><UserId>different</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>",
                    )
                } else if index % 2 == 0 {
                    (
                        "text/xml",
                        "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>test</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>",
                    )
                } else if index == 1 {
                    (
                        "application/x-amz-json-1.1",
                        r#"{"events":[],"nextToken":"continue"}"#,
                    )
                } else {
                    (
                        "application/x-amz-json-1.1",
                        r#"{"events":[{"eventId":"evt-1","logStreamName":"stream-a","timestamp":5,"ingestionTime":6,"message":"original line"}]}"#,
                    )
                };
                write!(socket, "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
                socket.flush().unwrap();
            }
            bodies
        });
        let credentials = aws_sdk_cloudwatchlogs::config::Credentials::new(
            "AKIDEXAMPLE",
            "secret",
            None,
            None,
            "local-test",
        );
        let region = aws_sdk_cloudwatchlogs::config::Region::new("us-east-1");
        let logs_config = aws_sdk_cloudwatchlogs::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(region.clone())
            .credentials_provider(credentials.clone())
            .endpoint_url(&endpoint)
            .build();
        let sts_config = aws_sdk_sts::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(region)
            .credentials_provider(credentials)
            .endpoint_url(&endpoint)
            .build();
        let binding = binding("123456789012", "us-east-1", "/aws/app");
        let transport = AwsCloudWatchTransportV1 {
            binding: binding.clone(),
            expected_caller_account: "123456789012".to_owned(),
            caller_arn: "arn:aws:iam::123456789012:user/test".to_owned(),
            runtime: Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
            logs: aws_sdk_cloudwatchlogs::Client::from_conf(logs_config),
            sts: aws_sdk_sts::Client::from_conf(sts_config),
        };
        let mut source = CloudWatchHistorySourceV1::new(binding, transport).unwrap();
        let partition = HistoryPartitionV1 {
            start_millis: 0,
            end_millis: 10,
        };
        let first = source.fetch_page(partition, None).unwrap();
        assert!(first.records.is_empty());
        assert_eq!(first.next_token.as_deref(), Some(b"continue".as_slice()));
        let second = source
            .fetch_page(partition, first.next_token.as_deref())
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].bytes, b"original line");
        assert!(second.next_token.is_none());
        assert_eq!(
            source.fetch_page(partition, None),
            Err(crate::HistorySyncErrorV1::AuthenticationChanged)
        );
        let bodies = server.join().unwrap();
        assert!(bodies[0].contains("GetCallerIdentity"));
        assert!(bodies[1].contains("logGroupName") && bodies[1].contains("startTime"));
        assert!(!bodies[1].contains("filterPattern") && !bodies[1].contains("logStreamNames"));
        assert!(bodies[3].contains("continue"));
        assert!(bodies[4].contains("GetCallerIdentity"));
    }
}
