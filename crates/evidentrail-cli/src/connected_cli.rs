//! macOS connection registration. Synchronization and query are separate
//! release gates; registration never claims that a source has been backfilled.

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use evidentrail_corpus::{EncryptedHistoryStore, MacOsCorpusKeychainV1};
use evidentrail_ingest::{
    AwsCloudWatchTransportV1, CloudWatchCapsV1, CloudWatchHistorySourceV1, CloudWatchPlanV1,
    HistoryPageSourceV1, HistoryPartitionV1,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::CliFailure;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CloudWatchDescriptor {
    schema_version: u8,
    provider: String,
    account: String,
    region: String,
    log_group: String,
    profile: Option<String>,
}

pub(super) fn run(args: Vec<OsString>) -> Result<ExitCode, CliFailure> {
    let mut args = args.into_iter();
    let command = args
        .next()
        .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_COMMAND_REQUIRED"))?;
    if command == "connect-cloudwatch" {
        connect_cloudwatch(parse_cloudwatch_args(args)?)
    } else if command == "list" {
        if args.next().is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        }
        list_sources()
    } else {
        Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_COMMAND"))
    }
}

fn parse_cloudwatch_args(
    mut args: impl Iterator<Item = OsString>,
) -> Result<CloudWatchDescriptor, CliFailure> {
    let mut account = None;
    let mut region = None;
    let mut log_group = None;
    let mut profile = None;
    while let Some(option) = args.next() {
        let target = if option == "--account" {
            &mut account
        } else if option == "--region" {
            &mut region
        } else if option == "--log-group" {
            &mut log_group
        } else if option == "--profile" {
            &mut profile
        } else {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_UNKNOWN_OPTION"));
        };
        let value = args
            .next()
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_MISSING_VALUE"))?
            .into_string()
            .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_VALUE"))?;
        if target.replace(value).is_some() {
            return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_DUPLICATE_OPTION"));
        }
    }
    let binding = CloudWatchDescriptor {
        schema_version: 1,
        provider: "cloudwatch".to_owned(),
        account: account
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_ACCOUNT_REQUIRED"))?,
        region: region.ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_REGION_REQUIRED"))?,
        log_group: log_group
            .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SOURCES_LOG_GROUP_REQUIRED"))?,
        profile,
    };
    validate_binding(&binding)?;
    Ok(binding)
}

fn validate_binding(binding: &CloudWatchDescriptor) -> Result<(), CliFailure> {
    if binding.schema_version != 1
        || binding.provider != "cloudwatch"
        || binding.account.len() != 12
        || !binding.account.bytes().all(|byte| byte.is_ascii_digit())
        || binding.region.is_empty()
        || binding.region.len() > 64
        || !binding
            .region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || binding.log_group.is_empty()
        || binding.log_group.len() > 512
        || binding.log_group.chars().any(char::is_control)
        || binding.profile.as_ref().is_some_and(|profile| {
            profile.is_empty()
                || profile.len() > 128
                || !profile
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"));
    }
    Ok(())
}

fn plan(binding: &CloudWatchDescriptor) -> Result<CloudWatchPlanV1, CliFailure> {
    let caps = CloudWatchCapsV1::new(10_000, 16 * 1024 * 1024, 1, 8 * 1024 * 1024)
        .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"))?;
    CloudWatchPlanV1::new(
        binding.account.as_bytes().to_vec(),
        binding.region.as_bytes().to_vec(),
        binding.log_group.as_bytes().to_vec(),
        Vec::<Vec<u8>>::new(),
        None,
        None,
        None,
        caps,
    )
    .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"))
}

fn connect_cloudwatch(binding: CloudWatchDescriptor) -> Result<ExitCode, CliFailure> {
    let source_plan = plan(&binding)?;
    let transport = AwsCloudWatchTransportV1::connect(
        source_plan.clone(),
        &binding.account,
        binding.profile.as_deref(),
    )
    .map_err(|error| CliFailure::runtime(error.code()))?;
    let mut source = CloudWatchHistorySourceV1::new(source_plan, transport)
        .map_err(|_| CliFailure::usage("EVIDENTRAIL_SOURCES_INVALID_BINDING"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CLOCK_FAILURE"))?
        .as_millis() as i64;
    // A narrow internal permission probe; it is not a product query window.
    source
        .fetch_page(
            HistoryPartitionV1 {
                start_millis: now.saturating_sub(1000),
                end_millis: now,
            },
            None,
        )
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_READ_VERIFICATION_FAILED"))?;

    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let descriptor = serde_json::to_vec(&binding)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
    let source_digest = MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let path = corpus_path(&source_digest, true)?;
    register_corpus(&authority, &tenant, &descriptor, &path)?;
    let response = json!({
        "source_id": hex(&source_digest),
        "provider": "cloudwatch",
        "account": binding.account,
        "region": binding.region,
        "log_group": binding.log_group,
        "status": "registered_backfill_pending"
    });
    serde_json::to_writer(io::stdout().lock(), &response)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn register_corpus(
    authority: &MacOsCorpusKeychainV1,
    tenant: &[u8; 32],
    descriptor: &[u8],
    path: &Path,
) -> Result<(), CliFailure> {
    let (source_digest, key) = authority
        .create_bound(tenant, descriptor)
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let reserved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    if reserved.is_err() {
        let _ = authority.destroy(tenant, &source_digest);
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_SOURCES_CORPUS_CREATE_FAILED",
        ));
    }
    drop(reserved);
    if EncryptedHistoryStore::open(path, &key, tenant, &source_digest).is_err() {
        let _ = fs::remove_file(path);
        let _ = authority.destroy(tenant, &source_digest);
        return Err(CliFailure::runtime(
            "EVIDENTRAIL_SOURCES_CORPUS_CREATE_FAILED",
        ));
    }
    Ok(())
}

fn list_sources() -> Result<ExitCode, CliFailure> {
    let authority = MacOsCorpusKeychainV1::production();
    let tenant = authority
        .local_tenant_digest()
        .map_err(|error| CliFailure::runtime(error.code()))?;
    let mut listed = Vec::new();
    for entry in authority
        .list_bound(&tenant)
        .map_err(|error| CliFailure::runtime(error.code()))?
    {
        let binding: CloudWatchDescriptor = serde_json::from_slice(&entry.descriptor)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        validate_binding(&binding)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DESCRIPTOR_FAILURE"))?;
        let path = corpus_path(&entry.source_digest, false)?;
        let status = if path.is_file() {
            let key = authority
                .load(&tenant, &entry.source_digest)
                .map_err(|error| CliFailure::runtime(error.code()))?;
            let store = EncryptedHistoryStore::open(&path, &key, &tenant, &entry.source_digest)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            let checkpoint = store
                .read_checkpoint()
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?;
            json!({
                "state": "registered_incomplete",
                "record_count": store.record_count().map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_CORPUS_OPEN_FAILED"))?,
                "scanned_through_millis": checkpoint.map(|value| value.completed_through_millis),
            })
        } else {
            json!({"state": "corpus_missing"})
        };
        listed.push(json!({
            "source_id": hex(&entry.source_digest),
            "provider": binding.provider,
            "account": binding.account,
            "region": binding.region,
            "log_group": binding.log_group,
            "status": status,
        }));
    }
    serde_json::to_writer(io::stdout().lock(), &listed)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn corpus_path(source_digest: &[u8; 32], create_dirs: bool) -> Result<PathBuf, CliFailure> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SOURCES_HOME_UNAVAILABLE"))?;
    if !home.is_absolute() {
        return Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_HOME_UNAVAILABLE"));
    }
    let home = fs::canonicalize(home)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_HOME_UNAVAILABLE"))?;
    let data = home.join("Library/Application Support/Evidentrail");
    let corpus = data.join("corpus");
    if create_dirs {
        ensure_private_directory(&data)?;
        ensure_private_directory(&corpus)?;
    } else {
        check_private_directory_if_present(&data)?;
        check_private_directory_if_present(&corpus)?;
    }
    Ok(corpus.join(format!("{}.db", hex(source_digest))))
}

fn ensure_private_directory(path: &Path) -> Result<(), CliFailure> {
    if !path.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE"))?;
    }
    check_private_directory(path)
}

fn check_private_directory_if_present(path: &Path) -> Result<(), CliFailure> {
    match path.symlink_metadata() {
        Ok(_) => check_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE")),
    }
}

fn check_private_directory(path: &Path) -> Result<(), CliFailure> {
    let meta = path
        .symlink_metadata()
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE"))?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err(CliFailure::runtime("EVIDENTRAIL_SOURCES_DATA_DIR_UNSAFE"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudwatch_registration_requires_complete_unfiltered_binding() {
        let args = [
            "--account",
            "123456789012",
            "--region",
            "us-west-2",
            "--log-group",
            "/aws/api",
        ]
        .into_iter()
        .map(OsString::from);
        let binding = parse_cloudwatch_args(args).unwrap();
        assert_eq!(binding.profile, None);
        assert_eq!(binding.log_group, "/aws/api");
        assert!(plan(&binding).unwrap().log_streams().is_empty());
        let mut invalid = binding;
        invalid.account = "wrong".to_owned();
        assert!(validate_binding(&invalid).is_err());
        assert!(
            parse_cloudwatch_args(["--account", "123"].into_iter().map(OsString::from)).is_err()
        );
    }

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain"]
    fn registered_source_reopens_same_encrypted_corpus() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let authority = MacOsCorpusKeychainV1::isolated_for_tests(&format!(
            "cli-{}-{suffix}",
            std::process::id()
        ))
        .unwrap();
        let tenant = [3; 32];
        let binding = CloudWatchDescriptor {
            schema_version: 1,
            provider: "cloudwatch".to_owned(),
            account: "123456789012".to_owned(),
            region: "us-west-2".to_owned(),
            log_group: "/aws/test".to_owned(),
            profile: None,
        };
        let descriptor = serde_json::to_vec(&binding).unwrap();
        let digest = MacOsCorpusKeychainV1::source_digest_for_descriptor(&descriptor).unwrap();
        let path = env::temp_dir().join(format!(
            "evidentrail-registered-{}-{suffix}.db",
            std::process::id()
        ));
        register_corpus(&authority, &tenant, &descriptor, &path).unwrap();
        assert_eq!(authority.list_bound(&tenant).unwrap().len(), 1);
        let key = authority.load(&tenant, &digest).unwrap();
        let store = EncryptedHistoryStore::open(&path, &key, &tenant, &digest).unwrap();
        assert_eq!(store.record_count().unwrap(), 0);
        assert_eq!(store.read_checkpoint().unwrap(), None);
        drop(store);
        assert_eq!(
            register_corpus(&authority, &tenant, &descriptor, &path)
                .err()
                .unwrap()
                .code,
            "EVIDENTRAIL_CORPUS_KEY_ALREADY_EXISTS"
        );
        authority.destroy(&tenant, &digest).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
