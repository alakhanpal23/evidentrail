//! Optional per-user launchd supervision of the connected source watcher.

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use rustix::process::geteuid;
use serde_json::json;

use crate::CliFailure;

const LABEL: &str = "io.evidentrail.connected-sync";
const PLIST_NAME: &str = "io.evidentrail.connected-sync.plist";

struct ServicePaths {
    plist: PathBuf,
    stderr_log: PathBuf,
}

pub(crate) fn run(mut args: impl Iterator<Item = OsString>) -> Result<ExitCode, CliFailure> {
    let command = args
        .next()
        .ok_or_else(|| CliFailure::usage("EVIDENTRAIL_SERVICE_COMMAND_REQUIRED"))?;
    if args.next().is_some() {
        return Err(CliFailure::usage("EVIDENTRAIL_SERVICE_UNKNOWN_OPTION"));
    }
    if command == "install" {
        install()
    } else if command == "status" {
        status()
    } else if command == "uninstall" {
        uninstall()
    } else {
        Err(CliFailure::usage("EVIDENTRAIL_SERVICE_UNKNOWN_COMMAND"))
    }
}

fn service_paths(create: bool) -> Result<ServicePaths, CliFailure> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SERVICE_HOME_UNAVAILABLE"))?;
    let home = fs::canonicalize(home)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_HOME_UNAVAILABLE"))?;
    check_directory(&home, false)?;
    let library = home.join("Library");
    check_directory(&library, false)?;
    let launch_agents = library.join("LaunchAgents");
    let logs = library.join("Logs");
    let private_logs = logs.join("Evidentrail");
    check_directory(&launch_agents, create)?;
    check_directory(&logs, create)?;
    check_directory(&private_logs, create)?;
    Ok(ServicePaths {
        plist: launch_agents.join(PLIST_NAME),
        stderr_log: private_logs.join("connected-sync.err"),
    })
}

fn check_directory(path: &Path, create: bool) -> Result<(), CliFailure> {
    if create && !path.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_DIRECTORY_UNSAFE"))?;
    }
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_DIRECTORY_UNSAFE")),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_DIRECTORY_UNSAFE"));
    }
    Ok(())
}

fn check_private_file(path: &Path) -> Result<bool, CliFailure> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE")),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"));
    }
    Ok(true)
}

fn current_binary() -> Result<PathBuf, CliFailure> {
    let binary = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_BINARY_UNSAFE"))?;
    let metadata = binary
        .metadata()
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_BINARY_UNSAFE"))?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_BINARY_UNSAFE"));
    }
    Ok(binary)
}

fn xml_escape(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&apos;".to_owned(),
            _ => character.to_string(),
        })
        .collect()
}

fn render_plist(binary: &Path, stderr_log: &Path) -> Result<String, CliFailure> {
    let binary = binary
        .to_str()
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SERVICE_BINARY_UNSAFE"))?;
    let stderr_log = stderr_log
        .to_str()
        .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{LABEL}</string>\n<key>ProgramArguments</key><array>\n<string>{}</string><string>sources</string><string>watch</string><string>--interval-seconds</string><string>60</string>\n</array>\n<key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>/dev/null</string>\n<key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
        xml_escape(binary),
        xml_escape(stderr_log)
    ))
}

fn service_target() -> String {
    format!("gui/{}/{LABEL}", geteuid().as_raw())
}

fn domain_target() -> String {
    format!("gui/{}", geteuid().as_raw())
}

fn launchctl(args: &[&str]) -> Result<bool, CliFailure> {
    Command::new("/bin/launchctl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_LAUNCHCTL_UNAVAILABLE"))
}

fn loaded() -> Result<bool, CliFailure> {
    launchctl(&["print", &service_target()])
}

fn write_status(value: serde_json::Value) -> Result<ExitCode, CliFailure> {
    serde_json::to_writer(io::stdout().lock(), &value)
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_OUTPUT_FAILED"))?;
    writeln!(io::stdout().lock())
        .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_OUTPUT_FAILED"))?;
    Ok(ExitCode::SUCCESS)
}

fn install() -> Result<ExitCode, CliFailure> {
    let guard = crate::connected_cli::connected_catalog_lock()?;
    let paths = service_paths(true)?;
    let binary = current_binary()?;
    let expected = render_plist(&binary, &paths.stderr_log)?;
    prepare_service_files(&paths, &expected)?;
    drop(guard);
    if !loaded()? {
        if !launchctl(&["enable", &service_target()])? {
            return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_ENABLE_FAILED"));
        }
        if !launchctl(&[
            "bootstrap",
            &domain_target(),
            paths
                .plist
                .to_str()
                .ok_or_else(|| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?,
        ])? {
            return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_BOOTSTRAP_FAILED"));
        }
    }
    write_status(json!({"status":"installed", "loaded":loaded()?, "label":LABEL}))
}

fn prepare_service_files(paths: &ServicePaths, expected: &str) -> Result<(), CliFailure> {
    if !check_private_file(&paths.stderr_log)? {
        let log = OpenOptions::new()
            .create_new(true)
            .append(true)
            .mode(0o600)
            .open(&paths.stderr_log)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
        log.sync_all()
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
    }
    if check_private_file(&paths.plist)? {
        let existing = fs::read(&paths.plist)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
        if existing != expected.as_bytes() {
            return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_ALREADY_INSTALLED"));
        }
    } else {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_RANDOMNESS_UNAVAILABLE"))?;
        let temporary = paths.plist.with_extension(format!(
            "plist.tmp-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let write_result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
            file.write_all(expected.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
            fs::rename(&temporary, &paths.plist)
                .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result?;
    }
    Ok(())
}

fn status() -> Result<ExitCode, CliFailure> {
    let paths = service_paths(false)?;
    let installed = check_private_file(&paths.plist)?;
    write_status(
        json!({"status":if installed {"installed"} else {"not_installed"}, "loaded":loaded()?, "label":LABEL}),
    )
}

fn uninstall() -> Result<ExitCode, CliFailure> {
    let paths = service_paths(false)?;
    let installed = check_private_file(&paths.plist)?;
    let is_loaded = loaded()?;
    if !installed && is_loaded {
        return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_FOREIGN_LOADED"));
    }
    if installed {
        let contents = fs::read_to_string(&paths.plist)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
        if !contents.contains(&format!("<string>{LABEL}</string>"))
            || !contents.contains("<string>sources</string><string>watch</string>")
        {
            return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"));
        }
    }
    if is_loaded && (!launchctl(&["bootout", &service_target()])? || loaded()?) {
        return Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_BOOTOUT_FAILED"));
    }
    let _guard = crate::connected_cli::connected_catalog_lock()?;
    if installed {
        fs::remove_file(&paths.plist)
            .map_err(|_| CliFailure::runtime("EVIDENTRAIL_SERVICE_FILE_UNSAFE"))?;
    }
    write_status(json!({"status":"uninstalled", "loaded":false, "label":LABEL}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_agent_plist_is_valid_and_escapes_paths() {
        let plist = render_plist(
            Path::new("/tmp/a&b<test>/evidentrail"),
            Path::new("/tmp/log&err"),
        )
        .unwrap();
        assert!(plist.contains("/tmp/a&amp;b&lt;test&gt;/evidentrail"));
        assert!(plist.contains("/tmp/log&amp;err"));
        assert!(plist.contains("<key>KeepAlive</key><true/>"));
        let path = env::temp_dir().join(format!(
            "evidentrail-launch-agent-{}.plist",
            std::process::id()
        ));
        fs::write(&path, plist).unwrap();
        let valid = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        fs::remove_file(path).unwrap();
        assert!(valid);
    }

    #[test]
    fn service_files_are_private_idempotent_and_refuse_replacement() {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        let base = env::temp_dir().join(format!(
            "evidentrail-service-{}-{:x?}",
            std::process::id(),
            random
        ));
        DirBuilder::new().mode(0o700).create(&base).unwrap();
        let paths = ServicePaths {
            plist: base.join(PLIST_NAME),
            stderr_log: base.join("connected-sync.err"),
        };
        let expected = render_plist(Path::new("/tmp/evidentrail"), &paths.stderr_log).unwrap();
        prepare_service_files(&paths, &expected).unwrap();
        prepare_service_files(&paths, &expected).unwrap();
        assert_eq!(fs::read_to_string(&paths.plist).unwrap(), expected);
        assert_eq!(
            paths.plist.metadata().unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            paths.stderr_log.metadata().unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            prepare_service_files(&paths, "different"),
            Err(CliFailure::runtime("EVIDENTRAIL_SERVICE_ALREADY_INSTALLED"))
        );
        fs::remove_dir_all(base).unwrap();
    }
}
