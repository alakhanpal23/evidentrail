# macOS Keychain provisioning

Evidentrail's production durable backend uses the macOS data-protection Keychain. It
does not use iCloud synchronization or cloud object storage. The repository
contains ciphertext on local APFS; the Keychain contains each result key and
its trusted lifecycle record.

## Required external setup

The release owner must provide an Apple Developer team and a provisioning
profile that authorizes the shipped executable's Keychain access group. Apple
documents that a macOS command-line tool needs an app-like bundle structure to
embed that profile, and that the access-group entitlement is restricted and
must be authorized by the profile.

The release artifact must therefore be:

1. packaged in an app-like bundle with the provisioning profile embedded;
2. signed with the release team's Developer ID identity;
3. entitled with its authorized `com.apple.application-identifier`, team
   identifier, and `keychain-access-groups` value;
4. notarized using the project's normal release process; and
5. verified with `codesign -d --entitlements :- PATH` before the Keychain
   integration and qualification suites run.

Do not commit signing certificates, private keys, provisioning profiles,
notarization credentials, or expanded team identifiers to this repository.

## Runtime gate

An unsigned developer binary receives `errSecMissingEntitlement` when it tries
to create a data-protection Keychain item. Evidentrail maps that status to the
contentless `EVIDENTRAIL_AUTHORITY_V2_UNAVAILABLE` error and never falls back to the
process authority or legacy file-based Keychain.

On the signed reference host, run:

```sh
cargo test -p evidentrail-store \
  --test macos_keychain_authority_v2_contract -- --ignored --exact \
  --test-threads=1
```

Then run the dedicated-host performance protocol. A successful developer
smoke does not replace the signed-binary, locked-session, reboot, and clean-boot
checks.

Apple references:

- [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [Keychain Access Groups Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups)
- [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/)
