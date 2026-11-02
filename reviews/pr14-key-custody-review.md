# CertRobo PR #14 review — 2 November 2026

Reviewed `80def2754f037136d3e78bbd8241c600bd5dfdea` against `master` `e80a384bc19dce836cdb222d421d3967b9786eae`. Recommendation: address the recovery procedure before merging.

## Findings

1. **Recovery instructions can delete the only legacy passphrase after a failed migration.** `README.md:334-340` runs `shred -u /etc/certrobo/legacy-ca.pass` immediately after `--reprotect-ca-keys`, independently of its exit status and before `--verify-ca-custody`. A missing key, incorrect source password, write failure, or other error makes the CLI exit nonzero, but a shell executing the documented lines continues to shred the passphrase file. Preserving the original encrypted key does not help if this was the only copy of its passphrase. Keep a secure independent copy; remove the unconditional destruction step and require successful migration and independent verification before any deliberate disposal. Add failure-path coverage and do not promise secure erasure on all storage.

2. **The CLI recovery procedure runs concurrently with the service despite using only a process-local lock.** `README.md:328-340` takes the CLI backup and re-protects keys before restarting the running service. `CertificateAuthorityService.cs:98,390` uses a static `SemaphoreSlim`, which does not coordinate the CLI process with the web service. During backup a concurrent pending-enrolment cancellation can delete a key after the database snapshot; during migration the server can retain an old in-memory passphrase or race lifecycle operations. The procedure should stop the service before the CLI backup and keep it stopped through migration and verification, or implement and validate real cross-process exclusion. Test interruption/failure and concurrent access rather than assuming the in-process lock covers both processes.

These are code/documentation findings; I have not reproduced the multi-process race against a live server. No production data was touched.

## Validation

- Linux, .NET SDK 10.0.113: `dotnet test -c Release --nologo -m:1` passed **76/76** tests.
- `git diff --check` passed. The PR head and base were unchanged when rechecked after testing.
- No full deployment, AD CS/CES interoperability test, or separate fault-injection test was performed.

The existing tests provide useful coverage for mismatched custody, restart, historical issuers, and migration. A passing suite does not exercise the documented failure/coordination scenarios above. The separate CA/CRL lifecycle work remains outside this review.

## Follow-up review — `086bc42a614b3999f4ea6bac9779b4676958b27c`

The original two findings have been addressed: the instructions retain the old passphrase and stop the service, and lifecycle operations now have cross-process locking. There is one remaining issue in the revised recovery procedure:

**A failed stop or backup does not prevent migration.** The stop, backup, initial custody check, and migration commands in `README.md:329-340` are separate shell commands. Only the final migration/verification/start sequence is conditional. When the block is pasted into a normal shell and stopping the service or taking the backup fails, execution continues into migration; the final command can succeed and make the overall block appear successful. A mocked execution of the exact README block reproduced this with a failed backup followed by migration and service start. No real service, key, or backup was touched.

Make successful service stop and backup prerequisites for the migration and start, with an explicit failure message and no migration on either failure. The initial custody verification can legitimately return nonzero in this mixed-passphrase recovery scenario, so handle that result intentionally rather than applying an indiscriminate `set -e` to the entire sequence. Add a test executing the documented shell flow with stubbed commands to verify failed stop/backup prevents migration, while an expected initial custody failure does not.

Linux validation of this follow-up: `dotnet test -c Release --nologo --no-restore -m:1` passed **78/78** tests. The mocked README execution reported backup failure, then migration and service start, with an overall success exit status.
