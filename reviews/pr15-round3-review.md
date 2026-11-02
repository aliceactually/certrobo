# CertRobo PR #15 review, third pass — 2 November 2026

Reviewed PR head `6dc833683369ff91e22b5fa4e46c3017f5af38c3` on Linux. The two earlier problems have substantially improved: ledger rows are no longer deleted and post-save CRL failures are reported as pending with a worker wake. Hold merge for the remaining duplicate-serial cases below.

## 1. Equivalent ledger rows disagree with a published revocation

`RevokeCertificateAsync` in `Services/CertificateAuthorityService.cs:2289-2314` changes the selected row to `Revoked`, but only updates *already revoked* siblings. If two issued rows identify the same issuer and numeric serial, the CRL revokes that certificate by serial while the second row stays `Issued`; `Pages/Admin.razor:1298-1336` displays the second row in green and offers a Revoke button. The CRL is correct for that issuer/serial, but the administrative ledger is misleading.

Reproduced with the same actual PEM and thumbprint in two ledger records, the second serial encoded with a leading zero. After revoking the first, the CRL contains the serial and the second record remains `Issued`. The first `ReviewProbe_` test in the accompanying patch asserts truthful status and fails on the reviewed head. Do not silently delete either record; make all affected records/status displays consistent with the serial's actual revocation, preserve unrelated issuance metadata, and test both successful and pending publication paths. Consider how to handle genuinely conflicting certificates carrying the same issuer/serial: revocation is per issuer/serial, not per row.

## 2. Reconciliation overwrites prior revocation attribution

The sibling reconciliation loop at `Services/CertificateAuthorityService.cs:2308-2314` replaces each already-revoked sibling's `RevokedAtUtc`, `RevocationReasonCode`, and `RevokedByUserName` with the selected row's values. The seeder similarly overwrites those fields for all equivalent rows at `:2397-2409`. These fields record who revoked a certificate and when; retaining the row but silently rewriting its historical attribution is not preservation of that evidence. I did not find an independent audit trail for these mutations in the inspected code.

A second disposable probe starts with a sibling already revoked by `original-operator`, then revokes the other row as `admin`: the persisted sibling's actor becomes `admin`. Decide how to maintain one consistent CRL entry while retaining prior revocation evidence—for example, preserve original fields and maintain explicit per-serial publication state or an append-only audit event; surface genuine conflicts instead of silently rewriting history. Cover both revoke and seed, distinct actors/reasons/timestamps, and retries/publication failure. Avoid an unnecessarily broad redesign if a small, reliable solution preserves the evidence.

## Probes

`pr15-round3-probes.patch` contains two tests applied to a disposable checkout of `6dc8336`. Both independently failed as described. To reproduce, use a clean checkout and `git apply --unidiff-zero reviews/pr15-round3-probes.patch`, then `dotnet test -c Release --filter FullyQualifiedName~ReviewProbe_`. The tests use disposable CAs and SQLite databases; no live CA was touched.

## Background-worker test timing

During the full Linux suite, `ReviewFix_BackgroundService_WakesPromptlyOnPendingRevocationAndUnlock_AfterCleanScan` timed out in `WaitForCrlNumberAsync`; a separate isolated rerun passed. The helper queries the CRL and *then* captures the completed-scan count, so a scan can finish between those operations and leave it waiting for another scan after the worker has returned to its 30-minute idle interval. That is a plausible test race, not proof that production refresh failed. Capture the scan count before querying, or otherwise make the wait race-free, and retain an actual bounded assertion about the worker's behavior.

Full suite on this head: 88 passed, 1 failed (the timeout above), 89 total. The isolated rerun of that one test passed.
