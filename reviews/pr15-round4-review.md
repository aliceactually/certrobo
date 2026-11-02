# CertRobo PR #15 review, fourth pass — 2 November 2026

Reviewed head `36eb13d` on Linux. The previous duplicate-row status and attribution cases now have targeted fixes and coverage, and the background-test scan-count ordering has been corrected. The new serial-event implementation has two independently reproduced seed-path failures. Hold merge.

## 1. Seed can claim successful CRL publication while omitting the serial

`SeedRevokedSerialAsync` selects all numeric serial matches at `Services/CertificateAuthorityService.cs:2413-2422`. If the only matching row is `Pending`, `Failed`, or another non-issued status, the loop at `:2439-2452` does not mark it revoked, but the code still saves an event and publishes a CRL. `GenerateAndPersistCrlInternalAsync` builds entries only from `Status == Revoked` rows (`:3465-3476`), so the new event by itself is not included. The method nevertheless returns `CrlPublished=true`.

In the attached isolated test, a legitimate `Failed` issuance record has serial `00ABCD`; seeding legacy serial `ABCD` returns published success, but the returned CRL has no entry for that serial. This is operationally possible because the issuance workflow reserves a numeric serial before signing and retains a `Failed` row if signing fails. Preserve the failed issuance history, but ensure accepted seed intent has an independent authoritative revocation record that is actually included in the CRL, or reject the request clearly before claiming success. Cover Pending and Failed states, both identical and alternate serial encodings, and check the signed CRL plus pending-status display.

## 2. New seed commits before audit event and can silently leave an unpublished revocation

In the no-match branch at `:2474-2516`, the new revoked ledger row is committed by one `SaveChangesAsync`, followed by a separate save for the serial event. An event-insert failure or cancellation between these commits leaves a revoked row durable while the call throws before `TryPublishRevocationCrlCoreAsync` signals the worker or returns a pending result. The old CRL lacks the serial, and the background worker may remain on its normal long interval. This recreates the post-save ambiguity the PR was intended to fix.

The attached test uses a SQLite trigger to fail the event insert: the method throws, no wake is signalled, and the revoked row remains in the database. Save the ledger row and event atomically, including the generated ID, and distinguish failure before commit from accepted-but-pending publication after commit. Cover an actual database insert failure and cancellation/commit boundaries; don't use the in-CRL-generation injector as the only test.

## Reproduction

`pr15-round4-probes.patch` contains the two failing tests against `36eb13d`; apply to a disposable clean checkout with `git apply --unidiff-zero reviews/pr15-round4-probes.patch`, then run `dotnet test -c Release --filter FullyQualifiedName~ReviewRound4_`. Both independently fail as described. Tests use disposable SQLite databases and CAs; no production CA was touched.
