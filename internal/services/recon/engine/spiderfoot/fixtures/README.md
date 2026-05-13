# SpiderFoot fixtures

JSON responses captured from a running `usulnet/recon-spiderfoot:4.0`
container against `example.com` with the `domain-surface` profile
(passive modules only). The capture script lives in
`scripts/recon/capture-spiderfoot-fixtures.sh` and is re-run whenever
the pinned SpiderFoot image is bumped.

Files:

- `scanstartlist_success.json`     — POST /scanstartlist happy path
- `scanstartlist_error.json`       — POST /scanstartlist with bad target
- `scanstatus_running.json`        — GET /scanstatus during the scan
- `scanstatus_finished.json`       — GET /scanstatus after FINISHED
- `scanstatus_aborted.json`        — GET /scanstatus after /scandelete
- `scanstatus_error_failed.json`   — GET /scanstatus after upstream failure
- `scaneventresults_partial.json`  — GET /scaneventresults mid-scan
- `scaneventresults_full.json`     — GET /scaneventresults after FINISHED
- `scandelete_success.json`        — POST /scandelete happy path

The `data` and `source_data` columns in the event fixtures are real
example.com responses — DNS records, the public root certificate,
publicly enumerated subdomains. They contain no personal data.
