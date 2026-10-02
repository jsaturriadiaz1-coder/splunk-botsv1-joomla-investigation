# Evidence

**Contains a real web shell sample from the BOTS v1 training dataset; do not execute it.**

I exported these CSVs directly from Splunk and preserved their contents. Password values and session cookies are not included. The agent response summary contains encoded response content from the historical training dataset. The upload export contains the extracted PHP as text evidence.

| File in native-exports | Purpose |
|---|---|
| web-request-patterns.csv | Top ten method/path groups for 40.80.148.42 to the server |
| suricata-alert-summary.csv | All 50 signature groups for the same source and server |
| http-activity-window.csv | Count and first/last HTTP activity for that pair |
| suricata-alert-window.csv | Count and first/last IDS alerts for that pair |
| admin-password-guessing-summary.csv | Password extraction coverage, distinct values, and timing |
| admin-control-panel-evidence.csv | Control Panel response to 23.22.63.114 |
| upload-source-control-panel.csv | Control Panel response to 40.80.148.42 |
| agent-response-summary.csv | All 194 agent.php GET records grouped by response status/content |
| agent-activity-window.csv | First/last of those requests |
| password-guessing-detection-results.csv | Output of the tested detection |
| upload-source-login-summary.csv | Single admin credential submission preceding the uploader's Control Panel response |
| credential-candidate-match.csv | Exact submitted-value comparison across both sources, without displaying the credential |
| credential-access-timing.csv | Chronological candidate #319 matches the uploader; #367 immediately precedes the Control Panel; 45 POSTs follow access |
| login-response-comparison.csv | #319 and #367 share response characteristics with all 411 captured responses; missing response is #7 |
| agent-upload-payload.csv | Upload metadata and the complete 1,509-character PHP section extracted from the request |
| password-bucket-distribution.csv | All qualifying account/source buckets for the endpoint, without a threshold |
| password-guessing-control-panel-correlation.csv | Guessing burst and Control Panel response from the same source in one bucket |
| scanner-user-agent-evidence.csv | Five User-Agent probe strings containing acunetix_wvs_security_test |

The [native upload export](native-exports/agent-upload-payload.csv) preserves the extracted PHP section and event metadata. It is a search result derived from the captured request, not a recovered file from the server. The [static-analysis notes](agent-static-analysis.md) explain how to check the code without executing it.

The [UTC correlation screenshot](correlation-utc.jpg) shows the tested search and its result: 412 distinct values and one Control Panel response for 23.22.63.114 in the 21:45 bucket.

Timed CSVs were exported from Splunk with a zero-offset account time zone. `_time` values include +0000; converted timestamp strings are UTC.

The [timing search](../searches/credential-access-timing.spl) numbers the 412 captured admin login POSTs from 23.22.63.114 in ascending event-time order. It compares credentials internally and exports only positions, match flags, timestamps, and counts. Candidate position describes recorded chronology, not a password-list line number. See the [report limitations](../reports/incident-report.md#limitations).

The [response comparison search](../searches/login-response-comparison.spl) uses the same ordering and groups all 412 records by status, redirect target, body length, body SHA-256, and presence of a Set-Cookie header. It exports #319, #367, and the record without a captured status. All 411 captured responses are identical in the compared fields. `Set-Cookie: absent` means the header was not found in the captured data; this may reflect a capture limitation and does not establish that the server omitted it. Cookie values and raw headers are excluded; other header differences are not assessed.


