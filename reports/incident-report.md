# Joomla incident investigation

**Type:** Personal lab using the published BOTS v1 attack-only dataset  
**Incident date:** August 10, 2016  
**Affected application:** imreallynotbatman.com on 192.168.250.70  
**Scope:** HTTP and Suricata records

## Executive summary

The logs show web scanning and automated administrator password guessing, with Control Panel responses supporting administrator access against the Joomla application. Source 23.22.63.114 submitted 412 distinct password values for `admin` over approximately 90 seconds. A Control Panel response appeared during that activity, followed by another 45 recorded login POSTs over 10.61 seconds.

Source 40.80.148.42 produced scanner probes and IDS alerts, submitted an admin credential matching chronological candidate #319 in the other source's guessing burst, then received a Control Panel response and submitted obfuscated PHP as `agent.php` through the installer. Later requests from 23.22.63.114 returned content with the code's output marker, supporting web shell interaction.

## Investigation approach

I inventoried log types, grouped web traffic, inspected individual requests and returned content, and compared source/destination IPs and timestamps. I then compared submitted credentials across sources and tested detection searches against the recorded activity.

## Findings and evidence

### Web scanning

40.80.148.42 produced 20,882 HTTP records using the website name and 20,996 targeting the server across all Host values. Requests included unusual Joomla search input and Windows configuration-file paths such as `/windows/win.ini` and `/boot.ini`. The [request-pattern export](../evidence/native-exports/web-request-patterns.csv) contains the top ten method/path groups.

Suricata produced 538 alerts across 50 signature groups for the source/server pair. These included 45 Acunetix-related alerts, 103 script-tag alerts, and SQL-injection and XXE signatures. The [signature summary](../evidence/native-exports/suricata-alert-summary.csv) and [alert window](../evidence/native-exports/suricata-alert-window.csv) corroborate the HTTP probes.

Five HTTP records contain `acunetix_wvs_security_test` in code-like User-Agent probe strings ([native export](../evidence/native-exports/scanner-user-agent-evidence.csv)), providing a second source of evidence for Acunetix-related testing alongside the IDS signature.

### Password guessing and administrator access

The [login summary](../evidence/native-exports/admin-password-guessing-summary.csv) shows 412 POST records, all with a captured password value, and 412 globally distinct values for `admin`. The burst lasted 90.17 seconds, approximately 4.6 records per second. A separate status inspection found 411 redirects and one missing status; redirect status alone did not establish outcome.

At 21:46:40.781 UTC, the same source received HTTP 200 with the title `I'm Not Batman - Administration - Control Panel` ([native evidence](../evidence/native-exports/admin-control-panel-evidence.csv)), supporting administrator access during the guessing burst.

40.80.148.42 submitted one credential for admin at 21:48:05.858 UTC ([login summary](../evidence/native-exports/upload-source-login-summary.csv)). The exact submitted username/password pair also appeared once among 23.22.63.114's guesses ([comparison](../evidence/native-exports/credential-candidate-match.csv)). Approximately two seconds later, 40.80.148.42 received a Control Panel response at 21:48:07.844 UTC ([native evidence](../evidence/native-exports/upload-source-control-panel.csv)).

I numbered the 412 captured login POSTs in ascending event-time order and compared the matching value with the POST immediately before the burst source's first Control Panel response. The [native timing export](../evidence/native-exports/credential-access-timing.csv) and [reproducible search](../searches/credential-access-timing.spl) show:

| Recorded event | Chronological position | Time (UTC) | Relation to Control Panel response |
|---|---|---|---|
| Credential matching the uploader | #319 | 21:46:33.689 | 7.092589 seconds before |
| Immediately preceding login POST, with a different value | #367 | 21:46:40.729 | 0.052198 seconds before |
| Control Panel response | — | 21:46:40.781 | Administrator page returned |
| Last login POST | #412 | 21:46:51.395 | 10.613063 seconds after |

The matching credential was not the immediately preceding POST. Another 45 login POSTs were recorded after the Control Panel response. This is consistent with a tool continuing submissions after success, or with parallel/queued requests remaining in flight while an earlier request succeeded. The records do not establish the tool's threading or stop behavior. Candidate #319 could have authenticated an earlier session even though #367 is closer in recorded time; neither proximity nor the later POST count selects the successful credential.

I also compared #319's response with all other captured login responses ([native comparison](../evidence/native-exports/login-response-comparison.csv), [search](../searches/login-response-comparison.spl)). All 411 captured responses share status 303, redirect target `http://imreallynotbatman.com/joomla/administrator/index.php`, an identical 182-character response body (compared by SHA-256), and no captured Set-Cookie header, which may reflect a capture limitation rather than server behavior. This includes both #319 and #367. The missing response belongs to #7 at 21:45:21.325 UTC. These response characteristics do not distinguish #319 or identify which POST authenticated a session.

### Suspected PHP web shell

At 21:50:31.324 UTC, 40.80.148.42 submitted a multipart request containing `filename="agent.php"`, `installtype=upload`, and `task=install.install` to the Joomla installer. The response was 303. The [native upload export](../evidence/native-exports/agent-upload-payload.csv) preserves the event metadata and extracted 1,509-character PHP section.

Static reconstruction of the exported PHP removes inserted `5|` strings from concatenated literals. The resulting function body reads Referer and Accept-Language headers and evaluates decoded/decompressed input. Its output marker is assembled from `3481` and `9d7b`. The [static-analysis notes](../evidence/agent-static-analysis.md) document these web shell capabilities and reproducible reconstruction steps.

23.22.63.114 subsequently made 194 GET records to `/joomla/agent.php` between 21:55:22.673 and 22:21:34.767 UTC ([window](../evidence/native-exports/agent-activity-window.csv)). The [response summary](../evidence/native-exports/agent-response-summary.csv) has 193 records with status 200 and one missing status. There are 51 records with marker-wrapped content matching the submitted code and 143 without captured content. The matching code marker in responses from the uploaded path is the strongest evidence of web shell interaction.

## Timeline

All times below and in timed CSV exports are UTC on August 10, 2016.

| Time | Observation |
|---|---|
| 21:36:45.625 | First examined HTTP activity from 40.80.148.42 to the server |
| 21:36:48.131 | First examined Suricata alert for that pair |
| 21:45:21.226 | Password-guessing burst from 23.22.63.114 begins |
| 21:46:33.689 | Candidate #319 matches the credential later submitted by 40.80.148.42 |
| 21:46:40.729 | Candidate #367 immediately precedes the Control Panel, with a different value |
| 21:46:40.781 | Control Panel returned to 23.22.63.114 |
| 21:46:51.395 | Last POST in that burst |
| 21:48:05.858 | Matching admin credential submitted by 40.80.148.42 |
| 21:48:07.844 | Control Panel returned to 40.80.148.42 |
| 21:50:31.324 | agent.php submitted by 40.80.148.42 |
| 21:55:22.673 | First examined agent.php GET from 23.22.63.114 |
| 22:21:34.767 | Last examined agent.php GET from that source |
| 22:21:51.814 | Last examined scanner-source Suricata alert |
| 22:22:27.615 | Last examined scanner-source HTTP activity |

These are observed events within the searches, not necessarily the entire incident's boundaries.

## Detection test

The [detection](../searches/password-guessing-detection.md) groups administrator submissions by source, destination, account, and five-minute bucket. The unfiltered [bucket distribution](../evidence/native-exports/password-bucket-distribution.csv) has two qualifying buckets: 412 distinct submitted values and 1. Twenty is a provisional threshold separating them, not uniquely justified; any integer from 2 through 412 also separates these results. A threshold of 500 missed the known burst.

A second tested search correlates at least 20 distinct submitted values with a GET/200 Control Panel response from the same source/server in the same bucket. Its [native result](../evidence/native-exports/password-guessing-control-panel-correlation.csv) shows 23.22.63.114, 412 distinct values, admin, and one Control Panel response. It prioritizes guessing associated with administrator access. Retain the original guessing rule to detect bursts without captured Control Panel responses. Both searches are prototypes; the [tuning plan](../searches/password-guessing-detection.md#tuning-notes) describes normal-week measurements and treatment of shared NAT addresses and authorized tests.

## ATT&CK interpretation

| Technique | Evidence and assessment |
|---|---|
| [T1595.002: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | Varied probes, scanner-related signatures, and Acunetix test strings |
| [T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | 412 different submitted values for admin over about 90 seconds |
| [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Credential submission followed by privileged page responses |
| [T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/) | Exported PHP execution capability and matching output markers in later responses |

## Access-path assessment and recommended response

The observed sequence is consistent with credential-based administrator access: a guessing burst, a privileged response, and a second source submitting a matching value before receiving the same privileged page. The timing check identifies that value as chronological candidate #319 and separates it from the closest preceding POST, #367.

In a live environment, the observed administrator access and suspicious PHP submission would warrant escalation to the application owner and incident lead. Recommended actions include preserving logs and host evidence, restricting administrator access, invalidating compromised sessions, resetting affected credentials, and examining the web root and installed extensions. Recover and hash the PHP file, inspect web-service child processes and outbound traffic, and determine scope before recovery. These are proposed actions; none was performed in this lab.

## Limitations

- **Dataset and detection tuning:** Attack-only data cannot establish normal traffic baselines, an optimal threshold, or false-positive rates. Validation was historical; no scheduled live alert or response was deployed.
- **Capture and timing:** Some content and status fields are missing. Timestamps describe captured records, and candidate positions describe event-time order rather than password-list line numbers. Parallel or queued requests can complicate that order.
- **Authentication and attribution:** A Control Panel title shows that the page was served and supports access, but does not identify the session owner. Credential equality and timing do not establish which POST authenticated, how credentials were obtained or shared, or common control of both IPs. Authentication-session correlation was not completed.
- **Scanner identification:** Client-supplied strings and IDS patterns identify scanner-related probes. An exact scanner version and successful exploitation of a particular CVE were not verified.
- **Web shell and host impact:** Submitted code and matching response markers support web shell interaction. No server file was recovered and no complete host analysis was performed; specific commands, durable persistence, exfiltration, defacement, and lateral movement were not assessed.
- **Evidence provenance:** Exports are described in the [evidence notes](../evidence/README.md). Captured response comparisons can distinguish records without proving session ownership.



