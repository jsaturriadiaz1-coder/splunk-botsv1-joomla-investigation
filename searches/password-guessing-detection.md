# Joomla suspected password guessing

This detection prototype finds sources submitting at least 20 distinct password values for the same account and destination in a fixed five-minute bucket. It is scoped to the investigated server and Joomla administrator endpoint and counts captured submissions.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| spath path=http_method output=method
| spath path=uri_path output=request_path
| search destination_address="192.168.250.70" method="POST" request_path="/joomla/administrator/index.php"
| spath path=src_content output=form_data
| rex field=form_data "(?:^|&)username=(?<username>[^&]*)"
| rex field=form_data "(?:^|&)passwd=(?<password_candidate>[^&]*)"
| bin _time span=5m
| stats count as post_records dc(password_candidate) as distinct_passwords by _time source_address destination_address username
| where distinct_passwords>=20
```

## Historical tests

| Threshold | Observed result |
|---|---|
| 20 distinct values | Flagged 23.22.63.114 targeting admin, with 412 POST records and 412 distinct values in the bucket starting 2016-08-10 21:45 UTC |
| 500 distinct values | No results; missed the known 412-value burst |
| Restored to 20 | Known activity returned |

The [distribution without a threshold](../evidence/native-exports/password-bucket-distribution.csv) contains two qualifying account/source buckets for this endpoint: 412 distinct values and 1. Twenty separates those observed results, but any integer threshold from 2 through 412 would also do so. This is a provisional lab threshold, not evidence that 20 is optimal.

[Native result export](../evidence/native-exports/password-guessing-detection-results.csv). Bucket time is not the exact first attempt. The earlier investigation measured the burst at approximately 90 seconds.

## Correlation for prioritization

The following tested search requires both a password burst and a GET/200 Control Panel response from the same source/server in the same five-minute bucket. It returned 23.22.63.114 with 412 distinct values, account admin, and one Control Panel response ([native result](../evidence/native-exports/password-guessing-control-panel-correlation.csv)).

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| spath path=http_method output=method
| spath path=uri_path output=request_path
| spath path=status output=response_status
| spath path=src_content output=form_data
| spath path=dest_content output=response_body
| search destination_address="192.168.250.70" request_path="/joomla/administrator/index.php"
| rex field=form_data "(?:^|&)username=(?<username>[^&]*)"
| rex field=form_data "(?:^|&)passwd=(?<password_candidate>[^&]*)"
| rex field=response_body "(?i)<title>(?<page_title>[^<]*)</title>"
| eval login_password=if(method="POST",password_candidate,null())
| eval control_panel=if(method="GET" AND response_status=200 AND like(page_title,"%Control Panel%"),1,0)
| bin _time span=5m
| stats dc(login_password) as distinct_passwords values(username) as submitted_accounts sum(control_panel) as control_panel_responses by _time source_address destination_address
| where distinct_passwords>=20 AND control_panel_responses>0
```

This version aggregates password values across submitted accounts for each source/server bucket. It requires both behaviors in that bucket without enforcing their order. Keep the first rule too: requiring response evidence misses guessing without a captured Control Panel page. Single attempts using a known credential, such as the uploader's one submission, do not meet either burst threshold.

## Tuning notes

The attack-only dataset has just two qualifying account/source buckets, with 412 and 1 distinct values. That separation verifies the query against known activity but cannot tune a production rule. Twenty remains a lab placeholder.

Before deployment, I would:

1. Measure administrator login activity over a normal week, including busy periods. Where equivalent form telemetry is available, calculate distinct submitted values per source per hour for context and per source/account/five-minute bucket to match the rule. Compare the median, upper percentiles, maximum, request counts, and number of affected accounts. If password fields are unavailable, adapt the rule to authentication failures and attempts; do not assume distinct-password counts can be reproduced from ordinary access logs.
2. Review flagged buckets with the application owner. Measure alerts per day, confirmed suspicious events, benign retry patterns, extraction coverage, and investigation time. Select a threshold against that baseline, then validate it against the known attack and held-out traffic.
3. Identify shared NAT and proxy addresses. Several users can share one source IP, especially in the correlation rule that aggregates across accounts. Add account, session, or device context where available and check successful/failed authentication records before escalating. Avoid blanket exclusions for shared addresses.
4. Label authorized penetration tests using the approved source addresses, target assets, and test window. Route or suppress only the agreed activity during that window, retain the events, and expire the exception after the test.
5. Test bursts spanning bucket boundaries, low-rate and distributed guessing, and repeated attempts with one value. Compare a rolling-window variant and account-based aggregation. Check encoded-value normalization because the current regex counts submitted strings.

A live search also needs a recent time window, a schedule with sufficient overlap for delayed events, and alert deduplication by source/account/server. The [report limitations](../reports/incident-report.md#limitations) describe the evidence and validation boundaries.

