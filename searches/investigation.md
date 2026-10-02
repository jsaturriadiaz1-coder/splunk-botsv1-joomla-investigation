# Investigation searches

Run each block separately. These searches reproduce my investigation of historical BOTS v1 data. Explicit time bounds include the 2016 records; they are not live alert time windows. Set the Splunk account time zone to a fixed zero-offset option before exporting timed results.

## 1. Inventory and discovery

Find available log types before choosing evidence sources.

```spl
index=botsv1 earliest=0 latest=now
| stats count by sourcetype
| sort - count
```

Identify high-volume source/server/website combinations. Volume is a lead, not proof of an attack.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| spath path=site output=website
| stats count by source_address destination_address website
| sort - count
| head 10
```

## 2. Request patterns

Summarize one source's method/path combinations. Run with 40.80.148.42 for scanning and replace that address with 23.22.63.114 for the second source. Groups with missing method/path values may be omitted.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| search source_address="40.80.148.42" destination_address="192.168.250.70"
| spath path=http_method output=method
| spath path=uri_path output=request_path
| stats count by method request_path
| sort - count
| head 10
```

## 3. Suricata alerts

Separate alerts from flow records and summarize every matching signature.

```spl
index=botsv1 earliest=0 latest=now sourcetype=suricata
"40.80.148.42" "192.168.250.70"
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| spath path=event_type output=record_type
| spath path=alert.signature output=signature_name
| search source_address="40.80.148.42" destination_address="192.168.250.70" record_type="alert"
| stats count by signature_name
| sort - count
```

## 4. Password-guessing coverage and timing

Inspect POST events first to discover form fields. Then capture account/password values and count distinct submitted strings without displaying passwords in the output.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| search source_address="23.22.63.114" destination_address="192.168.250.70"
| spath path=http_method output=method
| spath path=uri_path output=request_path
| search method="POST" request_path="/joomla/administrator/index.php"
| spath path=src_content output=form_data
| rex field=form_data "(?:^|&)username=(?<username>[^&]*)"
| rex field=form_data "(?:^|&)passwd=(?<password_candidate>[^&]*)"
| stats count as post_records count(password_candidate) as records_with_password dc(password_candidate) as distinct_passwords min(_time) as first_seen max(_time) as last_seen by username
| eval duration_seconds=round(last_seen-first_seen,2)
| convert ctime(first_seen) ctime(last_seen)
```

## 5. Control Panel evidence

Inspect returned page titles rather than inferring login outcome from redirects. Repeat with 40.80.148.42 to investigate access before its upload submission.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| search source_address="23.22.63.114" destination_address="192.168.250.70"
| spath path=http_method output=method
| spath path=uri_path output=request_path
| search method="GET" request_path="/joomla/administrator/index.php"
| spath path=dest_content output=response_body
| rex field=response_body "(?i)<title>(?<page_title>[^<]*)</title>"
| search page_title="*Control Panel*"
| spath path=status output=response_status
| table _time source_address destination_address method request_path response_status page_title
```

The upload-source export uses the same search with the other source and a table omitting method/path columns.

## 6. Upload inspection

Search POST bodies across all sources because the uploader is not established beforehand. Inspect each matching event's time, addresses, status, headers, and multipart content. This returns raw historical content, not a recovered file or an instruction to execute the PHP.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| spath path=http_method output=method
| spath path=src_content output=submitted_data
| search destination_address="192.168.250.70" method="POST"
| search submitted_data="*agent.php*"
| head 5
```

## 7. Agent responses

Compare all matching GET responses, preserving missing values as a labeled group.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| search source_address="23.22.63.114" destination_address="192.168.250.70"
| spath path=http_method output=method
| spath path=uri_path output=request_path
| search method="GET" request_path="/joomla/agent.php"
| spath path=status output=response_status
| spath path=dest_content output=response_body
| fillnull value="not captured" response_status response_body
| stats count by response_status response_body
| sort - count
```

For the agent activity-window export, replace the last five lines (starting with status extraction) with:

```spl
| stats count min(_time) as first_seen max(_time) as last_seen
| convert ctime(first_seen) ctime(last_seen)
```

For the scanner HTTP window, keep only the base HTTP search, source/destination extraction and filter for 40.80.148.42, then append those same two lines. For the Suricata alert window, use search 3, remove signature extraction, and replace its stats/sort lines with these two lines. No head limit should precede a full activity-window measurement.

## 8. Behavioral detection

See [the password-guessing detection](password-guessing-detection.md) for the source-independent search, test results, and tuning limits.

## 9. Credential match across sources

Compare exact submitted account/password values without displaying passwords. A match supports a credential connection, not attribution or proof of how the credential was obtained.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| search destination_address="192.168.250.70" (source_address="40.80.148.42" OR source_address="23.22.63.114")
| spath path=http_method output=method
| spath path=uri_path output=request_path
| search method="POST" request_path="/joomla/administrator/index.php"
| spath path=src_content output=form_data
| rex field=form_data "(?:^|&)username=(?<username>[^&]*)"
| rex field=form_data "(?:^|&)passwd=(?<password_candidate>[^&]*)"
| stats count(eval(source_address="23.22.63.114")) as guessing_source_records count(eval(source_address="40.80.148.42")) as upload_source_records by username password_candidate
| where upload_source_records>0
| eval matches_guessing_candidate=if(guessing_source_records>0,"yes","no")
| table username upload_source_records guessing_source_records matches_guessing_candidate
```

For the uploader's own login summary, rerun search 4 with source 40.80.148.42. Only POSTs with an extracted username appear in the grouped summary; this is not a count of every administrator POST.

## 10. Native PHP payload export

Preserve the extracted PHP section and upload metadata without request headers or cookies.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| spath path=http_method output=method
| spath path=uri output=request_uri
| spath path=status output=response_status
| spath path=src_content output=submitted_data
| search destination_address="192.168.250.70" method="POST" submitted_data="*agent.php*"
| rex field=submitted_data "filename=\"(?<submitted_filename>[^\"]+)\""
| rex field=submitted_data "(?s)(?<php_payload><\?php.*?\?>)"
| search submitted_filename="agent.php"
| eval payload_characters=len(php_payload)
| table _time source_address destination_address request_uri response_status submitted_filename payload_characters php_payload
```

## 11. Password-count distribution

Use the first detection query, add `| where isnotnull(username) AND isnotnull(password_candidate)` immediately before `bin`, and replace the threshold line with `| sort 0 - distinct_passwords`. This preserves every qualifying bucket rather than only detections.

## 12. Scanner-related User-Agent content

Check whether HTTP headers corroborate the Acunetix-related IDS signature.

```spl
index=botsv1 earliest=0 latest=now sourcetype=stream:http
| spath path=src_ip output=source_address
| spath path=dest_ip output=destination_address
| search source_address="40.80.148.42" destination_address="192.168.250.70"
| spath path=http_user_agent output=user_agent
| search user_agent="*Acunetix*"
| stats count by user_agent
| sort 0 - count
```

## 13. Credential position and access timing

Run [credential-access-timing.spl](credential-access-timing.spl). It compares the uploader's captured credential with the burst source's login POSTs, numbers those POSTs in event-time order, and selects both the matching value and the POST immediately before the first Control Panel response. It also counts later POSTs and measures how long submissions continued. Password values are excluded from the result table.

The [native export](../evidence/native-exports/credential-access-timing.csv) contains two rows: candidate #319 matches the uploader, while #367 immediately precedes the Control Panel and does not match. There are 45 subsequent POSTs, ending 10.613063 seconds after the Control Panel response. Positions refer to recorded login POST chronology. The search checks event order and equality; session attribution requires additional evidence, as described in the [report limitations](../reports/incident-report.md#limitations).

## 14. Compare login responses

Run [login-response-comparison.spl](login-response-comparison.spl) to compare #319 and #367 with the other login responses and identify the record with missing status. The search computes response groups across all 412 candidates before selecting those three records. It compares status, redirect target, response-body length and SHA-256, and presence of a Set-Cookie header, without exporting passwords or cookie values.

The [native comparison](../evidence/native-exports/login-response-comparison.csv) shows that #319 and #367 belong to the same 411-record group: status 303, the administrator index redirect target, identical 182-character response bodies, and no captured Set-Cookie header. The header's absence may reflect a capture limitation rather than server behavior. The record with missing response data is #7. These fields do not isolate a successful login; other headers and authentication-session continuity are not assessed by this search.
