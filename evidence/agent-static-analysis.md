# Static analysis of the submitted PHP

Source evidence: [native upload export](native-exports/agent-upload-payload.csv), one row containing 1,509 characters from `<?php` through `?>`. This is the PHP section captured in an HTTP submission, not a recovered server file.

## Reproduce the string reconstruction

1. Read the `php_payload` cell as text.
2. Locate the final assignment to `$L`. It concatenates the single-quoted values of `$d`, `$q`, `$e`, `$w`, `$a`, `$j`, `$Y`, `$Q`, `$o`, `$T`, `$B`, `$t`, `$N`, and `$c`, in that order.
3. Concatenate those literal strings and remove every `5|` occurrence, following the visible `str_replace` operation. The reconstructed function body has 941 characters.
4. Inspect the result as text. Executing the PHP is unnecessary for these observations.

## Observations

- `$kh="3481"` and `$kf="9d7b"` are combined as `$k=$kh.$kf`, producing `34819d7b`.
- The code reads `HTTP_REFERER` and `HTTP_ACCEPT_LANGUAGE`, parses URL query parameters and language-header components, and accumulates data in a PHP session.
- A decoding chain uses `base64_decode`, a custom XOR routine, `gzuncompress`, and `eval` to execute supplied PHP when the code's conditions are met.
- Output buffering captures output, then compression/XOR/Base64 encoding wraps the result between the key-based tags. The `<34819d7b>...</34819d7b>` marker matches content in the [agent response export](native-exports/agent-response-summary.csv).
- The surrounding wrapper reconstructs `create_function` by stripping `X` characters, builds the function from `$L`, and invokes it.

The execution chain identifies web shell capabilities; the matching response marker connects those capabilities to later requests. See the [report limitations](../reports/incident-report.md#limitations) for the remaining host and command-analysis boundaries.
