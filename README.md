# Browser Storage Inspector MCP

A local stdio tool for Chrome and Mullvad Browser. Each call exports one compact JSON snapshot to an owner-only file. The MCP reply includes the path, observed counts, coverage and errors. Node.js 24 or later is required. There are no package dependencies.

## Setup

Create a file named `.env` beside `server.mjs` with permissions `0600`. Set one or both profile paths. Use nonpersonal audit profiles. Chrome uses the user-data directory containing the Default profile. Mullvad uses the profile root shown in `about:profiles`.

```dotenv
BSI_CHROME_USER_DATA_DIR=/absolute/path/to/chrome-audit
BSI_MULLVAD_PROFILE_DIR=/absolute/path/to/mullvad-audit
BSI_PUBLIC_LABELS='["theme","audit_cookie","https://example.test","example.test","/"]'
```

The optional public-label list controls which exact site-authored strings can appear in a report, including names, domains, origins, cookie paths, worker scopes and partition labels. All others export as null. Keep only known public strings in this list. Counts, attributes and lengths work with an empty list. Snapshots default to the project's ignored `snapshots/` directory. Set `BSI_OUTPUT_DIR` to change it.

Register this stdio server in the MCP client. Substitute the actual absolute paths.

```json
{"mcpServers":{"browser-storage-inspector":{"command":"/absolute/path/to/node","args":["/absolute/path/to/browser-storage-inspector/server.mjs"]}}}
```

## Capture

For live inspection, start the audit browser yourself with its local debugging endpoint enabled. Chrome requires a dedicated non-default user-data directory. Keep it single-profile and use the Default profile. Mullvad accepts a separate Firefox-style profile directory. On macOS, for example:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --user-data-dir="/absolute/path/to/chrome-audit" --remote-debugging-port=0
"/Applications/Mullvad Browser.app/Contents/MacOS/mullvadbrowser" --no-remote --profile "/absolute/path/to/mullvad-audit" --remote-debugging-port 9223
```

The Mullvad profile directory must exist before launch. Use the same paths in the local configuration. Debugging grants local browser access, and a debugging session can affect browser fingerprinting. Keep these sessions separate from ordinary browsing. BSI connects to the endpoint advertised in the selected profile over loopback and releases its debugging session after each call.

Call **capture_storage_snapshot** with, for example:

```json
{"browser":"mullvad","capture_stage":"post_runtime"}
```

Use `chrome` or `mullvad`. Stages are `pre_runtime`, `runtime`, `post_runtime`, `post_restart`, and `manual` (default). Each stage labels the observation. Invoke post-runtime before closing the browser. A timestamp and UUID keep repeated exports distinct.

## Coverage

- Chrome reads cookies in the default browser context, including HttpOnly and partitioned cookies. The open HTTP(S) frames accessible through page targets supply local and session storage, IndexedDB, service workers and Cache Storage. Detached or out-of-process frames may be inaccessible.
- Mullvad reads open HTTP(S) contexts using WebDriver BiDi. Private mode can hide cookies from the BiDi cookie store. When a queried context returns no protocol cookies, BSI also observes script-visible cookie names and lengths. HttpOnly and cookies outside accessible contexts can be missing. Cookie counts from this fallback are observations by origin and URL path. Unknown cookie attributes stay null.
- Session storage uses snapshot-local tab numbers. Live IndexedDB records list object stores and read-only record counts. Worker records carry allowlisted scopes. Each cache has a name and nullable size. The live APIs used here do not expose individual cache sizes.
- With no accessible live endpoint, both backends inspect stable on-disk cookie metadata. Chrome encrypted value lengths stay null. Mullvad also reads persisted local-storage key metadata where available. Other offline stores are reported as unavailable. A closed private session may have left no inspectable data. The tool skips nonempty SQLite journals/WAL files to avoid writes or stale results.
- Each group has a status of `complete`, `partial` or `unavailable`. A summary of zero means the inspected scope yielded zero records. A null count means no inspection succeeded. Coverage codes such as `open_frames_only` and `persisted_view_only` identify limits. Counts measure groups' exported records, so IndexedDB counts databases and each store carries its own record count. Collection spans multiple reads and is not an atomic browser-wide transaction.
- Cookie lengths are bytes. Web Storage lengths are UTF-16 code units. Party type uses observed context where available. Browser-supplied values may pass through process memory during inspection. Reports and tool replies exclude raw values, browser session IDs, page URLs and underlying protocol errors.

Browser references: [Mullvad private browsing](https://mullvad.net/en/browser/hard-facts), [Chrome debugging requirements](https://developer.chrome.com/blog/remote-debugging-port), [WebDriver BiDi](https://w3c.github.io/webdriver-bidi/).
