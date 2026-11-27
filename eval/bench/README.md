# Phase 4 benchmark: WordPress and Nextcloud, labelled by the CRS plugins

`eval/requests.jsonl` is labelled by us, on two apps we wrote. This set takes
its false-positive labels from the OWASP CRS project instead: the official
rule-exclusion plugins for WordPress and Nextcloud. Each request is sent
byte-for-byte through a CRS-only WAF and a CRS + plugin WAF. A CRS match that
the plugin removes is a false positive that the CRS maintainers have already
accepted for that application.

## Plugin pins

| Plugin | Release | Commit | Vendored in |
| --- | --- | --- | --- |
| [wordpress-rule-exclusions-plugin](https://github.com/coreruleset/wordpress-rule-exclusions-plugin) | v1.2.0 | `161bb90bb0d543f805fc6cd966a7c53a2e5b08de` | `lab/bench/plugins/wordpress/` |
| [nextcloud-rule-exclusions-plugin](https://github.com/coreruleset/nextcloud-rule-exclusions-plugin) | v1.8.1 | `7a61167690fd69af95b64e34d39c8737f4ddca96` | `lab/bench/plugins/nextcloud/` |

The `-config.conf` and `-before.conf` files are copied without changes, with
the plugin's Apache-2.0 LICENSE and a `SOURCE` file that records the URL,
commit and sha256 of each file. Neither plugin has an `-after.conf`. The
WordPress v1.2.0 files still say `ver:'wordpress-rule-exclusions-plugin/1.1.0'`
inside; that comes from upstream.

## How the plugins are loaded

CRS 4 loads plugins from its `plugins/` directory in three passes:
`*-config.conf`, then `*-before.conf` before the CRS rules, then
`*-after.conf` after them. The `owasp/modsecurity-crs:nginx-alpine` image has
that directory (`/opt/owasp-crs/plugins`, which ships with empty stub files).
At startup, its `94-activate-plugins.sh` uncomments the three `Include` lines
in `setup.conf` for each kind of file it finds. The compose file mounts the
plugin files read-only into that directory. We did not need any custom
`Include` rules or image changes.

## Lab

`lab/bench/docker-compose.yml`, compose project `waftuner-bench`:

| Service | Port | Purpose |
| --- | --- | --- |
| `waf-base` | 127.0.0.1:18280 | CRS 4.30, no plugins |
| `waf-wp` | 127.0.0.1:18281 | CRS + WordPress plugin |
| `waf-nc` | 127.0.0.1:18282 | CRS + Nextcloud plugin |
| `wordpress` | (internal) | `wordpress:7.1.5-php8.4-apache` |
| `mariadb` | (internal) | `mariadb:11.4.13` |
| `nextcloud` | (internal) | `nextcloud:35.0.3-apache`, SQLite |
| `wpcli` | (one-off, `tools` profile) | `wordpress:cli-2.12.0-php8.4` |

All three WAFs use the image and settings of `lab/docker-compose.capture.yml`:
DetectionOnly, paranoia level 2, inbound threshold 10, JSON Serial audit log,
`SecAuditLogParts ABCFHIJKZ`, and `SecAuditEngine On`, so every transaction is
logged. `SecAuditLogRelevantStatus` is also set to `^[1-5]`, so 200s would
still be logged under `RelevantOnly`. Every WAF routes `Host: wp.bench` to
WordPress and `Host: nc.bench` to Nextcloud
(`lab/bench/nginx/bench-hosts.conf.template`). Each WAF keeps its audit log on a
tmpfs, and `capture.py` reads it with `docker compose exec`. Nothing is written
to the host.

We used three WAFs instead of two. WordPress traffic goes through `waf-base`
and `waf-wp`, and Nextcloud traffic through `waf-base` and `waf-nc`. This way
each plugin only sees the application it was written for. One shared plugin WAF
would need a host-gating rule of our own, and the Nextcloud plugin's global
changes, such as widening `allowed_methods` for WebDAV, would leak into the
WordPress labels.

`lab/bench/setup.sh` installs both apps. For WordPress it uses wp-cli to run
`core install`, set pretty permalinks, and install the Twenty Twenty-One
classic theme (for the Customizer and Menus screens) and the Classic Editor
plugin (block editor stays the default; users may switch). For Nextcloud it
runs `occ maintenance:install --database=sqlite`, sets the trusted domain,
installs the calendar, contacts and notes apps, and adds a second user `bea`
for sharing. Only in the lab, it turns off Nextcloud brute-force protection
and rate limiting, so the attack set cannot lock out the admin. Theme, plugin
and app installs need internet access from the containers.

## Run it

```sh
docker compose -p waftuner-bench -f lab/bench/docker-compose.yml up -d
lab/bench/setup.sh
python3 eval/bench/capture.py     # sends the traffic, writes eval/bench/pairs.jsonl
python3 eval/bench/label.py       # writes eval/bench/requests.jsonl and summary.json
docker compose -p waftuner-bench -f lab/bench/docker-compose.yml --profile tools down -v
```

`capture.py --apps wordpress` (or `nextcloud`) captures one app.
`label.py --pairs ...` relabels without Docker. Lab passwords are throwaway
defaults (`bench-*-pass`). You can override them with `BENCH_WP_ADMIN_PASSWORD`,
`BENCH_NC_ADMIN_PASSWORD`, `BENCH_NC_SECOND_PASSWORD`, `BENCH_WP_DB_PASSWORD` and
`BENCH_DB_ROOT_PASSWORD`, using the same values for `setup.sh` and `capture.py`.
A trial run and the final run on a freshly built lab gave identical counts.

## Traffic

Everything is scripted with the Python standard library (`traffic_wordpress.py`
and `traffic_nextcloud.py`). Each request is built once and sent first to the
CRS-only WAF and then to the plugin WAF, with the same `X-Request-ID`. Only the
first response is used: it feeds the cookie jar and supplies nonces and ids.
Page and API loads between the scripted steps are sent through both WAFs too
(category `navigation`).

- **WordPress, benign (96 requests).**
  - An admin logs in and writes posts in the block editor (REST publish,
    autosave and an update with `X-HTTP-Method-Override`). The posts use code
    blocks, quotes, tables, Markdown, custom HTML and an embed.
  - The admin also writes posts in the classic editor (`post.php` form and
    heartbeat autosave) with Windows paths, JavaScript and SQL-ish prose.
  - Media uploads: REST multipart and the media library, with odd file names
    and caption edits.
  - Settings: General, Discussion word lists, permalinks and profile bio.
  - Customizer preview and save with custom CSS, a menu create, add-item and
    save, and a block widget saved through `/wp-json/batch/v1`.
  - REST calls: categories, tags, settings, link search, url-details and
    the oEmbed proxy.
  - Visitors: front-end search with SQL-looking phrases, and comments.
- **WordPress, attacks (33).**
  - SQLi, XSS and command injection in search.
  - SQLi in REST search and `orderby`.
  - XSS, SQLi, RCE, PHP and traversal payloads in comment fields.
  - SQLi in login, and traversal in `redirect_to` and an AJAX `file` argument.
  - SSRF through url-details and the oEmbed proxy.
  - Stored XSS, PHP and SQLi through block-editor autosave.
  - A PHP web-shell media upload, PHP code in the tagline, and command
    injection in heartbeat.
- **Nextcloud, benign (76).**
  - Web login, then WebDAV: PROPFIND, MKCOL, PUT, MOVE, COPY, PROPPATCH,
    REPORT, SEARCH and DELETE, with names like `O'Brien notes (v2).md`,
    `Q3 report [final] – 2026.csv` and `schema & seed.sql`. File contents
    include shell, SQL, PHP, CSV formulas and HTML.
  - A file comment, version and trash listings, and a download.
  - A Text editor session and save.
  - User and link shares with notes, and a share update.
  - Notes app create and edit (Markdown), CalDAV events, and CardDAV contacts
    and search.
  - Personal info, custom status and admin theming.
  - Unified search, OCS capabilities and recommendations, and the link-preview
    resolver.
  - A desktop sync client that uses Basic auth.
- **Nextcloud, attacks (26).**
  - Traversal in the WebDAV path, the `Destination` header and a legacy
    download.
  - PHP web shell and polyglot uploads, and an XXE PROPFIND.
  - SQLi in unified search, DAV SEARCH and login.
  - XSS in a share note, display name, note, file comment and contact.
  - Command injection in a calendar event, biography and note.
  - PHP code in the theming slogan, and PHP object injection in the headline.
  - SSRF through the reference resolver, the theming URL and the PDF viewer.

## Labels

`requests.jsonl` uses the record schema of `eval/requests.jsonl`, with
`source: "bench-capture"`, `app: "wordpress" | "nextcloud"`, and
`modsec_audit` holding the CRS-only WAF's record. `application_context` comes
from `profiles/*.json`. Each label gains `plugin_excluded`.

For each match in the CRS-only record (aggregate anomaly-score rules are
skipped, as in `eval/capture_lab.py`):

- **Benign request:** `expected: false_positive`. `plugin_excluded` is `true`
  when the same rule no longer matches the same input (rule id, plus the
  input after unwrapping `MATCHED_VARS`/`TX` copies) behind the plugin WAF.
  Otherwise it is `false`: an FP the plugin does not cover.
- **Attack request:** matches on the payload's input are `true_positive`.
  `plugin_excluded: true` means that the plugin suppresses that detection.
  Matches on other inputs stay unlabeled and are named in `notes`.
- **Response-phase rules:** `RESPONSE-*` rules (two matches: 953101 and
  950100) are skipped, because the two WAFs see different responses for
  state-changing requests.
- **Requests with no labeled match:** these are left out, as in
  `eval/requests.jsonl`. The counts below include them.

`pairs.jsonl` keeps both audit records for every request, so you can audit
any label. `summary.json` has the counts and the per-attack suppression list.

Lab passwords, the Basic-auth token, and the session cookie values
(`wordpress_*`, `wordpress_logged_in_*`, Nextcloud's instance session cookie
and `oc_sessionPassphrase`) are replaced with `REDACTED` everywhere in
`pairs.jsonl` and `requests.jsonl`. WordPress nonces and Nextcloud
`requesttoken`s are kept, because they are realistic inputs and became invalid
when the lab was torn down.

## Counts

| | WordPress | Nextcloud |
| --- | --- | --- |
| Requests sent (benign / attack) | 129 (96 / 33) | 102 (76 / 26) |
| Records in `requests.jsonl` (benign / attack) | 78 (45 / 33) | 78 (57 / 21) |
| Labeled matches | 608 | 244 |
| FP, plugin excludes it | 361 | 120 |
| FP, plugin does not cover it | 30 | 12 |
| TP | 217 | 112 |
| TP suppressed by the plugin | 115 | 38 |
| Attacks with at least one TP suppressed / all TPs suppressed | 22 / 12 | 11 / 6 |
| Attacks with no match on the payload (CRS miss) | 0 | 5 |

The two WAFs saw 0 matches that fired only with the plugin.

## Attacks the plugins suppress

These matter most. Applying the plugin's exclusions would hide these real
attacks. "All" means that nothing on the payload's input still fires behind
the plugin WAF.

| Attack (`id`) | Input | TPs suppressed | Rules suppressed |
| --- | --- | --- | --- |
| `wp-atk-xss-comment-0` | ARGS:comment | all 8 | 941100 941110 941160 941180 941320 941390 942131 942520 |
| `wp-atk-xss-comment-1` | ARGS:comment | all 9 | 932200 941100 941120 941160 941180 941390 942131 942520 |
| `wp-atk-sqli-comment-2` | ARGS:comment | all 7 | 942100 942190 942200 942260 942270 942440 942480 |
| `wp-atk-rce-comment-3` | ARGS:comment | all 6 | 931130 932130 932200 932220 932235 932250 |
| `wp-atk-php-comment-4` | ARGS:comment | all 3 | 933100 933130 933160 |
| `wp-atk-lfi-comment-5` | ARGS:comment | all 3 | 930100 930110 930120 |
| `wp-atk-xss-comment-author` | ARGS:author | all 10 | 933160 934100 941100 941120 941150 941160 941320 942340 942370 |
| `wp-atk-sqli-rest-search` | ARGS:search (`/wp-json/wp/v2/posts`) | all 10 | 942100 942190 942200 942260 942270 942360 942361 942362 942440 942480 |
| `wp-atk-xss-block-content-0` | ARGS:json.content | all 16 | 932200 941100 941110 941150 941160 941180 941181 941320 941340 942120 942131 942370 942430 942440 942520 |
| `wp-atk-php-block-content-1` | ARGS:json.content | all 14 | 932200 933100 933130 933150 933151 933160 934100 941180 941181 941390 942120 942370 942430 942440 |
| `wp-atk-sqli-block-content-2` | ARGS:json.content | all 15 | 930120 932200 932240 941180 941181 942120 942130 942190 942300 942370 942390 942430 942440 942480 942520 |
| `wp-atk-rce-heartbeat` | ARGS:data[wp_autosave][content] | all 3 | 930120 932160 932236 |
| `wp-atk-sqli-search-0` | ARGS:s | 2 of 10 | 942200 942360 |
| `wp-atk-xss-search-0` | ARGS:s | 1 of 8 | 942131 |
| `wp-atk-rce-search-0/1/2` | ARGS:s | 1 each | 932236 |
| `wp-atk-lfi-login-redirect` | ARGS:redirect_to | 1 of 4 | 920230 |
| `wp-atk-ssrf-url-details-0/1/2`, `wp-atk-ssrf-oembed` | ARGS:url | 1 each | 931130 |
| `nc-atk-xss-displayname` | ARGS:json.value | all 7 | 941100 941120 941150 941160 941180 941320 941390 |
| `nc-atk-xss-note` | ARGS:json.content | all 7 | 941100 941150 941160 941170 941210 941320 941390 |
| `nc-atk-xss-file-comment` | REQUEST_BODY (JSON `message`) | all 7 | 941100 941110 941160 941180 941320 941390 942131 |
| `nc-atk-rce-biography` | ARGS:json.value | all 3 | 932160 932200 932236 |
| `nc-atk-rce-note` | ARGS:json.content | all 4 | 931130 932235 932236 932370 |
| `nc-atk-php-headline-serialized` | ARGS:json.value | all 5 | 930120 933170 942180 942430 942520 |
| `nc-atk-lfi-dav-put-path` | REQUEST_FILENAME | 1 of 3 | 930130 |
| `nc-atk-ssrf-reference-0/1/2`, `nc-atk-ssrf-theming-url` | reference / json.value | 1 each | 931130 |

Notes:

- **Comments.** The WordPress plugin's own comment says that the comment field
  is not excluded. But v1.2.0 rule 9507120 removes `ARGS:comment`, `author`,
  `email` and `url` on `/wp-comments-post.php` from every OWASP_CRS rule, so
  unauthenticated comment attacks go through unseen.
- **Block-editor payloads.** These were sent as the admin. WordPress lets admins
  and editors post raw HTML (`unfiltered_html`), so they are attacks only under
  a compromised or hostile author threat model. The plugin trusts the author;
  a tool that mirrors it must say so.
- **Nextcloud profile fields and notes.** The plugin exempts them completely,
  so a stored-XSS payload in a display name, note or file comment is invisible
  behind it.

Attacks where CRS matched nothing on the payload's input (so no record; listed
in `summary.json`): `nc-atk-php-dav-webshell`, `nc-atk-php-dav-polyglot`,
`nc-atk-lfi-dav-xxe`, `nc-atk-xss-contact` and `nc-atk-rce-calendar-event`.
WebDAV PUT bodies (PHP, iCalendar, vCard) are not parsed into ARGS, and no CRS
rule fired on the PROPFIND's external-entity DTD. CRS only reported the method
(911100) or the content type (920420) on these requests.

## Caveats

- **`plugin_excluded` is the plugin's opinion.** An FP the plugin does not
  cover is still a false positive (benign traffic). A suppressed TP is the
  plugin trading detection for usability.
- **State-changing requests run twice.** One copy goes through each WAF. The
  second copy can get a different response (409 duplicate comment, 405 on
  MKCOL, 204 on a PUT overwrite). WordPress comment flood control returns 429
  for most comments, because they all come from one IP within seconds. The
  WAF still inspects each request in full; only response-phase rules depend on
  the response, and those are skipped.
- **Unlabeled matches in attack requests.** Matches on inputs other than the
  payload (for example 932236 on the comment form's `submit=Post Comment`, or
  911100 on WebDAV methods) are left unlabeled. The same FPs appear labeled in
  the benign requests.

## Files

- `benchlib.py`: dual-WAF HTTP client, cookie jar, multipart encoder, form
  parser, audit-log reader, scrubbing, and match and profile helpers.
- `traffic_wordpress.py`, `traffic_nextcloud.py`: the scripted traffic.
- `capture.py`, `label.py`: capture and labelling.
- `profiles/wordpress.json`, `profiles/nextcloud.json`: draft application
  profiles in the shape of `backend/services/lab_profiles.py`
  (`name, host_patterns, context, routes[{path, methods, parameters, notes}]`;
  cookies as `REQUEST_COOKIES:<name>`, headers as `REQUEST_HEADERS:<name>`,
  JSON fields as `json.<field>`).
- `pairs.jsonl`, `requests.jsonl`, `summary.json`: the outputs.

## Copied code

To stay independent of the `backend/` rewrite, this directory imports nothing
from `backend/` or `eval/`. `benchlib.py` has small copies of the following:

- from `backend/services/inference_context.py`: `_AGGREGATE_IDS`,
  `extract_match_target` and its two regexes;
- from `eval/capture_lab.py`: the `MATCHED_VARS`/`TX` unwrapping regex, the
  no-redirect handler and the browser headers;
- from `backend/services/profile_match.py`: the route ranking
  (`_route_score`).

`audit_matches()` lists matches in the same order as
`services.audit_event.normalize_audit_event`, so `match_index` lines up. This
was checked against the backend normalizer for all 156 records.
