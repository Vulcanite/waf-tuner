"""Seeded application profiles for the two lab apps (DVWA and the Flask Lab Shop).

Standard library only, so eval/ can import the same profile data the backend
seeds without SQLAlchemy.
"""
from __future__ import annotations

import copy
from types import SimpleNamespace

DEFAULT_LAB_PROFILE_NAME = "default-lab"
SHOP_LAB_PROFILE_NAME = "shop-lab"
SHOP_LAB_HOST = "shop.lab"

_ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

# The catch-all supplies general lab context. Draft eligibility requires
# documented semantics for the observed parameter on a specific route.
DEFAULT_LAB_ROUTES = [
    {
        "path": "/login.php",
        "methods": ["GET", "POST"],
        "parameters": {
            "username": "account username",
            "password": "account password",
            "user_token": "csrf token",
            "Login": "form submit",
        },
        "notes": "DVWA login. Credential fields are not SQL.",
    },
    {
        "path": "/security.php",
        "methods": ["GET", "POST"],
        "parameters": {
            "security": "DVWA security level",
            "seclev_submit": "form submit",
            "user_token": "csrf token",
        },
        "notes": "DVWA security-level form.",
    },
    {
        "path": "/setup.php",
        "methods": ["GET", "POST"],
        "parameters": {"create_db": "form submit", "user_token": "csrf token"},
        "notes": "DVWA database setup / reset.",
    },
    {
        "path": "/instructions.php",
        "methods": ["GET"],
        "parameters": {"doc": "name of a bundled documentation page (readme, PDF, changelog, copying)"},
        "notes": "DVWA instructions viewer.",
    },
    {
        "path": "/vulnerabilities/brute/",
        "methods": ["GET"],
        "parameters": {"username": "account username", "password": "account password", "Login": "form submit"},
        "notes": "DVWA brute-force lab; credentials are sent in the query string.",
    },
    {
        "path": "/vulnerabilities/csrf/",
        "methods": ["GET"],
        "parameters": {
            "password_new": "new account password",
            "password_conf": "new password confirmation",
            "Change": "form submit",
        },
        "notes": "DVWA CSRF lab: password change form.",
    },
    {
        "path": "/vulnerabilities/sqli/",
        "methods": ["GET", "POST"],
        "parameters": {"id": "user id lookup", "Submit": "form submit"},
        "notes": "DVWA SQL injection lab. Natural-language id values are search terms.",
    },
    {
        "path": "/vulnerabilities/sqli_blind/",
        "methods": ["GET", "POST"],
        "parameters": {"id": "user id lookup", "Submit": "form submit"},
        "notes": "DVWA blind SQL injection lab.",
    },
    {
        "path": "/vulnerabilities/xss_d/",
        "methods": ["GET"],
        "parameters": {"default": "preferred language name (English, French, Spanish, German)"},
        "notes": "DVWA DOM XSS lab: language picker.",
    },
    {
        "path": "/vulnerabilities/xss_r/",
        "methods": ["GET", "POST"],
        "parameters": {"name": "display name shown in greeting"},
        "notes": "DVWA reflected XSS lab. Names may include punctuation.",
    },
    {
        "path": "/vulnerabilities/xss_s/",
        "methods": ["GET", "POST"],
        "parameters": {
            "txtName": "guestbook author name",
            "mtxMessage": "guestbook message, may include sanitized markup",
            "btnSign": "form submit",
        },
        "notes": "DVWA stored XSS / guestbook lab.",
    },
    {
        "path": "/vulnerabilities/exec/",
        "methods": ["GET", "POST"],
        "parameters": {"ip": "host to ping", "Submit": "form submit"},
        "notes": "DVWA command-injection lab. ip is a hostname or address.",
    },
    {
        "path": "/vulnerabilities/fi/",
        "methods": ["GET"],
        "parameters": {"page": "local content page name"},
        "notes": "DVWA file-inclusion lab. page is a local include name, not a filesystem path.",
    },
    {
        "path": "/*",
        "methods": list(_ALL_METHODS),
        "parameters": {},
        "notes": "General lab context for paths without a documented route.",
    },
]

# Cookies the browser sends on every route. Non-credential ones are also listed
# in each specific route's parameters, because a cookie false positive only gets
# a copyable rule when the route documents the cookie name.
DEFAULT_LAB_COOKIES = {
    "security": "cookie: DVWA security level (low, medium, high or impossible)",
    "theme": "cookie: UI theme name such as dark or light",
    "lang": "cookie: UI language code such as en or fr",
    "prefs": "cookie: JSON UI preferences written by front-end script",
}

DEFAULT_LAB_CONTEXT = {
    "purpose": "OWASP DVWA lab application behind ModSecurity CRS",
    "languages": ["php"],
    "frameworks": ["dvwa"],
    "data_stores": ["mysql"],
    "web_server": "apache httpd + mod_php",
    "cookies": {"PHPSESSID": "PHP session id (credential)", **DEFAULT_LAB_COOKIES},
}

# Parameter names follow ModSecurity's naming: JSON body fields are ARGS:json.<field>.
SHOP_LAB_ROUTES = [
    {
        "path": "/",
        "methods": ["GET"],
        "parameters": {},
        "notes": "Storefront home page.",
    },
    {
        "path": "/search",
        "methods": ["GET"],
        "parameters": {
            "q": "free-text product search; shoppers type product names, phrases and punctuation",
            "category": "category slug: bags, apparel, stationery or kitchen",
            "sort": "sort key: relevance, price or name",
            "page": "result page number",
        },
        "notes": "Product search. q is bound as a parameter of a LIKE query; sort picks from a fixed column list.",
    },
    {
        "path": "/products/{product_id}",
        "methods": ["GET"],
        "parameters": {"product_id": "numeric product id (path segment)"},
        "notes": "Product detail page.",
    },
    {
        "path": "/reviews",
        "methods": ["POST"],
        "parameters": {
            "product_id": "numeric product id",
            "author": "reviewer display name",
            "rating": "integer rating 1-5",
            "body": "review text; Markdown and a small HTML subset (b, i, em, strong, code, pre, a, ul, li, "
                    "blockquote) are allowed and sanitized on render; code samples are common",
        },
        "notes": "Product reviews form.",
    },
    {
        "path": "/api/cart",
        "methods": ["POST"],
        "parameters": {
            "json.sku": "product SKU",
            "json.quantity": "integer quantity",
            "json.coupon": "promotion code, letters and digits",
            "json.gift_message": "free-text gift message printed on the packing slip",
        },
        "notes": "JSON API (application/json) that adds an item to the cart.",
    },
    {
        "path": "/download",
        "methods": ["GET"],
        "parameters": {
            "name": "download file name such as user-guide.v2.pdf; looked up in a fixed allowlist, "
                    "never joined to a filesystem path",
        },
        "notes": "File downloads by name.",
    },
    {
        "path": "/preview",
        "methods": ["POST"],
        "parameters": {"url": "http(s) URL the user wants a link card for; parsed, never fetched by the server"},
        "notes": "Link preview for a URL field.",
    },
    {
        "path": "/account/settings",
        "methods": ["GET", "POST"],
        "parameters": {
            "display_name": "public display name",
            "email": "account email address",
            "bio": "short profile bio; Markdown allowed",
            "website": "personal homepage URL",
            "timezone": "IANA timezone name such as Europe/London",
            "signature": "signature shown under reviews; may contain quotes or a code snippet",
        },
        "notes": "Profile and settings form.",
    },
    {
        "path": "/login",
        "methods": ["GET", "POST"],
        "parameters": {
            "username": "account username",
            "password": "account password",
            "next": "relative path to return to after sign-in",
        },
        "notes": "Sign-in form. Credentials are compared in Python, not in SQL.",
    },
    {
        "path": "/support",
        "methods": ["POST"],
        "parameters": {
            "subject": "support ticket subject",
            "message": "free-text support message; customers paste error messages, file paths, shell output and code",
            "order_id": "order reference such as ORD-2024-0042",
        },
        "notes": "Support ticket form.",
    },
    {
        "path": "/*",
        "methods": list(_ALL_METHODS),
        "parameters": {},
        "notes": "General Lab Shop context for paths without a documented route.",
    },
]

SHOP_LAB_COOKIES = {
    "cart_id": "cookie: opaque cart identifier (hex)",
    "currency": "cookie: display currency code such as USD",
    "prefs": "cookie: JSON UI preferences written by front-end script",
    "recent": "cookie: recent search phrases, |-separated, written by front-end script",
    "cart_note": "cookie: draft gift-wrap note saved by front-end script",
    "lang": "cookie: UI language code such as en or fr",
}

SHOP_LAB_CONTEXT = {
    "purpose": "Lab Shop: small Flask storefront (second lab app) behind ModSecurity CRS",
    "languages": ["python"],
    "frameworks": ["flask", "jinja2"],
    "data_stores": ["sqlite"],
    "web_server": "gunicorn",
    "cookies": {"session": "Flask signed session cookie (credential)", **SHOP_LAB_COOKIES},
}

def _with_cookies(routes: list[dict], cookies: dict[str, str]) -> list[dict]:
    """Add the site-wide cookies to every specific route; a route's own field keeps its meaning."""
    for route in routes:
        if route["path"] != "/*":
            route["parameters"] = {**cookies, **route["parameters"]}
    return routes


_with_cookies(DEFAULT_LAB_ROUTES, DEFAULT_LAB_COOKIES)
_with_cookies(SHOP_LAB_ROUTES, SHOP_LAB_COOKIES)

SEEDED_PROFILES = [
    {
        "name": DEFAULT_LAB_PROFILE_NAME,
        "host_patterns": ["*"],
        "context": DEFAULT_LAB_CONTEXT,
        "routes": DEFAULT_LAB_ROUTES,
    },
    {
        "name": SHOP_LAB_PROFILE_NAME,
        "host_patterns": [SHOP_LAB_HOST],
        "context": SHOP_LAB_CONTEXT,
        "routes": SHOP_LAB_ROUTES,
    },
]


def seed_metadata(name: str) -> dict:
    return {"seeded": True, "seed": name, "replace_with_operator_profile": True}


def seeded_profiles() -> list[SimpleNamespace]:
    """The seeded profiles as the backend stores them (ids in insertion order, version 1)."""
    return [
        SimpleNamespace(
            id=index,
            name=profile["name"],
            version=1,
            active=True,
            host_patterns=list(profile["host_patterns"]),
            context=copy.deepcopy(profile["context"]),
            routes=copy.deepcopy(profile["routes"]),
            source_metadata=seed_metadata(profile["name"]),
        )
        for index, profile in enumerate(SEEDED_PROFILES, start=1)
    ]
