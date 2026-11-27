"""Lab Shop: a small Flask storefront that sits behind ModSecurity as a second lab app.

It exists so the WAF has a Python/Flask/SQLite target next to DVWA (PHP/MySQL).
The routes take believable input; responses are deliberately trivial. Nothing
here is intentionally vulnerable: SQL is parameterized, templates autoescape,
downloads come from a fixed allowlist, and the link preview never fetches.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from urllib.parse import urlsplit

from flask import Flask, abort, g, jsonify, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("SHOP_SECRET_KEY", "lab-shop-not-a-secret")

PRODUCTS = [
    (1, "Canvas tote bag", "bags", 1800),
    (2, "Union Station hoodie", "apparel", 5400),
    (3, "Select Committee notebook", "stationery", 900),
    (4, "Drop shoulder tee", "apparel", 2600),
    (5, "Stainless water bottle", "kitchen", 2200),
]
DOWNLOADS = {
    "user-guide.pdf": b"%PDF-1.4 lab shop user guide\n",
    "user-guide.v2.pdf": b"%PDF-1.4 lab shop user guide v2\n",
    "invoice-2024-03.pdf": b"%PDF-1.4 invoice\n",
    "price-list.csv": b"sku,name,price\n1,Canvas tote bag,18.00\n",
    "release-notes.txt": b"v1.2: faster checkout\n",
    "assets.tar.gz": b"\x1f\x8b lab archive\n",
}
USERS = {"shopper": "correct horse battery staple", "admin": "lab-admin"}

PAGE = """<!doctype html><title>Lab Shop</title>
<nav><a href="/">Home</a> <a href="/search">Search</a> <a href="/account/settings">Settings</a></nav>
<h1>{{ heading }}</h1>{% for line in lines %}<p>{{ line }}</p>{% endfor %}"""


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(":memory:")
        g.db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price_cents INTEGER)")
        g.db.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", PRODUCTS)
    return g.db


@app.teardown_appcontext
def close_db(_exc) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def page(heading: str, *lines: str, status: int = 200):
    return render_template_string(PAGE, heading=heading, lines=lines), status


@app.get("/")
def home():
    return page("Lab Shop", "Totes, hoodies and notebooks.")


@app.get("/search")
def search():
    q = request.args.get("q", "")
    category = request.args.get("category", "")
    sort = request.args.get("sort", "relevance")
    order = {"price": "price_cents", "name": "name"}.get(sort, "id")
    sql = f"SELECT name FROM products WHERE name LIKE ? AND (? = '' OR category = ?) ORDER BY {order}"
    rows = db().execute(sql, (f"%{q}%", category, category)).fetchall()
    return page(f"Results for {q!r}", *(row[0] for row in rows))


@app.get("/products/<int:product_id>")
def product(product_id: int):
    row = db().execute("SELECT name, price_cents FROM products WHERE id = ?", (product_id,)).fetchone()
    if row is None:
        abort(404)
    currency = request.cookies.get("currency", "USD")
    return page(row[0], f"{row[1] / 100:.2f} {currency}")


@app.post("/reviews")
def reviews():
    author = request.form.get("author", "anonymous")
    rating = request.form.get("rating", "5")
    body = request.form.get("body", "")
    return page("Thanks for your review", f"{author} rated product {request.form.get('product_id', '?')} {rating}/5", body)


@app.post("/api/cart")
def cart():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="expected a JSON object"), 400
    try:
        quantity = int(data.get("quantity", 1))
    except (TypeError, ValueError):
        return jsonify(error="quantity must be an integer"), 400
    response = jsonify(
        sku=str(data.get("sku", "")),
        quantity=quantity,
        coupon=str(data.get("coupon", "")),
        gift_message=str(data.get("gift_message", "")),
        status="added",
    )
    if "cart_id" not in request.cookies:
        response.set_cookie("cart_id", secrets.token_hex(8), httponly=True, samesite="Lax")
    return response


@app.get("/download")
def download():
    name = request.args.get("name", "")
    content = DOWNLOADS.get(name)
    if content is None:
        return page("Not found", f"No download named {name}", status=404)
    return content, 200, {"Content-Type": "application/octet-stream",
                          "Content-Disposition": f'attachment; filename="{name}"'}


@app.post("/preview")
def preview():
    # A real app would fetch the page for a link card. The lab never makes outbound requests.
    url = request.form.get("url", "")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return jsonify(error="unsupported URL"), 400
    return jsonify(url=url, host=parts.hostname, title=f"Preview of {parts.hostname}", fetched=False)


@app.route("/account/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        fields = ("display_name", "email", "bio", "website", "timezone", "signature")
        saved = {name: request.form.get(name, "") for name in fields}
        session["display_name"] = saved["display_name"]
        return page("Settings saved", *(f"{key}: {value}" for key, value in saved.items()))
    return page("Settings", f"Signed in as {session.get('user', 'guest')}")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("Sign in", "Use your Lab Shop account.")
    username = request.form.get("username", "")
    if USERS.get(username) != request.form.get("password", ""):
        return page("Sign in failed", status=401)
    session["user"] = username
    target = request.form.get("next", "/")
    return redirect(target if target.startswith("/") and not target.startswith("//") else "/")


@app.post("/support")
def support():
    subject = request.form.get("subject", "")
    return page("Ticket received", f"We will reply about {subject!r} soon.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
