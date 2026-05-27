"""
Traffic Generator — Phase 3

Three user classes simulating normal traffic (false positive triggers),
attack traffic (true positive triggers), and scanner noise.
"""
import io
import os
import random

from locust import HttpUser, task, between


TARGET_HOST = os.environ.get("TARGET_HOST", "http://nginx:8080")


class NormalUser(HttpUser):
    """
    Legitimate application traffic that triggers CRS false positives.
    Weight 70 — majority of traffic.
    """
    weight = 70
    wait_time = between(0.5, 2.0)

    @task(3)
    def search_fp_sqli(self):
        """Natural-language queries that trigger @detectSQLi false positives."""
        queries = [
            "select all products from category shoes",
            "drop down menu navigation help",
            "update my profile picture",
            "insert new item into wishlist",
            "union of all categories in store",
            "where can I find running shoes",
            "delete old wishlist items please",
            "select color filter for shirts",
        ]
        self.client.get(
            f"/search?q={random.choice(queries)}",
            name="/search (normal query)",
        )

    @task(2)
    def search_fp_generic(self):
        queries = [
            "best winter boots 2024",
            "compare laptop models",
            "how to return an item",
            "gift cards and promotions",
        ]
        self.client.get(f"/search?q={random.choice(queries)}", name="/search (generic)")

    @task(2)
    def comment_markdown(self):
        """Markdown comment — triggers XSS false positives."""
        bodies = [
            "This is **great** product! I love the <em>design</em>.",
            "Check out my review: <strong>5 stars</strong> ⭐",
            "The <a href='#'>link here</a> is helpful for reference.",
            "Use `code` blocks for **formatting** and <br/> line breaks.",
            "Here's an inline <script>-free comment about the product.",
        ]
        self.client.post(
            "/comment",
            json={"author": "reviewer", "body": random.choice(bodies)},
            name="/comment (markdown)",
        )

    @task(2)
    def login_special_chars(self):
        """Passwords with special chars — triggers SQLi/XSS false positives."""
        passwords = [
            "P@ssw0rd!#$",
            "my$ecure_Pass2024!",
            "hunter2!@#",
            "C0mpl3x&P@ss",
        ]
        self.client.post(
            "/login",
            data={"username": "alice", "password": random.choice(passwords)},
            name="/login (special chars)",
        )

    @task(1)
    def upload_file(self):
        """Small PNG upload — triggers binary content false positive."""
        # Minimal 1x1 PNG bytes
        png_bytes = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
            b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00'
            b'\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18'
            b'\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )
        self.client.post(
            "/upload",
            files={"file": ("test.png", io.BytesIO(png_bytes), "image/png")},
            name="/upload (png)",
        )

    @task(2)
    def api_users(self):
        self.client.get("/api/users", name="/api/users")

    @task(2)
    def api_data_nested(self):
        """Nested JSON with special chars."""
        payloads = [
            {"filter": "name LIKE '%select%'", "tags": ["<b>bold</b>", "normal"]},
            {"query": {"field": "content", "value": "it's a great day & sunny"}},
            {"search": "O'Reilly books on Python"},
            {"data": {"key": "value", "note": "Use & for 'and' in titles"}},
        ]
        self.client.post(
            "/api/data",
            json=random.choice(payloads),
            name="/api/data (nested)",
        )


class AttackUser(HttpUser):
    """
    Actual attack traffic — generates true positives.
    Weight 10.
    """
    weight = 10
    wait_time = between(2.0, 5.0)

    @task(3)
    def sqli_classic(self):
        payloads = [
            "1' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1; DROP TABLE users--",
            "' UNION SELECT username,password FROM users--",
        ]
        self.client.get(
            f"/search?q={random.choice(payloads)}",
            name="/search (SQLi)",
        )

    @task(2)
    def sqli_login(self):
        self.client.post(
            "/login",
            data={"username": "admin'--", "password": "x"},
            name="/login (SQLi)",
        )

    @task(2)
    def xss_search(self):
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
            "<svg onload=alert(1)>",
        ]
        self.client.get(
            f"/search?q={random.choice(payloads)}",
            name="/search (XSS)",
        )

    @task(1)
    def sqli_api(self):
        self.client.post(
            "/api/data",
            json={"key": "'; DROP TABLE users; --"},
            name="/api/data (SQLi)",
        )

    @task(1)
    def rce_attempt(self):
        self.client.get(
            "/search?q=;ls+-la+/etc/passwd",
            name="/search (RCE attempt)",
        )


class ScannerUser(HttpUser):
    """
    Automated scanner noise.
    Weight 20.
    """
    weight = 20
    wait_time = between(0.3, 1.0)

    @task(2)
    def scan_env_files(self):
        paths = ["/.env", "/.env.local", "/.env.production", "/config.php"]
        self.client.get(random.choice(paths), name="scanner /.env")

    @task(2)
    def scan_admin(self):
        paths = ["/wp-admin", "/wp-login.php", "/phpmyadmin", "/admin", "/administrator"]
        self.client.get(random.choice(paths), name="scanner /wp-admin")

    @task(2)
    def path_traversal(self):
        payloads = [
            "../../etc/passwd",
            "../../../etc/shadow",
            "..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        self.client.get(
            f"/search?q={random.choice(payloads)}",
            name="/search (path traversal)",
        )

    @task(1)
    def scan_backup_files(self):
        paths = ["/backup.zip", "/db.sql", "/database.sql", "/site.tar.gz"]
        self.client.get(random.choice(paths), name="scanner backup files")

    @task(1)
    def scan_git(self):
        paths = ["/.git/HEAD", "/.git/config", "/.svn/entries"]
        self.client.get(random.choice(paths), name="scanner .git")
