from flask import Flask, request, redirect, session, render_template_string, send_from_directory, url_for
from pathlib import Path
from datetime import datetime
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlparse
from functools import wraps
import json, secrets, hmac, hashlib, os, uuid

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("NEWS_DATA_FILE", str(BASE / "news-data" / "articles.json")))
PASSFILE = Path(os.environ.get("ADMIN_PASSWORD_FILE", str(BASE / "admin-password.txt")))
SECRETFILE = Path(os.environ.get("SECRET_KEY_FILE", str(BASE / "session-secret.txt")))
UPLOAD_FOLDER = Path(os.environ.get("UPLOAD_FOLDER", str(BASE / "uploads")))
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES + 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Render is HTTPS in production. This may be overridden for local testing.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "true" if os.environ.get("RENDER") else "false").lower() == "true"

if not SECRETFILE.exists():
    SECRETFILE.parent.mkdir(parents=True, exist_ok=True)
    SECRETFILE.write_text(secrets.token_urlsafe(48), encoding="utf-8")
    try:
        SECRETFILE.chmod(0o600)
    except OSError:
        pass
app.secret_key = os.environ.get("SECRET_KEY") or SECRETFILE.read_text(encoding="utf-8").strip()

# Keep the existing password login as a fallback; never expose the generated password.
if not PASSFILE.exists():
    PASSFILE.parent.mkdir(parents=True, exist_ok=True)
    PASSFILE.write_text(secrets.token_urlsafe(24) + "\n", encoding="utf-8")
    try:
        PASSFILE.chmod(0o600)
    except OSError:
        pass
    print("Admin password file created. Set ADMIN_PASSWORD in the hosting dashboard before relying on password login.")

DATA.parent.mkdir(parents=True, exist_ok=True)
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
if not DATA.exists():
    DATA.write_text("[]", encoding="utf-8")

CATEGORIES = [
    "বাংলাদেশ", "আন্তর্জাতিক", "রাজনীতি", "সমাজ ও মানবাধিকার",
    "ধর্ম ও সম্প্রীতি", "অর্থনীতি", "প্রযুক্তি", "সংস্কৃতি"
]
STATUSES = {"draft", "published", "archived"}
STATUS_BN = {"draft": "খসড়া", "published": "প্রকাশিত", "archived": "আর্কাইভ"}

# Google OAuth is enabled only when the required Render environment variables are configured.
oauth = OAuth(app)
GOOGLE_READY = bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET") and os.environ.get("ADMIN_EMAIL"))
if GOOGLE_READY:
    oauth.register(
        name="google",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


def articles():
    try:
        data = json.loads(DATA.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return []
        result = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            a = dict(item)
            a.setdefault("title", "")
            a.setdefault("body", "")
            a.setdefault("category", "বাংলাদেশ")
            a.setdefault("date", "")
            a.setdefault("status", "published")
            a.setdefault("image", "")
            a.setdefault("live_url", "")
            if a["status"] not in STATUSES:
                a["status"] = "published"
            if not a.get("id"):
                raw = f'{i}|{a["title"]}|{a["date"]}|{a["body"]}'
                a["id"] = hashlib.sha256(raw.encode()).hexdigest()[:16]
            result.append(a)
        return result
    except (ValueError, OSError):
        return []


def save_articles(items):
    DATA.parent.mkdir(parents=True, exist_ok=True)
    temp = DATA.with_suffix(".json.tmp")
    temp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        temp.chmod(0o600)
    except OSError:
        pass
    os.replace(temp, DATA)


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def csrf_valid():
    sent = request.form.get("csrf", "")
    saved = session.get("csrf", "")
    return bool(sent and saved and hmac.compare_digest(sent, saved))


def admin_required():
    return bool(session.get("admin"))


def valid_http_url(value):
    if not value:
        return ""
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return value.strip()


def save_uploaded_image(file_obj):
    if not file_obj or not file_obj.filename:
        return ""
    original = secure_filename(file_obj.filename)
    if "." not in original:
        raise ValueError("ছবির ফাইলের ধরন সমর্থিত নয়। JPG, PNG বা WEBP ব্যবহার করুন।")
    ext = original.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("শুধু JPG, PNG বা WEBP ছবি আপলোড করা যাবে।")
    file_obj.stream.seek(0, os.SEEK_END)
    size = file_obj.stream.tell()
    file_obj.stream.seek(0)
    if size > MAX_IMAGE_BYTES:
        raise ValueError("ছবির আকার ৫ MB-এর বেশি হতে পারবে না।")
    name = f"{uuid.uuid4().hex}.{ext}"
    UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    file_obj.save(UPLOAD_FOLDER / name)
    return f"/uploads/{name}"


PAGE = r"""
<!doctype html>
<html lang="bn"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BD INTERNATIONAL NEWS</title>
<style>
:root{color-scheme:light}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;max-width:960px;margin:auto;padding:14px;background:#f2f5f8;color:#18212b;line-height:1.65}
header{background:linear-gradient(120deg,#102b45,#1c5279);color:#fff;padding:20px;border-radius:14px}header h1{margin:0;font-size:clamp(1.45rem,5vw,2.2rem)}header p{margin:5px 0 0}
nav{margin:14px 0}section,article{background:#fff;padding:16px;margin:14px 0;border-radius:12px;box-shadow:0 2px 10px #102b4510}input,textarea,select,button{box-sizing:border-box;width:100%;padding:12px;margin:6px 0;font:inherit;border:1px solid #cbd5df;border-radius:8px}textarea{resize:vertical}button,.button{border:0;background:#123b5b;color:white;cursor:pointer;text-align:center;display:block;text-decoration:none;border-radius:8px;padding:12px;font-weight:650}button:hover,.button:hover{background:#1b5279}.google{background:#fff;color:#263746;border:1px solid #cbd5df}a{color:#075a9c}small,.muted{color:#526171}.news-image{display:block;max-width:100%;max-height:440px;object-fit:contain;border-radius:10px;margin:12px 0}.video-link{display:inline-block;margin:8px 0;padding:10px 13px;background:#b42318;color:white;text-decoration:none;border-radius:8px}hr{border:0;border-top:1px solid #ddd;margin:18px 0}.grid{display:grid;grid-template-columns:1fr;gap:8px}@media(min-width:640px){.grid{grid-template-columns:1fr 1fr}.span2{grid-column:1/-1}}.notice{background:#fff8e6;border:1px solid #f1d28a;padding:12px;border-radius:8px}
</style></head><body>
<header><h1>BD INTERNATIONAL NEWS</h1><p>বাংলাদেশ থেকে বিশ্ব, সত্যের সন্ধানে।</p></header>
<nav><a href="/">হোম</a> · <a href="/login">অ্যাডমিন লগইন</a></nav>
{% if message %}<section>{{ message }}</section>{% endif %}
{% if mode == "login" %}
<section><h2>অ্যাডমিন লগইন</h2>
{% if google_ready %}<p>আপনার অনুমোদিত Google অ্যাকাউন্ট দিয়ে প্রবেশ করুন।</p><a class="button google" href="/auth/google">Google দিয়ে লগইন করুন</a>{% else %}<p class="notice">Google লগইন চালু করতে Render Environment-এ GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET ও ADMIN_EMAIL সেট করতে হবে।</p>{% endif %}
<hr><p class="muted">বিকল্প পাসওয়ার্ড লগইন</p><form method="post" action="/login"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="password" name="password" placeholder="অ্যাডমিন পাসওয়ার্ড" required><button>পাসওয়ার্ড দিয়ে লগইন</button></form></section>
{% elif mode == "admin" %}
<section><h2>নতুন সংবাদ যোগ করুন</h2>
<form method="post" action="/add" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="title" maxlength="200" placeholder="সংবাদের শিরোনাম" required>
<select name="category">{% for c in categories %}<option>{{ c }}</option>{% endfor %}</select>
<textarea name="body" rows="7" placeholder="সংবাদের বিস্তারিত" required></textarea>
<label for="image"><strong>সংবাদের ছবি</strong> <small>(ফোনের গ্যালারি থেকে নির্বাচন করুন; সর্বোচ্চ ৫ MB)</small></label><input id="image" type="file" name="image" accept="image/jpeg,image/png,image/webp">
<label for="live_url"><strong>লাইভ টেলিকাস্ট লিংক</strong></label><input id="live_url" type="url" name="live_url" placeholder="https://www.youtube.com/live/...">
<select name="status"><option value="draft">খসড়া হিসেবে রাখুন</option><option value="published">প্রকাশ করুন</option><option value="archived">আর্কাইভ</option></select>
<button>সংবাদ সংরক্ষণ করুন</button></form>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button>লগআউট</button></form></section>
<h2>সংবাদ ব্যবস্থাপনা ({{ items|length }})</h2>
{% for a in items %}<article><small>{{ a.category }} · {{ a.date }} · {{ status_bn[a.status] }}</small><h3>{{ a.title }}</h3>
{% if a.image %}<img class="news-image" src="{{ a.image }}" alt="সংবাদের ছবি">{% endif %}<p style="white-space:pre-wrap">{{ a.body }}</p>{% if a.live_url %}<p><a class="video-link" href="{{ a.live_url }}" target="_blank" rel="noopener">▶ লাইভ/ভিডিও দেখুন</a></p>{% endif %}
<p><a href="/edit/{{ a.id }}">সংবাদ সম্পাদনা</a></p>
<form method="post" action="/status/{{ a.id }}"><input type="hidden" name="csrf" value="{{ csrf }}"><select name="status">{% for s in ["draft","published","archived"] %}<option value="{{ s }}" {% if a.status == s %}selected{% endif %}>{{ status_bn[s] }}</option>{% endfor %}</select><button>অবস্থা পরিবর্তন করুন</button></form>
<form method="post" action="/delete/{{ a.id }}" onsubmit="return confirm('এই সংবাদ মুছে ফেলবেন?')"><input type="hidden" name="csrf" value="{{ csrf }}"><button>সংবাদ মুছুন</button></form></article>
{% else %}<article>এখনো কোনো সংবাদ যোগ করা হয়নি।</article>{% endfor %}
{% elif mode == "edit" %}
<section><h2>সংবাদ সম্পাদনা</h2><form method="post" action="/edit/{{ article.id }}" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{ csrf }}">
<input name="title" maxlength="200" value="{{ article.title }}" required><select name="category">{% for c in categories %}<option {% if c == article.category %}selected{% endif %}>{{ c }}</option>{% endfor %}</select>
<textarea name="body" rows="9" required>{{ article.body }}</textarea>
{% if article.image %}<p>বর্তমান ছবি:</p><img class="news-image" src="{{ article.image }}" alt="বর্তমান ছবি">{% endif %}<label for="image"><strong>নতুন ছবি নির্বাচন (ঐচ্ছিক)</strong></label><input id="image" type="file" name="image" accept="image/jpeg,image/png,image/webp">
<label for="live_url"><strong>লাইভ টেলিকাস্ট লিংক</strong></label><input id="live_url" type="url" name="live_url" value="{{ article.live_url }}" placeholder="https://www.youtube.com/live/...">
<select name="status">{% for s in ["draft","published","archived"] %}<option value="{{ s }}" {% if article.status == s %}selected{% endif %}>{{ status_bn[s] }}</option>{% endfor %}</select><button>পরিবর্তন সংরক্ষণ করুন</button></form><p><a href="/admin">অ্যাডমিন প্যানেলে ফিরুন</a></p></section>
{% endif %}
{% if mode != "admin" and mode != "edit" %}<h2>সর্বশেষ প্রকাশিত সংবাদ</h2>{% for a in items %}<article><small>{{ a.category }} · {{ a.date }}</small><h2>{{ a.title }}</h2>{% if a.image %}<img class="news-image" src="{{ a.image }}" alt="সংবাদের ছবি">{% endif %}<p style="white-space:pre-wrap">{{ a.body }}</p>{% if a.live_url %}<p><a class="video-link" href="{{ a.live_url }}" target="_blank" rel="noopener">▶ লাইভ/ভিডিও দেখুন</a></p>{% endif %}</article>{% else %}<article>এখনো কোনো সংবাদ প্রকাশিত হয়নি।</article>{% endfor %}{% endif %}
<footer><small>BD INTERNATIONAL NEWS</small></footer></body></html>
"""


def page(mode, items=None, message="", article=None):
    context = {"mode": mode, "items": items or [], "message": message, "article": article,
               "categories": CATEGORIES, "statuses": STATUSES, "status_bn": STATUS_BN,
               "csrf": csrf_token(), "google_ready": GOOGLE_READY}
    return render_template_string(PAGE, **context)


@app.get("/")
def home():
    published = [a for a in articles() if a["status"] == "published"]
    published.sort(key=lambda a: a.get("date", ""), reverse=True)
    return page("home", published)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        if not csrf_valid():
            return "নিরাপত্তা যাচাই ব্যর্থ। পেজ রিফ্রেশ করে আবার চেষ্টা করুন।", 400
        supplied = request.form.get("password", "")
        saved = os.environ.get("ADMIN_PASSWORD") or PASSFILE.read_text(encoding="utf-8").strip()
        if hmac.compare_digest(supplied, saved):
            session.clear()
            session["admin"] = True
            session["auth_method"] = "password"
            return redirect("/admin")
        message = "পাসওয়ার্ড সঠিক নয়।"
    message = message or request.args.get("message", "")
    return page("login", message=message)


@app.get("/auth/google")
def google_login():
    if not GOOGLE_READY:
        return redirect("/login?message=Google+লগইন+এখনো+কনফিগার+করা+হয়নি")
    callback = os.environ.get("GOOGLE_REDIRECT_URI") or (request.url_root.rstrip("/") + "/auth/callback")
    return oauth.google.authorize_redirect(callback)


@app.get("/auth/callback")
def google_callback():
    if not GOOGLE_READY:
        return redirect("/login")
    try:
        token = oauth.google.authorize_access_token()
        user = token.get("userinfo") or oauth.google.userinfo()
    except Exception:
        return "Google লগইন সম্পন্ন করা যায়নি। OAuth সেটিংস ও Redirect URI যাচাই করুন।", 400
    email = str((user or {}).get("email", "")).strip().lower()
    verified = (user or {}).get("email_verified")
    allowed = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    if not email or email != allowed or verified is not True:
        session.clear()
        return "এই Google অ্যাকাউন্টটি অ্যাডমিন হিসেবে অনুমোদিত নয়।", 403
    session.clear()
    session["admin"] = True
    session["admin_email"] = email
    session["auth_method"] = "google"
    return redirect("/admin")


@app.get("/admin")
def admin():
    if not admin_required():
        return redirect("/login")
    items = sorted(articles(), key=lambda a: a.get("date", ""), reverse=True)
    return page("admin", items, request.args.get("message", ""))


@app.post("/add")
def add():
    if not admin_required():
        return redirect("/login")
    if not csrf_valid():
        return "নিরাপত্তা যাচাই ব্যর্থ।", 400
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    category = request.form.get("category", "বাংলাদেশ")
    status = request.form.get("status", "draft")
    live_url = valid_http_url(request.form.get("live_url", ""))
    if not title or not body:
        return "শিরোনাম ও বিস্তারিত আবশ্যক।", 400
    if live_url is None:
        return "লাইভ ভিডিওর লিংক অবশ্যই http:// অথবা https:// দিয়ে শুরু হতে হবে।", 400
    try:
        image_url = save_uploaded_image(request.files.get("image"))
    except ValueError as exc:
        return str(exc), 400
    if category not in CATEGORIES:
        category = "বাংলাদেশ"
    if status not in STATUSES:
        status = "draft"
    items = articles()
    items.append({"id": secrets.token_hex(8), "title": title, "body": body,
                  "category": category, "status": status,
                  "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                  "image": image_url, "live_url": live_url})
    save_articles(items)
    return redirect("/admin?message=সংবাদ+সংরক্ষিত")


@app.route("/edit/<article_id>", methods=["GET", "POST"])
def edit(article_id):
    if not admin_required():
        return redirect("/login")
    items = articles()
    article = next((a for a in items if a["id"] == article_id), None)
    if article is None:
        return "সংবাদ পাওয়া যায়নি।", 404
    if request.method == "POST":
        if not csrf_valid():
            return "নিরাপত্তা যাচাই ব্যর্থ।", 400
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        category = request.form.get("category", "বাংলাদেশ")
        status = request.form.get("status", "draft")
        live_url = valid_http_url(request.form.get("live_url", ""))
        if not title or not body:
            return "শিরোনাম ও বিস্তারিত আবশ্যক।", 400
        if live_url is None:
            return "লাইভ ভিডিওর লিংক অবশ্যই http:// অথবা https:// দিয়ে শুরু হতে হবে।", 400
        try:
            new_image = save_uploaded_image(request.files.get("image"))
        except ValueError as exc:
            return str(exc), 400
        article.update({"title": title, "body": body,
                        "category": category if category in CATEGORIES else "বাংলাদেশ",
                        "status": status if status in STATUSES else "draft",
                        "live_url": live_url})
        if new_image:
            article["image"] = new_image
        save_articles(items)
        return redirect("/admin?message=পরিবর্তন+সংরক্ষিত")
    return page("edit", article=article)


@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, max_age=3600)


@app.post("/status/<article_id>")
def change_status(article_id):
    if not admin_required():
        return redirect("/login")
    if not csrf_valid():
        return "নিরাপত্তা যাচাই ব্যর্থ।", 400
    status = request.form.get("status", "")
    if status not in STATUSES:
        return "অবস্থা সঠিক নয়।", 400
    items = articles()
    article = next((a for a in items if a["id"] == article_id), None)
    if article is None:
        return "সংবাদ পাওয়া যায়নি।", 404
    article["status"] = status
    save_articles(items)
    return redirect("/admin?message=অবস্থা+পরিবর্তিত")


@app.post("/delete/<article_id>")
def delete(article_id):
    if not admin_required():
        return redirect("/login")
    if not csrf_valid():
        return "নিরাপত্তা যাচাই ব্যর্থ।", 400
    items = articles()
    updated = [a for a in items if a["id"] != article_id]
    if len(updated) == len(items):
        return "সংবাদ পাওয়া যায়নি।", 404
    save_articles(updated)
    return redirect("/admin?message=সংবাদ+মুছে+ফেলা+হয়েছে")


@app.post("/logout")
def logout():
    if not admin_required():
        return redirect("/login")
    if not csrf_valid():
        return "নিরাপত্তা যাচাই ব্যর্থ।", 400
    session.clear()
    return redirect("/")


@app.errorhandler(413)
def too_large(_error):
    return "আপলোড করা ফাইলটি খুব বড়। সর্বোচ্চ ৫ MB-এর ছবি ব্যবহার করুন।", 413


if __name__ == "__main__":
    print("News portal: http://127.0.0.1:8081")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8081")), debug=False)
