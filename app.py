from flask import Flask, request, redirect, session, render_template_string
from pathlib import Path
from datetime import datetime
import json, secrets, hmac, hashlib, os

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("NEWS_DATA_FILE", str(BASE / "news-data" / "articles.json")))
PASSFILE = Path(os.environ.get("ADMIN_PASSWORD_FILE", str(BASE / "admin-password.txt")))
SECRETFILE = Path(os.environ.get("SECRET_KEY_FILE", str(BASE / "session-secret.txt")))

app = Flask(__name__)

if not SECRETFILE.exists():
    SECRETFILE.write_text(secrets.token_urlsafe(48))
    SECRETFILE.chmod(0o600)
app.secret_key = os.environ.get("SECRET_KEY") or SECRETFILE.read_text().strip()

if not PASSFILE.exists():
    PASSFILE.write_text(secrets.token_urlsafe(12) + "\n")
    PASSFILE.chmod(0o600)
    print("Admin password file created; keep it private.")

DATA.parent.mkdir(parents=True, exist_ok=True)
if not DATA.exists():
    DATA.write_text("[]", encoding="utf-8")

CATEGORIES = [
    "বাংলাদেশ", "আন্তর্জাতিক", "রাজনীতি", "সমাজ ও মানবাধিকার",
    "ধর্ম ও সম্প্রীতি", "অর্থনীতি", "প্রযুক্তি", "সংস্কৃতি"
]
STATUSES = {"draft", "published", "archived"}
STATUS_BN = {
    "draft": "খসড়া", "published": "প্রকাশিত", "archived": "আর্কাইভ"
}

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
    temp = DATA.with_suffix(".json.tmp")
    temp.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    temp.chmod(0o600)
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

PAGE = r"""
<!doctype html>
<html lang="bn"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BD INTERNATIONAL NEWS</title>
<style>
body{font-family:sans-serif;max-width:900px;margin:auto;padding:16px;background:#f2f5f8;color:#18212b}
header{background:#12304c;color:white;padding:20px;border-radius:12px}
section,article{background:white;padding:15px;margin:14px 0;border-radius:10px}
input,textarea,select,button{box-sizing:border-box;width:100%;padding:12px;margin:6px 0;font:inherit}
button{border:0;border-radius:7px;background:#12304c;color:white;cursor:pointer}
a{color:#075a9c}small,.muted{color:#526171}
hr{border:0;border-top:1px solid #ddd;margin:18px 0}
</style></head><body>
<header><h1>BD INTERNATIONAL NEWS</h1>
<p>বাংলাদেশ থেকে বিশ্ব, সত্যের সন্ধানে।</p></header>
<p><a href="/">হোম</a> · <a href="/login">অ্যাডমিন লগইন</a></p>
{% if message %}<section>{{ message }}</section>{% endif %}

{% if mode == "login" %}
<section><h2>অ্যাডমিন লগইন</h2>
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input type="password" name="password" placeholder="অ্যাডমিন পাসওয়ার্ড" required>
<button>লগইন</button></form></section>

{% elif mode == "admin" %}
<section><h2>নতুন সংবাদ যোগ করুন</h2>
<form method="post" action="/add">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="title" maxlength="200" placeholder="সংবাদের শিরোনাম" required>
<select name="category">{% for c in categories %}<option>{{ c }}</option>{% endfor %}</select>
<textarea name="body" rows="7" placeholder="সংবাদের বিস্তারিত" required></textarea>
<select name="status">
<option value="draft">খসড়া হিসেবে রাখুন</option>
<option value="published">প্রকাশ করুন</option>
<option value="archived">আর্কাইভ</option>
</select>
<button>সংবাদ সংরক্ষণ করুন</button></form>
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button>লগআউট</button></form></section>

<h2>সংবাদ ব্যবস্থাপনা ({{ items|length }})</h2>
{% for a in items %}
<article><small>{{ a.category }} · {{ a.date }} · {{ status_bn[a.status] }}</small>
<h3>{{ a.title }}</h3><p style="white-space:pre-wrap">{{ a.body }}</p>
<p><a href="/edit/{{ a.id }}">সংবাদ সম্পাদনা</a></p>
<form method="post" action="/status/{{ a.id }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<select name="status">
{% for s in ["draft","published","archived"] %}
<option value="{{ s }}" {% if a.status == s %}selected{% endif %}>{{ status_bn[s] }}</option>
{% endfor %}
</select><button>অবস্থা পরিবর্তন করুন</button></form>
<form method="post" action="/delete/{{ a.id }}" onsubmit="return confirm('এই সংবাদ মুছে ফেলবেন?')">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button>সংবাদ মুছুন</button></form></article>
{% else %}<article>এখনো কোনো সংবাদ যোগ করা হয়নি।</article>{% endfor %}

{% elif mode == "edit" %}
<section><h2>সংবাদ সম্পাদনা</h2>
<form method="post" action="/edit/{{ article.id }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="title" maxlength="200" value="{{ article.title }}" required>
<select name="category">
{% for c in categories %}<option {% if c == article.category %}selected{% endif %}>{{ c }}</option>{% endfor %}
</select>
<textarea name="body" rows="9" required>{{ article.body }}</textarea>
<select name="status">
{% for s in ["draft","published","archived"] %}
<option value="{{ s }}" {% if article.status == s %}selected{% endif %}>{{ status_bn[s] }}</option>
{% endfor %}
</select><button>পরিবর্তন সংরক্ষণ করুন</button></form>
<p><a href="/admin">অ্যাডমিন প্যানেলে ফিরুন</a></p></section>
{% endif %}

{% if mode != "admin" and mode != "edit" %}
<h2>সর্বশেষ প্রকাশিত সংবাদ</h2>
{% for a in items %}
<article><small>{{ a.category }} · {{ a.date }}</small>
<h2>{{ a.title }}</h2><p style="white-space:pre-wrap">{{ a.body }}</p></article>
{% else %}<article>এখনো কোনো সংবাদ প্রকাশিত হয়নি।</article>{% endfor %}
{% endif %}
<footer><small>BD INTERNATIONAL NEWS</small></footer>
</body></html>
"""

def page(mode, items=None, message="", article=None):
    context = {
        "mode": mode, "items": items or [], "message": message,
        "article": article, "categories": CATEGORIES,
        "statuses": STATUSES, "status_bn": STATUS_BN,
        "csrf": csrf_token()
    }
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
            return redirect("/admin")
        message = "পাসওয়ার্ড সঠিক নয়।"
    return page("login", message=message)

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
    if not title or not body:
        return "শিরোনাম ও বিস্তারিত আবশ্যক।", 400
    if category not in CATEGORIES:
        category = "বাংলাদেশ"
    if status not in STATUSES:
        status = "draft"
    items = articles()
    items.append({
        "id": secrets.token_hex(8), "title": title, "body": body,
        "category": category, "status": status,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M")
    })
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
        if not title or not body:
            return "শিরোনাম ও বিস্তারিত আবশ্যক।", 400
        article.update({
            "title": title, "body": body,
            "category": category if category in CATEGORIES else "বাংলাদেশ",
            "status": status if status in STATUSES else "draft"
        })
        save_articles(items)
        return redirect("/admin?message=পরিবর্তন+সংরক্ষিত")
    return page("edit", article=article)

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

if __name__ == "__main__":
    print("News portal: http://127.0.0.1:8081")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8081")), debug=False)
