


# ---- Imports (keep one of each; no duplicates) ----
import os
from datetime import datetime
from io import BytesIO
import smtplib
from email.message import EmailMessage
from functools import wraps

from flask import Flask, request, session, redirect, url_for, render_template, flash, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import func
from werkzeug.utils import secure_filename
from PIL import Image
from flask import send_from_directory
import csv
import urllib.request

def require_perm(perm_name):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                nxt = request.full_path if request.query_string else request.path
                return redirect(url_for("login", next=nxt))

            # IMPORTANT: use the existing db.session and model classes
            u = db.session.get(User, int(uid))  # SQLAlchemy 2.0 style
            if not u:
                flash("Please log in again.")
                return redirect(url_for("login"))

            # Admins bypass checks
            if (u.role or "").lower() == "admin":
                return fn(*args, **kwargs)

            if not u.has_perm(perm_name):
                flash("You don't have permission to do that.")
                return redirect(url_for("home"))

            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ---- Flask app setup ----
app = Flask(__name__)
app.secret_key = "change-me"  # TODO: put a strong secret here
# --- Money formatting helper ---
@app.template_filter("money")
def money_filter(cents):
    """Convert cents to $1,234.56 format for templates"""
    if cents is None:
        return ""
    return f"${cents/100:,.2f}"

# ---- Paths & Database (ABSOLUTE path so we always hit the same DB) ----
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "flashbidz.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---- File uploads ----
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}

# ---- Barcode helpers ----
from barcode import Code128
from barcode.writer import ImageWriter

BARCODE_DIR = os.path.join(BASE_DIR, "static", "barcodes")
os.makedirs(BARCODE_DIR, exist_ok=True)

def barcode_path_for(sku: str) -> str:
    safe = "".join(ch for ch in sku if ch.isalnum() or ch in "-_")
    return os.path.join(BARCODE_DIR, f"{safe}.png")

def ensure_barcode_png(sku: str) -> str:
    """Generate barcode PNG for the SKU if it doesn't exist. Returns file path."""
    path = barcode_path_for(sku)
    if os.path.exists(path):
        return path
    Code128(sku, writer=ImageWriter()).save(path[:-4])  # python-barcode auto-adds .png
    if not os.path.exists(path):
        if os.path.exists(path + ".png"):
            os.rename(path + ".png", path)
    return path

@app.get("/barcode/<sku>.png")
def barcode_png(sku):
    """Serve (and lazily generate) the barcode image for a SKU."""
    if not sku:
        abort(404)
    ensure_barcode_png(sku)
    return send_from_directory(BARCODE_DIR, os.path.basename(barcode_path_for(sku)))


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
@app.template_filter("money")
def money_filter(cents):
    if cents is None:
        return ""
    return f"${cents/100:,.2f}"

# ---- Mail defaults (admin page can override) ----
app.config.setdefault("MAIL_FROM", None)
app.config.setdefault("MAIL_SMTP", "smtp.gmail.com")
app.config.setdefault("MAIL_PORT", 587)
app.config.setdefault("MAIL_USERNAME", None)
app.config.setdefault("MAIL_PASSWORD", None)
app.config.setdefault("MAIL_USE_TLS", True)

# ---- Business defaults ----
app.config.setdefault("CONSIGNOR_RATE", 0.65)

# ---- DB handle ----
db = SQLAlchemy(app)

# ---------------------------
# GLOBAL LOGIN REQUIREMENT
# ---------------------------


@app.before_request
def _require_login_globally():
    # Allow static files (CSS/JS/images)
    if request.path.startswith("/static/"):
        return
    # Sometimes there's no endpoint (404 etc.)
    if request.endpoint is None:
        return
    # Allow GET /login and POST /login
    allowed = {"login", "login_post", "static",
           "consignors_list", "admin_view", "statements_index"}
    # If logged in, allow anything
    if session.get("user_id"):
        return
    # Otherwise force login, preserving destination
    if request.endpoint not in allowed:
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))
    # role-based restriction: only admins can access /admin* and /users*
    if request.path.startswith("/admin") or request.path.startswith("/users"):
        if session.get("role") != "admin":
            flash("Admin access required")
            return redirect(url_for("home"))

# ---------------------------
# DATABASE MODELS
# ---------------------------

# ---------------------------
# DATABASE MODELS (canonical)
# ---------------------------
from datetime import datetime
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username  = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="staff")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_perm(self, perm):
        if (self.role or "").lower() == "admin":
            return True
        staff_perms  = {"items:view","items:add","items:edit","reports:view","data:import","data:export"}
        viewer_perms = {"items:view"}
        role = (self.role or "").lower()
        if role == "staff":
            return perm in staff_perms
        if role == "viewer":
            return perm in viewer_perms
        return False

# ↓ Paste require_perm HERE (after User is defined)
def require_perm(perm_name):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                nxt = request.full_path if request.query_string else request.path
                return redirect(url_for("login", next=nxt))

            u = db.session.get(User, int(uid))
            if not u:
                flash("Please log in again.")
                return redirect(url_for("login"))

            if (u.role or "").lower() == "admin":
                return fn(*args, **kwargs)

            if not u.has_perm(perm_name):
                flash("You don't have permission to do that.")
                return redirect(url_for("home"))

            return fn(*args, **kwargs)
        return wrapper
    return decorator

    # NEW: comma-separated permissions string, e.g. "items:view,items:add,reports:view"
    permissions = db.Column(db.String(255), nullable=False, default="")

    def set_password(self, raw: str):
        from werkzeug.security import generate_password_hash
        try:
            self.password_hash = generate_password_hash(raw, method="scrypt")
        except Exception:
            self.password_hash = generate_password_hash(raw, method="pbkdf2:sha256")

    def check_password(self, raw: str) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, raw)

    # ---- Permission helpers ----
    def _perm_set(self):
        return set(p.strip() for p in (self.permissions or "").split(",") if p.strip())

    def has_perm(self, perm):
        # admins can do everything
        if (self.role or "").lower() == "admin":
            return True

        staff_perms  = {"items:view", "items:add", "items:edit", "reports:view", "data:import", "data:export"}
        viewer_perms = {"items:view"}

        role = (self.role or "").lower()
        if role == "staff":
            return perm in staff_perms
        if role == "viewer":
            return perm in viewer_perms
        return False

    def grant_perm(self, perm: str):
        s = self._perm_set()
        s.add(perm)
        self.permissions = ",".join(sorted(s))

    def revoke_perm(self, perm: str):
        s = self._perm_set()
        if perm in s:
            s.remove(perm)
        self.permissions = ",".join(sorted(s))
class Consignor(db.Model):
    __tablename__ = "consignors"

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(140), nullable=False, index=True)
    phone      = db.Column(db.String(50))
    email      = db.Column(db.String(200))
    notes      = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Supplier(db.Model):
    __tablename__ = "suppliers"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(50))
    email = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Item(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))

    photos = db.relationship(
        "Photo",
        backref="item",
        lazy="selectin",              # or "joined"
        cascade="all, delete-orphan"  # optional but handy
    )

    # Ownership / consignor
    ownership     = db.Column(db.String(20), nullable=False, default="owned")  # "owned" or "consigned"
    consignor     = db.Column(db.String(120))
    consignor_id  = db.Column(db.Integer, db.ForeignKey("consignors.id"), nullable=True)  # keep if you have a Consignor table; otherwise remove
    consignor_rate = db.Column(db.Float)  # e.g., 0.65

    # Money (store as cents)
    cost_cents       = db.Column(db.Integer)
    price_cents      = db.Column(db.Integer)     # <-- matches importer
    sale_price_cents = db.Column(db.Integer)
    status           = db.Column(db.String(20), nullable=False, default="available")  # "available" or "sold"

    # Dates / parties
    sale_date   = db.Column(db.Date)            # use Date if parse_date returns a date
    buyer_name  = db.Column(db.String(120))     # <-- matches importer

    # Supplier (name + FK)
    supplier    = db.Column(db.String(140))     # optional free-text name
    supplier_id = db.Column(db.Integer, db.ForeignKey("suppliers.id"))  # <-- table name matches Supplier.__tablename__

    # Misc
    notes = db.Column(db.Text)

    # Relationship
    supplier_ref = db.relationship("Supplier", backref="items", lazy="joined")

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ----- Computed helpers (unchanged) -----
    @property
    def cost(self):
        return (self.cost_cents or 0) / 100.0

    @property
    def asking(self):
        return (self.price_cents or 0) / 100.0

    @property
    def sale_price(self):
        return (self.sale_price_cents or 0) / 100.0

    @property
    def consignor_payout_dollars(self):
        v = self.consignor_payout
        return None if v is None else v / 100.0
    
    @property
    def house_net_dollars(self):
        v = self.house_net
        return None if v is None else v / 100.0

    @property
    def consignor_payout(self):
        """
        Consignor payout in CENTS:
        - None for non-consigned items
        - 0 if consigned but not sold yet
        - Otherwise sale_price_cents * consignor_rate (or default rate)
        """
        # Not consigned → no payout
        if (self.ownership or "").lower() != "consigned":
            return None

        # Not sold yet → 0
        if not self.sale_price_cents:
            return 0

        # Use item rate if present; else app default (e.g., 0.65)
        rate = self.consignor_rate
        if rate is None:
            rate = current_app.config.get("CONSIGNOR_RATE", 0.65)

        try:
            return int(round(self.sale_price_cents * float(rate)))
        except Exception:
            return 0

    @property
    def house_net(self):
        """
        Store net in CENTS.
        - None if not sold yet
        - Consigned: sale - consignor payout
        - Owned:     sale - cost
        """
        sp = self.sale_price_cents
        if not sp:
            return None  # not sold yet

        if (self.ownership or "").lower() == "consigned":
            payout = self.consignor_payout or 0
            return sp - payout
        else:
            cost = self.cost_cents or 0
            return sp - cost
from datetime import datetime

def next_sku():
    """FBZ-YYYYMMDD-####, increments per day."""
    today = datetime.utcnow().strftime("%Y%m%d")
    prefix = f"FBZ-{today}-"
    last = (
        Item.query.filter(Item.sku.like(prefix + "%"))
        .order_by(Item.sku.desc())
        .first()
    )
    n = 1
    if last:
        try:
            n = int(last.sku.rsplit("-", 1)[-1]) + 1
        except Exception:
            n = 1
    candidate = f"{prefix}{n:04d}"
    while Item.query.filter_by(sku=candidate).first():
        n += 1
        candidate = f"{prefix}{n:04d}"
    return candidate

class Photo(db.Model):
    __tablename__ = "photos"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.id"), nullable=False)  # <-- plural 'items'
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---- relationships MUST come *after* classes are defined ----
Item.consignor_ref = relationship("Consignor", backref="items", lazy="joined")
Item.photos = relationship("Photo", backref="item", cascade="all, delete-orphan", lazy="dynamic")
# ---------- Auto-categorize & Auto-SKU helpers ----------
from sqlalchemy import event, text as sqltext

def _normalize_text(s: str) -> str:
    return (s or "").lower()

# Keyword-based category map — tweak as you like
_CATEGORY_KEYWORDS = {
    "Electronics": ["iphone", "android", "laptop", "macbook", "ipad", "tablet", "camera", "ps5", "xbox", "nintendo", "tv", "speaker", "airpods", "headphones"],
    "Footwear":    ["shoe", "sneaker", "cleat", "boot", "jordan", "yeezy", "nike", "adidas"],
    "Clothing":    ["shirt", "pants", "jeans", "hoodie", "jacket", "coat", "dress", "skirt", "sweater"],
    "Accessories": ["purse", "handbag", "wallet", "belt", "sunglasses", "watch", "jewelry", "ring", "necklace"],
    "Toys":        ["lego", "nerf", "barbie", "hot wheels", "puzzle", "board game", "toy"],
    "Tools":       ["dewalt", "milwaukee", "ryobi", "drill", "saw", "sander", "tool"],
    "Home":        ["sofa", "couch", "chair", "table", "lamp", "rug", "vacuum", "kitchen"],
    "Sports":      ["golf", "baseball", "basketball", "football", "hockey", "tennis", "bike", "bicycle"],
    "Collectibles":["card", "funko", "comic", "vintage", "antique", "coin", "stamp"],
}

def guess_category_from_text(text: str) -> str:
    text_n = _normalize_text(text)
    best_cat, best_hits = None, 0
    for cat, words in _CATEGORY_KEYWORDS.items():
        hits = sum(1 for w in words if w in text_n)
        if hits > best_hits:
            best_cat, best_hits = cat, hits
    return best_cat or "General"

def build_sku_from(item) -> str:
    # Example: FBZ-ELE-20251019-0042
    cat3 = (item.category or "General")[:3].upper()
    dt = (item.created_at or datetime.utcnow()).strftime("%Y%m%d")
    return f"FBZ-{cat3}-{dt}-{item.id:04d}"

# Auto-fill missing category and SKU on insert
@event.listens_for(Item, "before_insert")
def _auto_fill_before_insert(mapper, connection, target):
    if not getattr(target, "category", None):
        source = f"{target.title or ''} {target.notes or ''}"
        target.category = guess_category_from_text(source)
    if not getattr(target, "sku", None):
        import uuid
        target.sku = f"TEMP-{uuid.uuid4().hex[:8]}"

@event.listens_for(Item, "after_insert")
def _auto_fill_after_insert(mapper, connection, target):
    from sqlalchemy import text as sqltext
    if not target.sku or target.sku.startswith("TEMP"):
        base = build_sku_from(target)
        sku = base
        i = 1
        while connection.execute(sqltext("SELECT 1 FROM item WHERE sku = :s"), {"s": sku}).fetchone():
            i += 1
            sku = f"{base}-{i}"
        connection.execute(sqltext("UPDATE item SET sku=:s WHERE id=:id"), {"s": sku, "id": target.id})

# Wire relationships AFTER both classes are defined
from sqlalchemy.orm import relationship
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # always 1
    brand_name = db.Column(db.String(120), default="FlashBidz")
    brand_color = db.Column(db.String(16), default="#e60000")
    logo_url = db.Column(db.String(400))
    default_consignor_rate = db.Column(db.Float, default=0.65)  # 0..1
    store_address = db.Column(db.String(240))
    store_phone = db.Column(db.String(40))
    mail_from = db.Column(db.String(200))
    mail_smtp = db.Column(db.String(200), default="smtp.gmail.com")
    mail_port = db.Column(db.Integer, default=587)
    mail_username = db.Column(db.String(200))
    mail_password = db.Column(db.String(200))
    mail_use_tls = db.Column(db.Boolean, default=True)
def get_settings():
    s = Settings.query.get(1)
    if not s:
        s = Settings(id=1)
        db.session.add(s)
        db.session.commit()
    return s

# ---------------------------
# CONSIGNOR MODEL
# ---------------------------

# Optional: add relationship

# Core info
title = db.Column(db.String(200), nullable=False)
# Furniture, Electronics, Toys, etc.
category = db.Column(db.String(100), nullable=True)

# Ownership: owned | consigned | internal
ownership = db.Column(db.String(20), nullable=False, default="owned")

# Pricing
# your cost (None/0 for consigned if you wish)
cost_cents = db.Column(db.Integer, nullable=True)
asking_cents = db.Column(db.Integer,
                         nullable=True)   # optional asking price

# Sales
status = db.Column(
    db.String(20),
    nullable=False,
    default="available")  # available | sold
sale_price_cents = db.Column(db.Integer, nullable=True)
sale_date = db.Column(db.Date, nullable=True)
buyer = db.Column(db.String(120), nullable=True)

# Consignor details (simple for now)
consignor = db.Column(db.String(120), nullable=True)

# Notes
notes = db.Column(db.Text, nullable=True)

# Timestamps

updated_at = db.Column(
    db.DateTime,
    default=datetime.utcnow,
    onupdate=datetime.utcnow)

# Convenience $ helpers for templates


@property
def cost(self): return (self.cost_cents or 0) / 100


@property
def asking(self): return (self.asking_cents or 0) / 100
@property
def sale_price(self): return (self.sale_price_cents or 0) / 100

# ---------------------------
# LOGIN / LOGOUT ROUTES
# ---------------------------


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session["user_id"] = str(user.id)
        session["username"] = user.username
        session["role"] = user.role
        nxt = request.args.get("next") or url_for("home")
        return redirect(nxt)

    flash("Invalid username or password")
    return redirect(url_for("login"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------
# BASIC PAGES
# ---------------------------


@app.get("/")
def home():
    return render_template("home.html")


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")
def send_email(to_addr: str, subject: str, body: str):
    if not to_addr:
        return
    msg = EmailMessage()
    msg["From"] = app.config["MAIL_FROM"]
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(app.config["MAIL_SMTP"], app.config["MAIL_PORT"]) as s:
        if app.config.get("MAIL_USE_TLS"):
            s.starttls()
        s.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
        s.send_message(msg)

# ---------------------------
# INVENTORY ROUTES
# ---------------------------


from sqlalchemy import func

@require_perm("consignors:manage")
@require_perm("data:import")
@require_perm("reports:view")
@app.get("/items")
@require_perm("items:view")
def items_list():
    q = Item.query

    s = (request.args.get("s") or "").strip()
    status = (request.args.get("status") or "").strip()
    owner = (request.args.get("ownership") or "").strip()
    cat = (request.args.get("category") or "").strip()

    if s:
        like = f"%{s}%"
        q = q.filter(db.or_(Item.title.ilike(like), Item.sku.ilike(like), Item.notes.ilike(like)))
    if status:
        q = q.filter(Item.status == status)
    if owner:
        q = q.filter(Item.ownership == owner)
    if cat:
        q = q.filter(Item.category == cat)

    page = max(int(request.args.get("page", 1)), 1)
    per = 50
    p = q.order_by(Item.created_at.desc()).paginate(page=page, per_page=per, error_out=False)
    items = p.items

    nz = lambda v: 0 if v is None else v
    total_cost      = sum(nz(it.cost_cents) for it in items)
    total_asking    = sum(nz(it.asking_cents) for it in items)
    total_sales     = sum(nz(it.sale_price_cents) for it in items if it.sale_price_cents)
    total_consignor = sum(nz(it.consignor_payout) for it in items if it.consignor_payout is not None)
    total_house     = sum(nz(it.house_net) for it in items if it.house_net is not None)

    return render_template(
        "items.html",
        items=items, page=page, pages=p.pages,
        total_cost=total_cost, total_asking=total_asking,
        total_sales=total_sales, total_consignor=total_consignor,
        total_house=total_house, s=s, status=status, ownership=owner, category=cat
    )

    items = q.order_by(Item.created_at.desc()).all()

    # --- Totals (server-side) ---
    total_cost = sum((it.cost_cents or 0) for it in items) / 100.0
    total_sales = sum((it.sale_price_cents or 0) for it in items) / 100.0
    total_profit = sum(
        ((it.sale_price_cents or 0) - (it.cost_cents or 0)) for it in items
        if it.sale_price_cents is not None
    ) / 100.0
    total_consignor = sum((it.consignor_payout or 0) for it in items if it.consignor_payout is not None)
    total_house = sum((it.house_net or 0) for it in items if it.house_net is not None)

    totals = {
        "cost": total_cost,
        "sales": total_sales,
        "profit": total_profit,
        "consignor": total_consignor,
        "house": total_house,
    }

    return render_template("items.html", items=items, totals=totals)


@app.get("/items/new")
def item_new():
    return render_template("item_form.html", item=None)
@app.template_filter("money")
def money(cents):
    if cents is None:
        return ""
    try:
        return "${:,.2f}".format((int(cents) / 100.0))
    except Exception:
        return ""


@app.post("/items/new")
@require_perm("items:add")
def item_create():
    def to_cents(v):
        if not v:
            return None
        try:
            return int(round(float(v) * 100))
        except Exception:
            return None

    title = (request.form.get("title") or "").strip()
    category = (request.form.get("category") or "").strip() or None
    ownership = (request.form.get("ownership") or "owned").strip().lower()
    cost_cents = to_cents(request.form.get("cost"))
    asking_cents = to_cents(request.form.get("asking"))
    notes = (request.form.get("notes") or "").strip() or None
    consignor_name = (request.form.get("consignor") or "").strip() or None
    supplier_name = (request.form.get("supplier") or "").strip() or None
    sale_date_str = (request.form.get("sale_date") or "").strip() or None

    # Use provided SKU if present, otherwise auto-generate
    sku = (request.form.get("sku") or "").strip()
    if not sku:
        sku = next_sku()  # requires next_sku() to be defined below Item class

    # Resolve consignor_name -> consignor_id (optional)
    consignor_id = None
    if consignor_name:
        c = Consignor.query.filter(Consignor.name.ilike(consignor_name)).first()
        if not c:
            c = Consignor(name=consignor_name)
            db.session.add(c)
            db.session.flush()  # get c.id without a separate commit
        consignor_id = c.id

    item = Item(
        sku=sku,
        title=title,
        category=category,
        ownership=ownership,
        cost_cents=cost_cents,
        asking_cents=asking_cents,
        status="available",
        notes=notes,
        consignor=consignor_name,
        consignor_id=consignor_id,
    )
    db.session.add(item)
    db.session.commit()
    flash(f"Item '{title}' created with SKU {sku}.")
    return redirect(url_for("items_list"))
from datetime import datetime

def parse_date(s):
    if not s: return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass
    return None


@app.get("/items/<int:item_id>/edit")
def item_edit(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template("item_form.html", item=item)


@app.post("/items/<int:item_id>/edit")
def item_update(item_id):
    item = Item.query.get_or_404(item_id)

    def dollars_to_cents(val):
        try:
            return int(round(float(val) * 100))
        except BaseException:
            return None
    item.title = request.form.get("title", "").strip() or item.title
    item.ownership = request.form.get("ownership", "owned").strip()
    item.category = request.form.get("category", "").strip() or None
    item.cost_cents = dollars_to_cents(request.form.get("cost", ""))
    item.asking_cents = dollars_to_cents(request.form.get("asking", ""))
    item.consignor = request.form.get("consignor", "").strip() or None
    item.notes = request.form.get("notes", "").strip() or None
    db.session.commit()
    flash("Item updated")
    return redirect(url_for("items_list"))


@app.post("/items/<int:item_id>/delete")
def item_delete(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted")
    return redirect(url_for("items_list"))


@app.get("/items/<int:item_id>/sell")
def item_sell_form(item_id):
    item = Item.query.get_or_404(item_id)
    if item.status == "sold":
        flash("Item already sold")
        return redirect(url_for("items_list"))
    return render_template("sell_form.html", item=item)


@app.post("/items/<int:item_id>/sell")
def item_sell(item_id):
    item = Item.query.get_or_404(item_id)
    if item.status == "sold":
        flash("Item already sold")
        return redirect(url_for("items_list"))

    def dollars_to_cents(val):
        try:
            return int(round(float(val) * 100))
        except BaseException:
            return None

    sale_price_cents = dollars_to_cents(request.form.get("sale_price", ""))
    sale_date_str = request.form.get("sale_date", "").strip()
    buyer = request.form.get("buyer", "").strip()

    if not sale_price_cents:
        flash("Sale price is required")
        return redirect(url_for("item_sell_form", item_id=item.id))

    sale_date = None
    if sale_date_str:
        try:
            sale_date = datetime.strptime(sale_date_str, "%Y-%m-%d").date()
        except BaseException:
            pass
    if not sale_date:
        sale_date = datetime.utcnow().date()

    item.status = "sold"
    item.sale_price_cents = sale_price_cents
    item.sale_date = sale_date
    item.buyer = buyer or None
    db.session.commit()
    flash("Sale recorded")
    return redirect(url_for("items_list"))


# Create tables if they don't exist
with app.app_context():
    db.create_all()


@app.get("/upload")
def upload_form():
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template("upload.html", items=items)


@app.post("/upload")
def upload_post():
    item_id = request.form.get("item_id", "").strip()
    if not item_id:
        flash("Please choose an item to attach photos to.")
        return redirect(url_for("upload_form"))

    item = Item.query.get(item_id)
    if not item:
        flash("Selected item not found.")
        return redirect(url_for("upload_form"))

    files = request.files.getlist("photos")
    if not files or all(f.filename == "" for f in files):
        flash("Please select at least one image.")
        return redirect(url_for("upload_form"))

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    saved_any = False

    for f in files:
        if f and allowed_file(f.filename):
            # Make filename safe & unique
            base = secure_filename(f.filename)
            name, ext = os.path.splitext(base)
            unique = f"{name}-{int(datetime.utcnow().timestamp())}{ext}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], unique)
            f.save(path)

            # Record in DB
            p = Photo(item_id=item.id, filename=unique)
            db.session.add(p)
            saved_any = True

    if saved_any:
        db.session.commit()
        flash("Photo(s) uploaded.")
        return redirect(url_for("item_photos", item_id=item.id))
    else:
        flash("No valid image files were uploaded.")
        return redirect(url_for("upload_form"))


@app.get("/items/<int:item_id>/photos")
def item_photos(item_id):
    item = Item.query.get_or_404(item_id)
    photos = item.photos.order_by(Photo.uploaded_at.desc()).all()
    return render_template("photos.html", item=item, photos=photos)

@app.get("/reports")
def reports():
    # Optional date filters for SOLD items
    start = request.args.get("start", "").strip()  # YYYY-MM-DD
    end = request.args.get("end", "").strip()      # YYYY-MM-DD

    sold_q = Item.query.filter(Item.status == "sold")
    if start:
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d").date()
            sold_q = sold_q.filter(Item.sale_date >= start_date)
        except:
            start_date = None
    else:
        start_date = None

    if end:
        try:
            end_date = datetime.strptime(end, "%Y-%m-%d").date()
            sold_q = sold_q.filter(Item.sale_date <= end_date)
        except:
            end_date = None
    else:
        end_date = None

    # Totals (all inventory)
    total_items = db.session.query(func.count(Item.id)).scalar() or 0
    total_cost_cents = db.session.query(func.coalesce(func.sum(Item.cost_cents), 0)).scalar() or 0
    total_listed = db.session.query(func.count(Item.id)).filter(Item.status == "available").scalar() or 0
    total_sold = db.session.query(func.count(Item.id)).filter(Item.status == "sold").scalar() or 0

    # Sales totals (respecting date filters if provided)
    total_sales_cents = db.session.query(func.coalesce(func.sum(Item.sale_price_cents), 0)).select_from(sold_q.subquery()).scalar() or 0
    # Profit = sum(sale - cost) on SOLD items (null-safe)
    profit_cents = db.session.query(
        func.coalesce(func.sum(
            (func.coalesce(Item.sale_price_cents, 0) - func.coalesce(Item.cost_cents, 0))
        ), 0)
    ).select_from(sold_q.subquery()).scalar() or 0

    # Ownership breakdown (counts / sales / cost / profit)
    # Note: profit is approximated as sale - cost; if you have consignor payout rules, we can refine later.
    ownership_rows = db.session.query(
        Item.ownership.label("ownership"),
        func.count(Item.id).label("cnt"),
        func.coalesce(func.sum(Item.cost_cents), 0).label("cost_cents"),
        func.coalesce(func.sum(Item.sale_price_cents), 0).label("sales_cents"),
        func.coalesce(func.sum(
            func.coalesce(Item.sale_price_cents, 0) - func.coalesce(Item.cost_cents, 0)
        ), 0).label("profit_cents"),
    ).group_by(Item.ownership).all()

    def cents_to_dollars(c): return (c or 0) / 100.0

    summary = {
        "total_items": total_items,
        "total_listed": total_listed,
        "total_sold": total_sold,
        "total_cost": cents_to_dollars(total_cost_cents),
        "total_sales": cents_to_dollars(total_sales_cents),
        "profit": cents_to_dollars(profit_cents),
        "start": start_date.isoformat() if start_date else "",
        "end": end_date.isoformat() if end_date else "",
    }

    # Convert ownership rows to plain dicts for the template
    ownership = []
    for r in ownership_rows:
        ownership.append({
            "ownership": r.ownership,
            "count": r.cnt,
            "cost": cents_to_dollars(r.cost_cents),
            "sales": cents_to_dollars(r.sales_cents),
            "profit": cents_to_dollars(r.profit_cents),
        })

    return render_template("reports.html", summary=summary, ownership=ownership)
@app.get("/items/<int:item_id>/qrcode")
def item_qrcode(item_id):
    item = Item.query.get_or_404(item_id)
    # Encode a useful URL (photos page) or the SKU itself:
    url = url_for("item_photos", item_id=item.id, _external=True)
    img = qrcode.make(url)
    bio = BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    return send_file(bio, mimetype="image/png")

@app.get("/items/<int:item_id>/barcode")
def item_barcode(item_id):
    item = Item.query.get_or_404(item_id)
    # Code128 supports alphanumeric SKUs well
    code_class = barcode.get_barcode_class("code128")
    code = code_class(item.sku, writer=ImageWriter())
    bio = BytesIO()
    # text=True prints SKU under the bars
    code.write(bio, options={"write_text": True})
    bio.seek(0)
    return send_file(bio, mimetype="image/png")
@app.get("/items/<int:item_id>/print")
def item_print(item_id):
    item = Item.query.get_or_404(item_id)
    if item.sku:
        ensure_barcode_png(item.sku)
    return render_template("print_item.html", item=item)
from datetime import datetime, date
from flask import Response

def parse_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except:
        return None

@app.get("/statements")
def statements_index():
    dfrom = parse_date(request.args.get("from", ""))
    dto   = parse_date(request.args.get("to", ""))
    q = Item.query.filter(Item.status == "sold", Item.consignor_id.isnot(None))
    if dfrom:
        q = q.filter(Item.sale_date >= dfrom)
    if dto:
        q = q.filter(Item.sale_date <= dto)
    rows = q.all()

    by_consignor = {}
    for it in rows:
        cid = it.consignor_id
        by_consignor.setdefault(cid, {
            "consignor": it.consignor_ref,
            "items": [],
            "totals": {"sales": 0.0, "payout": 0.0, "house": 0.0}
        })
        rate = it.effective_rate or 0
        sale = it.sale_price or 0
        payout = sale * rate
        house = sale - payout
        by_consignor[cid]["items"].append(it)
        by_consignor[cid]["totals"]["sales"]  += sale
        by_consignor[cid]["totals"]["payout"] += payout
        by_consignor[cid]["totals"]["house"]  += house

    return render_template("statements_index.html",
                           groups=by_consignor, dfrom=dfrom, dto=dto)
# ---------------------------
# CONSIGNOR STATEMENTS ROUTES
# ---------------------------
from flask import Response
from datetime import datetime, date

def parse_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except:
        return None


@app.get("/consignors/<int:cid>/statement.csv")
def consignor_statement_csv(cid):
    c = Consignor.query.get_or_404(cid)
    dfrom = parse_date(request.args.get("from","") or "")
    dto   = parse_date(request.args.get("to","") or "")

    q = Item.query.filter(Item.status=="sold", Item.consignor_id==cid)
    if dfrom: q = q.filter(Item.sale_date >= dfrom)
    if dto:   q = q.filter(Item.sale_date <= dto)
    items = q.order_by(Item.sale_date.desc().nullslast()).all()

    def row(it):
        rate = it.effective_rate or 0.0
        sale = it.sale_price or 0.0
        payout = sale * rate
        house = sale - payout
        title = (it.title or "").replace(",", " ")
        return f'{it.sku},{title},{it.sale_date or ""},{sale:.2f},{int(rate*100)},{payout:.2f},{house:.2f}\n'

    csv_data = "SKU,Title,Sale Date,Sale,Rate %,Consignor Payout,House Net\n"
    csv_data += "".join(row(it) for it in items)

    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=statement_{cid}.csv"})
# ---------------------------
# BASIC CONSIGNORS / ADMIN PAGES
# ---------------------------

@app.get("/consignors")
def consignors_list():
    # Show list even if empty
    consignors = Consignor.query.order_by(Consignor.name.asc()).all() if 'Consignor' in globals() else []
    return render_template("consignors.html", consignors=consignors)

# ---------------------------
# CONSIGNORS: NEW (GET + POST)
# ---------------------------

@app.get("/consignors/new")
def consignor_new():
    # show the new consignor form
    return render_template("consignor_form.html", consignor=None)

@app.post("/consignors/new")
def consignor_create():
    name  = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    phone = (request.form.get("phone") or "").strip() or None
    notes = (request.form.get("notes") or "").strip() or None
    dr    = (request.form.get("default_rate") or "").strip()
    try:
        default_rate = float(dr) if dr else None
        if default_rate is not None and not (0 <= default_rate <= 1):
            default_rate = None
    except Exception:
        default_rate = None

    if not name:
        flash("Name is required")
        return redirect(url_for("consignor_new"))

    c = Consignor(name=name, email=email, phone=phone, notes=notes, default_rate=default_rate)
    db.session.add(c)
    db.session.commit()
    flash("Consignor created")
    return redirect(url_for("consignors_list"))
def get_settings():
    s = Settings.query.get(1)
    if not s:
        s = Settings(id=1)
        db.session.add(s)
        db.session.commit()
    return s

@app.get("/admin")
def admin_view():
    s = get_settings()
    return render_template("admin.html", s=s)

@app.post("/admin")
def admin_save():
    s = get_settings()
    s.brand_name = (request.form.get("brand_name") or "FlashBidz").strip()
    s.brand_color = (request.form.get("brand_color") or "#e60000").strip()
    s.logo_url = (request.form.get("logo_url") or "").strip() or None

    try:
        r = float(request.form.get("default_consignor_rate") or "0.65")
        if 0 <= r <= 1: s.default_consignor_rate = r
    except: pass

    s.store_address = (request.form.get("store_address") or "").strip() or None
    s.store_phone   = (request.form.get("store_phone") or "").strip() or None

    s.mail_from     = (request.form.get("mail_from") or "").strip() or None
    s.mail_smtp     = (request.form.get("mail_smtp") or "smtp.gmail.com").strip()
    try: s.mail_port = int(request.form.get("mail_port") or "587")
    except: s.mail_port = 587
    s.mail_username = (request.form.get("mail_username") or "").strip() or None
    s.mail_password = (request.form.get("mail_password") or "").strip() or None
    s.mail_use_tls  = True if request.form.get("mail_use_tls") == "on" else False

    db.session.commit()

    # reflect into app config for payouts & email helpers
    app.config["CONSIGNOR_RATE"] = s.default_consignor_rate or 0.65
    app.config["MAIL_FROM"] = s.mail_from or app.config.get("MAIL_FROM")
    app.config["MAIL_SMTP"] = s.mail_smtp or app.config.get("MAIL_SMTP", "smtp.gmail.com")
    app.config["MAIL_PORT"] = s.mail_port or app.config.get("MAIL_PORT", 587)
    app.config["MAIL_USERNAME"] = s.mail_username or app.config.get("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = s.mail_password or app.config.get("MAIL_PASSWORD")
    app.config["MAIL_USE_TLS"]  = s.mail_use_tls if s.mail_use_tls is not None else app.config.get("MAIL_USE_TLS", True)

    flash("Settings saved")
    return redirect(url_for("admin_view"))

@app.get("/admin/export/items.csv")
def export_items_csv():
    import csv, io
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["id","sku","title","category","ownership","cost","asking","status","sale_price","sale_date","buyer","consignor_id","consignor","notes","created_at","updated_at"])
    for it in Item.query.order_by(Item.id.asc()).all():
        w.writerow([
            it.id, it.sku, it.title or "", it.category or "", it.ownership or "",
            it.cost, it.asking, it.status or "", it.sale_price, it.sale_date or "",
            it.buyer or "", it.consignor_id or "", it.consignor or "", (it.notes or "").replace("\n"," "),
            it.created_at or "", it.updated_at or ""
        ])
    from flask import make_response
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=items_export.csv"
    return resp

@app.get("/admin/export/consignors.csv")
def export_consignors_csv():
    import csv, io
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["id","name","email","phone","default_rate","notes","created_at"])
    for c in Consignor.query.order_by(Consignor.name.asc()).all():
        w.writerow([c.id, c.name or "", c.email or "", c.phone or "", c.default_rate if c.default_rate is not None else "", (c.notes or "").replace("\n"," "), c.created_at or ""])
    from flask import make_response
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=consignors_export.csv"
    return resp

@app.get("/admin/backup/db")
def backup_db():
    from flask import send_file
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flashbidz.db")
    if not os.path.exists(db_path):
        return "DB file not found", 404
    return send_file(db_path, as_attachment=True, download_name="flashbidz_backup.db")
# ---------- USERS (Admin) ----------
@app.get("/users")
def users_list():
    # admin-only (guard also checks, but we double-check here)
    if session.get("role") != "admin":
        return "Forbidden", 403
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("manage_users.html", users=users)

@app.post("/users/new")
def users_new():
    if session.get("role") != "admin":
        return "Forbidden", 403
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    role     = (request.form.get("role") or "staff").strip()
    if not username or not password:
        flash("Username and password are required")
        return redirect(url_for("users_list"))
    if role not in ("admin", "staff"):
        role = "staff"
    if User.query.filter_by(username=username).first():
        flash("That username is taken")
        return redirect(url_for("users_list"))
    u = User(username=username, role=role)
    u.set_password(password)
    db.session.add(u); db.session.commit()
    flash(f"User '{username}' created")
    return redirect(url_for("users_list"))

@app.post("/users/<int:uid>/role")
def users_set_role(uid):
    if session.get("role") != "admin":
        return "Forbidden", 403
    role = (request.form.get("role") or "staff").strip()
    if role not in ("admin", "staff"):
        role = "staff"
    u = User.query.get_or_404(uid)
    u.role = role
    db.session.commit()
    flash(f"Role updated for {u.username} → {role}")
    return redirect(url_for("users_list"))

@app.post("/users/<int:uid>/delete")
def users_delete(uid):
    if session.get("role") != "admin":
        return "Forbidden", 403
    u = User.query.get_or_404(uid)
    if u.username == "admin":
        flash("Cannot delete the primary admin user")
        return redirect(url_for("users_list"))
    db.session.delete(u)
    db.session.commit()
    flash(f"Deleted {u.username}")
    return redirect(url_for("users_list"))
@app.get("/account/password")
def account_password_form():
    if not session.get("user_id"):
        return redirect(url_for("login", next=request.path))
    return render_template("change_password.html")

@app.post("/account/password")
def account_password_change():
    if not session.get("user_id"):
        return redirect(url_for("login", next=request.path))
    current = (request.form.get("current") or "").strip()
    new1    = (request.form.get("new1") or "").strip()
    new2    = (request.form.get("new2") or "").strip()
    u = User.query.get(int(session["user_id"]))
    if not u or not u.check_password(current):
        flash("Current password is incorrect")
        return redirect(url_for("account_password_form"))
    if not new1 or new1 != new2:
        flash("New passwords do not match")
        return redirect(url_for("account_password_form"))
    u.set_password(new1)
    db.session.commit()
    flash("Password updated")
    return redirect(url_for("dashboard"))
import csv, io, urllib.request
from datetime import datetime


def _money_to_cents(v):
    if v is None: return None
    s = str(v).strip().replace(",", "")
    if s == "": return None
    try:
        # if it has a dot, treat as dollars
        if "." in s:
            return int(round(float(s) * 100))
        # otherwise assume integer dollars or raw cents; default: dollars -> cents
        n = int(s)
        # Heuristic: if it's large (>= 100000), assume it's already cents
        return n if n >= 100000 else n * 100
    except:
        return None

def _parse_date(s):
    if not s: return None
    s = str(s).strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%d-%b-%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except: pass
    # last resort: try fromisoformat
    try:
        return datetime.fromisoformat(s).date()
    except:
        return None

def _normalize_header(h):
    return (h or "").strip().lower().replace(" ", "_")

def _generate_sku_for(item):
    dt = item.created_at or datetime.utcnow()
    # we assume item.id is assigned (after flush)
    item.sku = f"FBZ-{dt.strftime('%Y%m%d')}-{item.id:04d}"

@app.get("/admin/import")
def import_items_form():
    if session.get("role") != "admin":
        flash("Admin access required")
        return redirect(url_for("home"))
    return render_template("import_items.html")


@app.post("/admin/import")
def import_items_post():
    # Optional: guard
    if session.get("role") != "admin":
        flash("Admin access required", "error")
        return redirect(url_for("home"))

    import csv, io, urllib.request

    # ---- inputs ----
    f = request.files.get("file")
    csv_url = (request.form.get("csv_url") or "").strip()

    total = created = updated = skipped = errors = 0

    # ---- fetch CSV bytes (file or URL) ----
    try:
        if f and f.filename:
            data = f.read()
        elif csv_url:
            with urllib.request.urlopen(csv_url) as resp:
                data = resp.read()
        else:
            flash("Please upload a CSV file or provide a CSV URL.", "error")
            return redirect(url_for("import_items_form"))
    except Exception as e:
        flash(f"Failed to fetch CSV: {e}", "error")
        return redirect(url_for("import_items_form"))

    # ---- parse CSV and upsert items ----
    try:
        text = data.decode("utf-8", "replace")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            flash("CSV appears to have no header row.", "error")
            return redirect(url_for("import_items_form"))

        norm_headers = [_normalize_header(h or "") for h in reader.fieldnames]

        for idx, raw in enumerate(reader, start=2):  # row index (header is 1)
            total += 1
            try:
                # normalize row keys
                row = {}
                for i, key in enumerate(raw.keys()):
                    norm = norm_headers[i] if i < len(norm_headers) else _normalize_header(key or "")
                    row[norm] = raw.get(key, "")

                title = (pick(row, ["title", "name", "item", "description"]) or "").strip()
                if not title:
                    skipped += 1
                    continue

                # SKU (generate if missing)
                sku = (pick(row, ["sku", "item_sku", "stock_keeping_unit"]) or "").strip()
                if not sku:
                    sku = _generate_sku_for(Item(title=title))

                # money + misc
                cost_cents  = to_cents(pick(row, ["cost", "purchase_price", "buy_cost", "purchase cost"]))
                price_cents = to_cents(pick(row, ["asking_price", "price", "list_price", "price_usd"]))
                notes = (pick(row, ["notes", "note", "comments", "comment"]) or "").strip()

                # supplier
                supplier_name = pick(row, ["supplier", "vendor", "source"])
                supplier = None
                if supplier_name:
                    name_clean = supplier_name.strip()
                    if name_clean:
                        supplier = Supplier.query.filter(
                            db.func.lower(Supplier.name) == name_clean.lower()
                        ).first()
                        if not supplier:
                            supplier = Supplier(name=name_clean)
                            db.session.add(supplier)

                # sale info
                sale_date_raw = pick(row, ["sale_date", "sold_date", "date_sold", "sold on"])
                sale_date = parse_date(sale_date_raw) if sale_date_raw else None
                buyer_name = (pick(row, ["buyer", "buyer_name", "purchaser"]) or "").strip()
                consignor_name = (pick(row, ["consignor", "consignor_name", "seller"]) or "").strip()

                status_from_csv = (pick(row, ["status", "item_status"]) or "").strip().lower()
                status = "sold" if sale_date else (status_from_csv or "active")

                # upsert by SKU
                item = Item.query.filter_by(sku=sku).first()
                if not item:
                    item = Item(
                        sku=sku,
                        title=title,
                        cost_cents=cost_cents,
                        price_cents=price_cents,
                        notes=notes,
                        supplier_id=(supplier.id if supplier else None),
                        sale_date=sale_date,
                        buyer_name=buyer_name or None,
                        consignor_name=consignor_name or None,
                        status=status,
                    )
                    db.session.add(item)
                    created += 1
                else:
                    if title: item.title = title
                    if cost_cents is not None: item.cost_cents = cost_cents
                    if price_cents is not None: item.price_cents = price_cents
                    if notes: item.notes = notes
                    if supplier: item.supplier_id = supplier.id
                    if sale_date:
                        item.sale_date = sale_date
                        item.status = "sold"
                    elif status_from_csv:
                        item.status = status
                    if buyer_name: item.buyer_name = buyer_name
                    if consignor_name: item.consignor_name = consignor_name
                    updated += 1

            except Exception as row_err:
                errors += 1
                print(f"Row {idx}: {row_err}")
                continue

    except Exception as e:
        flash(f"Failed to parse CSV: {e}", "error")
        return redirect(url_for("import_items_form"))

    # ---- commit and report ----
    db.session.commit()
    flash(
        f"Import complete. Total {total} | Created {created} | Updated {updated} | "
        f"Skipped {skipped} | Errors {errors}",
        "success" if errors == 0 else "warning",
    )
    return redirect(url_for("import_items_form"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5001, debug=False)

