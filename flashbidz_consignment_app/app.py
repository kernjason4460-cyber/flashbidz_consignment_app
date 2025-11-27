


# ---- Imports (keep one of each; no duplicates) ----
import os
from datetime import datetime, date
from io import BytesIO
import smtplib
from email.message import EmailMessage
from functools import wraps
from decimal import Decimal
from sqlalchemy import text
from sqlalchemy import or_ 
import io
from flask import make_response
from flask import Response
from flask_login import login_required, current_user
from io import StringIO
from flask import Flask, request, session, redirect, url_for, render_template, flash, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import func, literal
from werkzeug.utils import secure_filename
from PIL import Image
from flask import send_from_directory
import csv
import urllib.request
import time
import re
import zipfile

# ---- Permission decorator (only admins or explicit perms) ----
def require_perm(perm_name):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                nxt = request.full_path if request.query_string else request.path
                return redirect(url_for("login", next=nxt))

            # Load user
            u = db.session.get(User, int(uid))
            if not u:
                flash("Please log in again.")
                return redirect(url_for("login"))

            role = (u.role or "").lower()

            # 1) Admins can do everything
            if role == "admin":
                return fn(*args, **kwargs)

            # 2) Explicit permission list on the user (comma-separated)
            perms = {
                p.strip()
                for p in (u.permissions or "").split(",")
                if p.strip()
            }

            if perms:
                # If a user has an explicit permission list,
                # ONLY those are allowed.
                if perm_name not in perms:
                    flash("You don't have permission to do that.")
                    return redirect(url_for("home"))
                return fn(*args, **kwargs)

            # 3) Default permissions by role when permissions field is empty
            default_perms_by_role = {
                "staff": {
                    "items:view", "items:add", "items:edit",
                    "photos:upload",
                    "suppliers:view", "suppliers:edit",
                    "sales:edit",
                    "consignors:view", "consignors:edit",
                    # NOTE: NO "reports:view" here on purpose
                },
                "viewer": {
                    "items:view",
                },
            }

            allowed = perm_name in default_perms_by_role.get(role, set())
            if not allowed:
                flash("You don't have permission to do that.")
                return redirect(url_for("home"))

            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ---- Flask app setup ----
app = Flask(__name__)
# ---- session/flash secret key ----
import os
_secret = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    _secret = os.urandom(32).hex()
app.config["SECRET_KEY"] = _secret

# Folder for driver's license images (under /static/licenses)
LICENSE_UPLOAD_FOLDER = os.path.join(app.root_path, "static", "licenses")
os.makedirs(LICENSE_UPLOAD_FOLDER, exist_ok=True)

ALLOWED_LICENSE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}

def allowed_license_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_LICENSE_EXTENSIONS
    )

# ===== Driver's license upload config =====
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
LICENSE_UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "licenses")
os.makedirs(LICENSE_UPLOAD_FOLDER, exist_ok=True)

app.config["LICENSE_UPLOAD_FOLDER"] = LICENSE_UPLOAD_FOLDER
ALLOWED_LICENSE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}


def allowed_license_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_LICENSE_EXTENSIONS

# (optional) tiny log to confirm source
app.logger.info("SECRET_KEY source: %s", "ENV" if os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") else "GENERATED")

from flask import g

@app.before_request
def _attach_company():
    g.user = None
    g.company = None
    uid = session.get("user_id")
    if uid:
        u = User.query.get(uid)
        if u:
            g.user = u
            g.company = getattr(u, "company", None)

# --- Money formatting helper ---
@app.template_filter("money")
def money_filter(cents):
    """Convert cents to $1,234.56 format for templates"""
    if cents is None:
        return ""
    return f"${cents/100:,.2f}"

# ---- Paths & Database (ABSOLUTE path so we always hit the same DB) ----
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Use DATABASE_URL from Render/Postgres
db_uri = os.environ.get("DATABASE_URL")
if not db_uri:
    raise RuntimeError("DATABASE_URL is not set")
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
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

# Make the DB engine more robust against dropped/SSL connections
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,   # check connections before using them
    "pool_recycle": 280,     # recycle connections every ~5 minutes
}
# ---- DB handle ----
db = SQLAlchemy(app)

# ---------------------------
# GLOBAL LOGIN REQUIREMENT
# ---------------------------


@app.before_request
def _require_login_globally():
    # 1) Always allow static files (CSS, JS, images)
    if request.path.startswith("/static/"):
        return

    # 2) Allow the login page itself without being logged in
    if request.endpoint in ("login", "login_post"):
        return

    # 3) If not logged in, force login (keep where they were trying to go)
    if not session.get("user_id"):
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login", next=nxt))

    # 4) From here on, we know the user IS logged in.
    #    Lock down /admin* and /users* so only real admins can see them.
    if request.path.startswith("/admin") or request.path.startswith("/users"):
        if (session.get("role") or "").lower() != "admin":
            flash("Admin access required")
            return redirect(url_for("home"))

# ---------------------------
# DATABASE MODELS (canonical)
# ---------------------------
from datetime import datetime
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="staff")
    # comma-separated list of explicit permissions
    permissions = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ---------- Password helpers ----------
    def set_password(self, raw: str):
        from werkzeug.security import generate_password_hash
        try:
            self.password_hash = generate_password_hash(raw, method="scrypt")
        except Exception:
            self.password_hash = generate_password_hash(raw, method="pbkdf2:sha256")

    def check_password(self, raw: str) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, raw)

    # ---------- Permission helpers ----------
    def perm_set(self):
        """Return a set of permission strings from the comma-separated field."""
        return {
            p.strip()
            for p in (self.permissions or "").split(",")
            if p.strip()
        }

    def has_perm(self, perm: str) -> bool:
        """
        Check if user has a given permission.

        * Admins can do everything.
        * If `permissions` is non-empty, ONLY those are used.
        * If `permissions` is empty, fall back to safe role defaults.
        """
        role = (self.role or "").lower()

        # Admin can do anything
        if role == "admin":
            return True

        # If explicit permissions are set, use only those
        perms = self.perm_set()
        if perms:
            return perm in perms

        # ---- SAFE DEFAULTS (no reports / statements by default) ----
        staff_perms = {
            "items:view", "items:add", "items:edit",
            "photos:upload",
            "suppliers:view", "suppliers:edit",
            "sales:edit",
            "consignors:view", "consignors:edit",
            # intentionally **no** "reports:view" or "payouts:view" here
        }
        viewer_perms = {
            "items:view",
        }

        if role == "staff":
            return perm in staff_perms
        if role == "viewer":
            return perm in viewer_perms

        return False
class Consignor(db.Model):
    __tablename__ = "consignors"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)

    email = db.Column(db.String(255))
    phone = db.Column(db.String(50))

    street = db.Column(db.String(240))
    city = db.Column(db.String(120))
    state = db.Column(db.String(40))
    postal_code = db.Column(db.String(20))

    notes = db.Column(db.Text)

    commission_pct = db.Column(db.Float, default=0.0)
    advance_balance = db.Column(db.Float, default=0.0)

    license_image = db.Column(db.String(255))

    sell_at_auction = db.Column(db.Boolean, default=True)
    sell_in_store = db.Column(db.Boolean, default=False)
    sell_on_ebay = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- One-time safe schema tweaks for Consignor + Items (Postgres) ---
with app.app_context():
    # These are safe to run multiple times thanks to IF NOT EXISTS
    db.session.execute(text("""
        ALTER TABLE consignors
        ADD COLUMN IF NOT EXISTS street VARCHAR(240);
    """))
    db.session.execute(text("""
        ALTER TABLE consignors
        ADD COLUMN IF NOT EXISTS city VARCHAR(120);
    """))
    db.session.execute(text("""
        ALTER TABLE consignors
        ADD COLUMN IF NOT EXISTS state VARCHAR(40);
    """))
    db.session.execute(text("""
        ALTER TABLE consignors
        ADD COLUMN IF NOT EXISTS postal_code VARCHAR(20);
    """))

    # ✅ New: item location column
    db.session.execute(text("""
        ALTER TABLE items
        ADD COLUMN IF NOT EXISTS location VARCHAR(120);
    """))

    db.session.commit()

    # ✅ NEW: location fields on items
    db.session.execute(text("""
        ALTER TABLE items
        ADD COLUMN IF NOT EXISTS location_building VARCHAR(80);
    """))
    db.session.execute(text("""
        ALTER TABLE items
        ADD COLUMN IF NOT EXISTS location_room VARCHAR(80);
    """))
    db.session.execute(text("""
        ALTER TABLE items
        ADD COLUMN IF NOT EXISTS location_shelf VARCHAR(80);
    """))
    db.session.execute(text("""
        ALTER TABLE items
        ADD COLUMN IF NOT EXISTS location_tote VARCHAR(80);
    """))

    db.session.commit()
    
class Supplier(db.Model):
    __tablename__ = "suppliers"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(50))
    email = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Contract(db.Model):
    __tablename__ = "contracts"
    def get_open_contract(consignor_id: int):
        """Return the latest DRAFT contract for a consignor, or None."""
        return (
            Contract.query
            .filter_by(consignor_id=consignor_id, status="draft")
            .order_by(Contract.id.desc())
            .first()
        )
    id = db.Column(db.Integer, primary_key=True)

    # Link to consignor
    consignor_id = db.Column(db.Integer, db.ForeignKey("consignors.id"), nullable=False)

    # Basic info
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default="draft")

    # Totals for quick reference
    total_items = db.Column(db.Integer)
    total_estimated_value_cents = db.Column(db.Integer)

    # Signature + notes
    signature_data = db.Column(db.Text)  # will later store base64 or similar
    notes = db.Column(db.Text)

    # Relationships
    consignor = db.relationship("Consignor", backref="contracts")
class Item(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))
    # --- NEW Item Location Fields ---
    building        = db.Column(db.String(80))
    room            = db.Column(db.String(80))
    shelf           = db.Column(db.String(80))
    tote            = db.Column(db.String(80))
    location        = db.Column(db.String(120))
    location_detail = db.Column(db.String(200))
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
    asking_cents     = db.Column(db.Integer, nullable=True)
    status           = db.Column(db.String(20), nullable=False, default="available")  # "available" or "sold"

    # Dates / parties
    sale_date   = db.Column(db.Date)            # use Date if parse_date returns a date
    buyer_name  = db.Column(db.String(120))     # <-- matches importer

    # Supplier (name + FK)
    supplier    = db.Column(db.String(140))     # optional free-text name
    supplier_id = db.Column(db.Integer, db.ForeignKey("suppliers.id"))  # <-- table name matches Supplier.__tablename__

    # Misc
    notes = db.Column(db.Text)
    
    # Inventory location
    location = db.Column(db.String(120))        # e.g. "Back room", "Trailer", "Garage"
    location_detail = db.Column(db.String(240)) # e.g. "Shelf A3", "Bin 12", "Rack 4"# Location (for warehouse / room / shelf / tote)
    location_building = db.Column(db.String(80))  # e.g., WH1, Store, Garage
    location_room     = db.Column(db.String(80))  # e.g., Back Room, Aisle 3
    location_shelf    = db.Column(db.String(80))  # e.g., Shelf 2, Rack B
    location_tote     = db.Column(db.String(80))  # e.g., Tote 14, Bin C

    @property
    def location_display(self):
        """Nice one-line version: 'Store / Back Room / Shelf 2 / Tote 14'."""
        parts = [
            self.location_building,
            self.location_room,
            self.location_shelf,
            self.location_tote,
        ]
        parts = [p for p in parts if p]
        return " / ".join(parts)
    # Relationship
    supplier_ref = db.relationship("Supplier", backref="items", lazy="joined")

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
   
    # Contract this item belongs to (optional)
    contract_id = db.Column(
        db.Integer,
        db.ForeignKey("contracts.id"),
        nullable=True,
    )
    contract = db.relationship("Contract", backref="items")
    # ----- Computed helpers (unchanged) -----
    @property
    def cost(self):
        return (self.cost_cents or 0) / 100.0

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


    @property
    def asking(self):
        """Return asking price in dollars from asking_cents."""
        if self.asking_cents is None:
            return None
        return self.asking_cents / 100.0
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

class Payout(db.Model):
    __tablename__ = "payouts"
    id           = db.Column(db.Integer, primary_key=True)
    consignor_id = db.Column(db.Integer, db.ForeignKey("consignors.id"), nullable=False)
    sale_id      = db.Column(db.Integer, db.ForeignKey("sales.id"))
    amount       = db.Column(db.Numeric(10,2), nullable=False, default=0)
    method       = db.Column(db.String(30))      # cash / check / ACH / PayPal
    reference    = db.Column(db.String(100))     # check # / txn id
    notes        = db.Column(db.String(200))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    consignor    = db.relationship("Consignor", backref="payouts")
    sale         = db.relationship("Sale", backref="payouts")

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

        # Correct table name
        while connection.execute(
            sqltext("SELECT 1 FROM items WHERE sku = :s"),
            {"s": sku}
        ).fetchone():
            i += 1
            sku = f"{base}-{i}"

        # Correct table name
        connection.execute(
            sqltext("UPDATE items SET sku=:s WHERE id=:id"),
            {"s": sku, "id": target.id}
        )

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
@app.context_processor
def inject_settings():
    return {
        "get_settings": lambda: Settings.query.get(1)
    }
class Sale(db.Model):
    __tablename__ = "sales"

    id = db.Column(db.Integer, primary_key=True)
    consignor_id = db.Column(
        db.Integer,
        db.ForeignKey("consignors.id"),
        nullable=False
    )
    item_id = db.Column(db.Integer, db.ForeignKey("items.id"))  # if you have Item model
    quantity = db.Column(db.Integer, default=1)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    fees = db.Column(db.Numeric(10, 2), default=0)              # eBay/processing fees
    shipping_cost = db.Column(db.Numeric(10, 2), default=0)     # what YOU paid to ship
    channel = db.Column(db.String(30))                          # ebay, in_person, etc
    external_order_id = db.Column(db.String(100))               # eBay order id
    sold_at = db.Column(db.DateTime, default=datetime.utcnow)

    consignor = db.relationship("Consignor", backref="sales")
    item = db.relationship("Item", backref="sales")  # if Item exists
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
asking = db.Column(db.Float, nullable=True)
   # optional asking price

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

from sqlalchemy import func  # make sure this import is near the top

@require_perm("items:view")
@app.get("/items")
def items_list():
    # ------- Filters from query string -------
    search       = (request.args.get("q") or "").strip()
    ownership    = (request.args.get("ownership") or "").strip().lower()
    status       = (request.args.get("status") or "").strip().lower()
    consignor_id = request.args.get("consignor_id", type=int)

    building = (request.args.get("building") or "").strip()
    room     = (request.args.get("room") or "").strip()
    shelf    = (request.args.get("shelf") or "").strip()
    tote     = (request.args.get("tote") or "").strip()
    location = (request.args.get("location") or "").strip()

    # ------- Base query -------
    q = Item.query

    # Text search
    if search:
        like = f"%{search}%"
        q = q.filter(
            db.or_(
                Item.title.ilike(like),
                Item.category.ilike(like),
                Item.sku.ilike(like),
                Item.notes.ilike(like),
                Item.buyer_name.ilike(like),
                Item.consignor.ilike(like),
            )
        )

    # Ownership filter
    if ownership in ("owned", "consigned", "internal"):
        q = q.filter(Item.ownership == ownership)

    # Status filter
    if status in ("available", "sold"):
        q = q.filter(Item.status == status)

    # Consignor filter
    if consignor_id:
        q = q.filter(Item.consignor_id == consignor_id)

    # Location filters
    if building:
        q = q.filter(Item.building == building)
    if room:
        q = q.filter(Item.room == room)
    if shelf:
        q = q.filter(Item.shelf == shelf)
    if tote:
        q = q.filter(Item.tote == tote)
    if location:
        loc_like = f"%{location}%"
        q = q.filter(Item.location.ilike(loc_like))

    # ------- Load items -------
    items = q.order_by(Item.created_at.desc()).all()

    # ------- Photo counts per item (for "needs photos" flag) -------
    photo_counts = {}
    if items:
        ids = [it.id for it in items]
        rows = (
            db.session.query(Photo.item_id, func.count(Photo.id))
            .filter(Photo.item_id.in_(ids))
            .group_by(Photo.item_id)
            .all()
        )
        photo_counts = {item_id: count for (item_id, count) in rows}

    # ------- Totals (in dollars) -------
    total_cost = sum((it.cost_cents or 0) for it in items) / 100.0
    total_sales = sum((it.sale_price_cents or 0) for it in items) / 100.0
    total_consignor = sum(
        (it.consignor_payout or 0) for it in items
        if it.consignor_payout is not None
    ) / 100.0
    total_house = sum(
        (it.house_net or 0) for it in items
        if it.house_net is not None
    ) / 100.0
    total_profit = total_house  # house_net already = profit for you

    totals = {
        "cost": total_cost,
        "sales": total_sales,
        "consignor": total_consignor,
        "house": total_house,
        "profit": total_profit,
    }

    # ------- Helper to build dropdown lists -------
    def distinct_vals(col):
        rows = db.session.query(col).distinct().order_by(col.asc()).all()
        return [r[0] for r in rows if r[0]]

    buildings = distinct_vals(Item.building)
    rooms     = distinct_vals(Item.room)
    shelves   = distinct_vals(Item.shelf)
    totes     = distinct_vals(Item.tote)

    consignors = Consignor.query.order_by(Consignor.name.asc()).all()

    return render_template(
        "items.html",
        items=items,
        totals=totals,
        # current filters
        q=search,
        ownership=ownership,
        status=status,
        consignor_id=consignor_id,
        building=building,
        room=room,
        shelf=shelf,
        tote=tote,
        location=location,
        # dropdown data
        buildings=buildings,
        rooms=rooms,
        shelves=shelves,
        totes=totes,
        consignors=consignors,
        # NEW: photo count map
        photo_counts=photo_counts,
    )

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

@require_perm("items:add")
@app.get("/items/new")
def item_new():
    consignors = Consignor.query.order_by(Consignor.name.asc()).all()
    return render_template("item_form.html", item=None, consignors=consignors)

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

    # Basic fields
    title = (request.form.get("title") or "").strip()
    category = (request.form.get("category") or "").strip() or None
    ownership = (request.form.get("ownership") or "owned").strip().lower()

    # Money fields (stored as cents)
    cost_cents = to_cents(request.form.get("cost"))
    asking_cents = to_cents(request.form.get("asking"))

    # Location fields
    building = (request.form.get("building") or "").strip() or None
    room     = (request.form.get("room") or "").strip() or None
    shelf    = (request.form.get("shelf") or "").strip() or None
    tote     = (request.form.get("tote") or "").strip() or None
    location       = (request.form.get("location") or "").strip() or None
    location_detail = (request.form.get("location_detail") or "").strip() or None
    
    # Other optional fields
    notes          = (request.form.get("notes") or "").strip() or None
    consignor_name = (request.form.get("consignor") or "").strip() or None
    supplier_name  = (request.form.get("supplier") or "").strip() or None
    sale_date_str  = (request.form.get("sale_date") or "").strip() or None

    # Parse sale_date if present
    sale_date = parse_date(sale_date_str)

    # Use provided SKU if present, otherwise auto-generate
    sku = (request.form.get("sku") or "").strip()
    if not sku:
        sku = next_sku()

    # Resolve consignor_name -> consignor_id (optional)
    consignor_id = None
    consignor_obj = None
    if consignor_name:
        consignor_obj = Consignor.query.filter(
            Consignor.name.ilike(consignor_name)
        ).first()
        if not consignor_obj:
            consignor_obj = Consignor(name=consignor_name)
            db.session.add(consignor_obj)
            db.session.flush()
        consignor_id = consignor_obj.id

    # Resolve supplier_name -> supplier_id (optional)
    supplier_id = None
    if supplier_name:
        s = Supplier.query.filter(Supplier.name.ilike(supplier_name)).first()
        if not s:
            s = Supplier(name=supplier_name)
            db.session.add(s)
            db.session.flush()
        supplier_id = s.id

    # ---- Auto-create / reuse consignment contract for this consignor ----
    contract = None
    if ownership == "consigned" and consignor_id:
        if hasattr(Contract, "get_open_contract"):
            contract = Contract.get_open_contract(consignor_id)
        else:
            contract = (
                Contract.query
                .filter_by(consignor_id=consignor_id, status="draft")
                .order_by(Contract.id.desc())
                .first()
            )

        if not contract:
            contract = Contract(
                consignor_id=consignor_id,
                created_at=datetime.utcnow().isoformat(timespec="seconds"),
                status="draft",
            )
            db.session.add(contract)
            db.session.flush()

    # If this is NOT consigned, we do not tie it to a consignor/contract
    if ownership != "consigned":
        consignor_name = None
        consignor_id = None
        contract = None

    # Create the item (linked to consignor + contract if applicable)
    item = Item(
        sku=sku,
        title=title,
        ownership=ownership,
        category=category,
        cost_cents=cost_cents,
        asking_cents=asking_cents,
        status="available",
        consignor=consignor_name,
        consignor_id=consignor_id,
        supplier=supplier_name,
        supplier_id=supplier_id,
        notes=notes,
        sale_date=sale_date,
        contract_id=contract.id if contract else None,
        building=building,
        room=room,
        shelf=shelf,
        tote=tote,
        location=location,
        location_detail=location_detail,
    )

    db.session.add(item)
    db.session.commit()
    flash("Item created.", "success")
    return redirect(url_for("items_list"))

@require_perm("items:edit")
@app.get("/items/<int:item_id>/edit")
def item_edit(item_id):
    # Load the item being edited
    item = Item.query.get_or_404(item_id)

    # Load consignors for the dropdown
    consignors = Consignor.query.order_by(Consignor.name.asc()).all()

    # Re-use the same form template as "New Item"
    return render_template("item_form.html", item=item, consignors=consignors)

@app.get("/items/<int:item_id>/clone")
@require_perm("items:edit")
def item_clone(item_id):
    original = Item.query.get_or_404(item_id)

    # Create new empty item (not yet committed)
    cloned = Item(
        title = original.title,
        category = original.category,
        ownership = original.ownership,
        consignor = original.consignor,
        consignor_id = original.consignor_id,
        notes = original.notes,
        cost_cents = original.cost_cents,
        asking_cents = original.asking_cents,
        building = original.building,
        room = original.room,
        shelf = original.shelf,
        tote = original.tote,
        location = original.location,
        location_detail = original.location_detail,
        status = "draft"
    )

    db.session.add(cloned)
    db.session.commit()

    return redirect(f"/items/{cloned.id}/edit")   
@require_perm("items:edit")
@app.post("/items/<int:item_id>/edit")
def item_update(item_id):
    item = Item.query.get_or_404(item_id)

    def dollars_to_cents(val):
        val = (val or "").strip()
        if not val:
            return None
        try:
            return int(round(float(val) * 100))
        except Exception:
            return None

    # Basic fields
    title = (request.form.get("title") or "").strip()
    if title:
        item.title = title

    ownership = (request.form.get("ownership") or "owned").strip().lower()
    item.ownership = ownership

    item.category      = (request.form.get("category") or "").strip() or None
    item.cost_cents    = dollars_to_cents(request.form.get("cost"))
    item.asking_cents  = dollars_to_cents(request.form.get("asking"))

    # Location fields
    item.building = (request.form.get("building") or "").strip() or None
    item.room     = (request.form.get("room") or "").strip() or None
    item.shelf    = (request.form.get("shelf") or "").strip() or None
    item.tote     = (request.form.get("tote") or "").strip() or None

    # Notes
    notes = (request.form.get("notes") or "").strip()
    item.notes = notes or None
    loc = (request.form.get("location") or "").strip()
    item.location = loc or None

    loc_detail = (request.form.get("location_detail") or "").strip()
    item.location_detail = loc_detail or None
    
    # Consignor selection from dropdown
    consignor_name = (request.form.get("consignor") or "").strip() or None
    item.consignor = consignor_name

    consignor_id = None
    contract = None

    if ownership == "consigned" and consignor_name:
        # Look up or create consignor
        c = Consignor.query.filter(
            Consignor.name.ilike(consignor_name)
        ).first()
        if not c:
            c = Consignor(name=consignor_name)
            db.session.add(c)
            db.session.flush()
        consignor_id = c.id
        item.consignor_id = consignor_id

        # Open (or create) draft contract
        if hasattr(Contract, "get_open_contract"):
            contract = Contract.get_open_contract(consignor_id)
        else:
            contract = (
                Contract.query
                .filter_by(consignor_id=consignor_id, status="draft")
                .order_by(Contract.id.desc())
                .first()
            )

        if not contract:
            contract = Contract(
                consignor_id=consignor_id,
                created_at=datetime.utcnow().isoformat(timespec="seconds"),
                status="draft",
            )
            db.session.add(contract)
            db.session.flush()

        item.contract_id = contract.id

    else:
        # Not consigned anymore → clear links
        item.consignor_id = None
        item.contract_id = None

    db.session.commit()
    flash("Item updated")
    return redirect(url_for("items_list"))

@require_perm("items:delete")
@app.post("/items/<int:item_id>/delete")
def item_delete(item_id):
    ...
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted")
    return redirect(url_for("items_list"))

@require_perm("items:sell")
@app.post("/items/<int:item_id>/sell")
def item_sell(item_id):
    ...
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
@require_perm("photos:upload")
@app.get("/upload")
def upload_form():
    ...
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template("upload.html", items=items)


@require_perm("photos:upload")
@app.post("/upload")
def upload_post():
    ...
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
@require_perm("reports:view")
def reports():
    ...
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
from sqlalchemy import func  # you already import this, just be sure it's there

# ========= DETAILED REPORTS =========

from sqlalchemy import func

# ---------- CONSIGNOR PERFORMANCE REPORT ----------
@app.get("/reports/consignors")
@require_perm("reports:view")
def report_consignors():
    """Consignor performance report."""

    # Optional date filters for SOLD items
    start = (request.args.get("start") or "").strip()
    end   = (request.args.get("end") or "").strip()

    sold_q = Item.query.filter(Item.status == "sold")

    start_date = None
    end_date = None

    if start:
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d").date()
            sold_q = sold_q.filter(Item.sale_date >= start_date)
        except Exception:
            start_date = None

    if end:
        try:
            end_date = datetime.strptime(end, "%Y-%m-%d").date()
            sold_q = sold_q.filter(Item.sale_date <= end_date)
        except Exception:
            end_date = None

    # Aggregate by consignor
    sold_sub = (
        sold_q.with_entities(
            Item.consignor_id.label("consignor_id"),
            func.count(Item.id).label("count"),
            func.coalesce(func.sum(Item.cost_cents), 0).label("cost_cents"),
            func.coalesce(func.sum(Item.sale_price_cents), 0).label("sale_cents"),
        )
        .group_by(Item.consignor_id)
        .subquery()
    )

    rows = (
        db.session.query(
            Consignor.id,
            Consignor.name,
            sold_sub.c.count,
            sold_sub.c.cost_cents,
            sold_sub.c.sale_cents,
        )
        .outerjoin(sold_sub, Consignor.id == sold_sub.c.consignor_id)
        .order_by(func.coalesce(sold_sub.c.sale_cents, 0).desc())
        .all()
    )

    consignor_rows = []
    for r in rows:
        cost  = (r.cost_cents or 0) / 100.0
        sales = (r.sale_cents or 0) / 100.0
        consignor_rows.append({
            "id":    r.id,
            "name":  r.name,
            "count": r.count or 0,
            "cost":  cost,
            "sales": sales,
            "profit": sales - cost,
        })

    # Summary for the template (and to show in the header)
    summary = {
        "start": start_date,
        "end":   end_date,
    }

    # CSV export
    if request.args.get("export") == "csv":
        return _csv_response("report_consignors.csv", consignor_rows)

    # HTML view
    return render_template(
        "report_consignors.html",
        rows=consignor_rows,
        summary=summary,
    )

# ---------- CHANNEL PERFORMANCE REPORT ----------
@app.get("/reports/channels")
@require_perm("reports:view")
def report_channels():
    """
    Channel performance report (auction / store / eBay / etc.).
    Uses the Sale table and aggregates in Python so it works even if
    some columns are missing or named slightly differently.
    """
    # Optional date filters
    start = (request.args.get("start") or "").strip()
    end   = (request.args.get("end") or "").strip()

    sale_q = Sale.query
    start_date = None
    end_date = None

    if start:
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d").date()
            # assume Sale has created_at; if not, you can swap to sale_date
            sale_q = sale_q.filter(Sale.created_at >= datetime.combine(start_date, datetime.min.time()))
        except Exception:
            start_date = None

    if end:
        try:
            end_date = datetime.strptime(end, "%Y-%m-%d").date()
            sale_q = sale_q.filter(Sale.created_at <= datetime.combine(end_date, datetime.max.time()))
        except Exception:
            end_date = None

    sales = sale_q.all()

    # Aggregate by channel
    channels = {}  # channel -> dict
    for s in sales:
        ch = (getattr(s, "channel", None) or "unknown").lower()

        if ch not in channels:
            channels[ch] = {
                "channel": ch,
                "count": 0,
                "sales_cents": 0,
                "shipping_cents": 0,
                "fees_cents": 0,
                "tax_cents": 0,
            }

        row = channels[ch]
        qty = getattr(s, "qty", 1) or 1

        row["count"]          += qty
        row["sales_cents"]    += (getattr(s, "sale_price_cents", 0) or 0)
        row["shipping_cents"] += (getattr(s, "shipping_fee_cents", 0) or 0)
        row["fees_cents"]     += (getattr(s, "marketplace_fee_cents", 0) or 0)
        row["tax_cents"]      += (getattr(s, "tax_cents", 0) or 0)

    # Convert to list with dollar amounts
    channel_rows = []
    for ch_key, data in channels.items():
        sales_d    = data["sales_cents"] / 100.0
        shipping_d = data["shipping_cents"] / 100.0
        fees_d     = data["fees_cents"] / 100.0
        tax_d      = data["tax_cents"] / 100.0
        net_d      = sales_d + shipping_d - fees_d - tax_d

        channel_rows.append({
            "channel": ch_key,
            "count": data["count"],
            "sales": sales_d,
            "shipping": shipping_d,
            "fees": fees_d,
            "tax": tax_d,
            "net": net_d,
        })

    # Overall summary
    summary = {
        "start": start_date,
        "end": end_date,
        "total_sales": sum(r["sales"] for r in channel_rows),
        "total_shipping": sum(r["shipping"] for r in channel_rows),
        "total_fees": sum(r["fees"] for r in channel_rows),
        "total_tax": sum(r["tax"] for r in channel_rows),
        "total_net": sum(r["net"] for r in channel_rows),
    }

    # CSV export
    if request.args.get("export") == "csv":
        return _csv_response("report_channels.csv", channel_rows)

    # HTML view
    return render_template(
        "report_channels.html",
        rows=channel_rows,
        summary=summary,
    )
@app.get("/reports/aging")
@require_perm("reports:view")
def report_aging():
    """Inventory aging – how long unsold items have been listed."""

    # Optional filters on created_at, mostly for consistency with other reports
    start = (request.args.get("start") or "").strip()
    end   = (request.args.get("end") or "").strip()

    item_q = Item.query.filter(Item.status != "sold")
    start_date = None
    end_date = None

    if start:
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d").date()
            item_q = item_q.filter(Item.created_at >= start_date)
        except Exception:
            start_date = None

    if end:
        try:
            end_date = datetime.strptime(end, "%Y-%m-%d").date()
            end_dt = datetime.combine(end_date, datetime.max.time())
            item_q = item_q.filter(Item.created_at <= end_dt)
        except Exception:
            end_date = None

    items = item_q.all()
    today = date.today()

    # Buckets for aging
    buckets = {
        "0–30 days":  {"count": 0, "cost_cents": 0},
        "31–60 days": {"count": 0, "cost_cents": 0},
        "61–90 days": {"count": 0, "cost_cents": 0},
        "90+ days":   {"count": 0, "cost_cents": 0},
    }

    for it in items:
        if not it.created_at:
            continue

        age_days = (today - it.created_at.date()).days
        if age_days <= 30:
            key = "0–30 days"
        elif age_days <= 60:
            key = "31–60 days"
        elif age_days <= 90:
            key = "61–90 days"
        else:
            key = "90+ days"

        buckets[key]["count"] += 1
        buckets[key]["cost_cents"] += (it.cost_cents or 0)

    # Convert to list with dollar amounts
    aging_rows = []
    for label in ["0–30 days", "31–60 days", "61–90 days", "90+ days"]:
        data = buckets[label]
        aging_rows.append({
            "label": label,
            "count": data["count"],
            "cost":  (data["cost_cents"] or 0) / 100.0,
        })

    # Summary for header
    total_items = sum(r["count"] for r in aging_rows)
    total_cost  = sum(r["cost"] for r in aging_rows)

    summary = {
        "start":       start_date,
        "end":         end_date,
        "total_items": total_items,
        "total_cost":  total_cost,
    }

    # CSV export
    if request.args.get("export") == "csv":
        return _csv_response("report_aging.csv", aging_rows)

    # HTML view
    return render_template(
        "report_aging.html",
        rows=aging_rows,
        summary=summary,
    )

@app.get("/reports/movers")
@require_perm("reports:view")
def report_movers():
    """Fast vs slow movers based on days to sell."""

    # Optional date filters based on sale_date
    start = (request.args.get("start") or "").strip()
    end   = (request.args.get("end") or "").strip()

    q = Item.query.filter(Item.status == "sold")

    start_date = None
    end_date = None

    if start:
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d").date()
            q = q.filter(Item.sale_date >= start_date)
        except Exception:
            start_date = None

    if end:
        try:
            end_date = datetime.strptime(end, "%Y-%m-%d").date()
            q = q.filter(Item.sale_date <= end_date)
        except Exception:
            end_date = None

    items = q.order_by(Item.sale_date.desc()).all()

    summary = {
        "start": start_date,
        "end": end_date,
    }

    # Build row list
    rows = []
    for it in items:
        if not it.created_at or not it.sale_date:
            continue

        days_to_sell = (it.sale_date - it.created_at.date()).days
        rows.append({
            "item": it,
            "sku": it.sku,
            "title": it.title,
            "days_to_sell": days_to_sell,
            "sale_price": (it.sale_price_cents or 0) / 100.0,
        })

    # Fastest 20 and slowest 20
    rows_sorted = sorted(rows, key=lambda r: r["days_to_sell"])
    fast = rows_sorted[:20]
    slow = list(reversed(rows_sorted))[:20]

    # CSV export (all movers)
    if request.args.get("export") == "csv":
        return _csv_response("report_movers.csv", rows)

    # HTML view
    return render_template(
        "report_movers.html",
        rows=rows,
        fast=fast,
        slow=slow,
        summary=summary,
    )
    
@app.get("/locations")
@require_perm("items:view")
def locations_overview():
    """
    Summary of inventory by location (building / room / shelf / tote).
    """
    # Group by full physical location
    rows = (
        db.session.query(
            Item.building,
            Item.room,
            Item.shelf,
            Item.tote,
            func.count(Item.id).label("count_items"),
            func.coalesce(func.sum(Item.cost_cents), 0).label("cost_cents"),
            func.coalesce(func.sum(Item.sale_price_cents), 0).label("sales_cents"),
        )
        .group_by(Item.building, Item.room, Item.shelf, Item.tote)
        .order_by(
            Item.building.nullsfirst(),
            Item.room.nullsfirst(),
            Item.shelf.nullsfirst(),
            Item.tote.nullsfirst(),
        )
        .all()
    )

    def cents_to_dollars(c):
        return (c or 0) / 100.0

    locations = []
    for r in rows:
        locations.append({
            "building": r.building or "",
            "room": r.room or "",
            "shelf": r.shelf or "",
            "tote": r.tote or "",
            "count_items": r.count_items or 0,
            "total_cost": cents_to_dollars(r.cost_cents),
            "total_sales": cents_to_dollars(r.sales_cents),
        })

    return render_template("locations.html", locations=locations)
    
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
@require_perm("reports:view")
def statements_index():
    ...
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

@require_perm("consignors:view")
@app.get("/contracts/<int:contract_id>")
def contract_view(contract_id):
    contract  = Contract.query.get_or_404(contract_id)
    consignor = contract.consignor
    settings  = get_settings()

    items = (
        Item.query
        .filter_by(contract_id=contract.id)
        .order_by(Item.created_at.asc())
        .all()
    )

    total_items = len(items)
    total_estimated = sum((it.asking_cents or 0) for it in items) / 100.0
    total_sale_estimate = sum((it.sale_price_cents or 0) for it in items) / 100.0

    # pick a commission % to show in the contract
    commission_pct = None
    if getattr(contract, "commission_pct", None) is not None:
        commission_pct = contract.commission_pct
    elif consignor and consignor.commission_pct is not None:
        commission_pct = consignor.commission_pct
    else:
        commission_pct = (settings.default_consignor_rate or 0.65) * 100.0

    return render_template(
        "contract_view.html",
        contract=contract,
        consignor=consignor,
        items=items,
        total_items=total_items,
        total_estimated=total_estimated,
        total_sale_estimate=total_sale_estimate,
        settings=settings,
        commission_pct=commission_pct,
    )
def _require_admin():
    if not session.get("user_id"):
        return redirect(url_for("login", next=request.path))
    if (session.get("role") or "").lower() != "admin":
        flash("Admin access required.")
        return redirect(url_for("home"))
    return None

@app.post("/contracts/<int:contract_id>/lock")
def contract_lock(contract_id):
    maybe = _require_admin()
    if maybe:
        return maybe

    contract = Contract.query.get_or_404(contract_id)
    if contract.status != "draft":
        flash("Contract is already locked.")
        return redirect(url_for("contract_view", contract_id=contract.id))

    contract.status = "locked"
    db.session.commit()
    flash("Contract locked. New items will go on a new draft contract.")
    return redirect(url_for("contract_view", contract_id=contract.id))


@app.post("/contracts/<int:contract_id>/unlock")
def contract_unlock(contract_id):
    maybe = _require_admin()
    if maybe:
        return maybe

    contract = Contract.query.get_or_404(contract_id)
    if contract.status != "locked":
        flash("Contract is not locked.")
        return redirect(url_for("contract_view", contract_id=contract.id))

    contract.status = "draft"
    db.session.commit()
    flash("Contract unlocked (be careful – items can be changed).")
    return redirect(url_for("contract_view", contract_id=contract.id))
def parse_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except:
        return None

@app.get("/consignors/<int:cid>/statement.csv")
@require_perm("reports:view")
def consignor_statement_csv(cid):
    ...
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
# ---------- Payouts ----------
@app.get("/payouts/new/<int:consignor_id>")
@require_perm("users:manage")
def payouts_new(consignor_id):
    consignor = db.session.get(Consignor, consignor_id) or abort(404)
    return render_template("payout_new.html", consignor=consignor)

@app.post("/payouts/new/<int:consignor_id>")
@require_perm("users:manage")
def payouts_create(consignor_id):
    consignor = db.session.get(Consignor, consignor_id) or abort(404)
    amount    = Decimal(request.form.get("amount", "0") or "0")
    method    = request.form.get("method") or None
    reference = request.form.get("reference") or None
    notes     = request.form.get("notes") or None
    sale_id   = request.form.get("sale_id")
    sale_id   = int(sale_id) if sale_id else None

    p = Payout(consignor_id=consignor.id, sale_id=sale_id,
               amount=amount, method=method, reference=reference, notes=notes)
    db.session.add(p)

    if sale_id:
        sale = db.session.get(Sale, sale_id)
        if sale and amount >= (sale.consignor_due or 0):
            sale.is_paid_out = True

    db.session.commit()
    flash("Payout recorded.")
    return redirect(url_for("consignor_statement", consignor_id=consignor.id))


# ---------- Consignor statement ----------

@app.get("/consignors/<int:consignor_id>/statement")
@require_perm("reports:view")
def consignor_statement(consignor_id):
    ...
    consignor = db.session.get(Consignor, consignor_id) or abort(404)

    # total owed from sales
    owed = db.session.query(func.sum(Sale.consignor_due))\
        .join(Item, Item.id == Sale.item_id)\
        .filter(Item.consignor_id == consignor.id).scalar() or 0

    # payouts made
    paid = db.session.query(func.sum(Payout.amount))\
        .filter(Payout.consignor_id == consignor.id).scalar() or 0

    balance = (owed - paid) - (consignor.advance_balance or 0)
    return render_template("consignor_statement.html",
        consignor=consignor, total_owed=owed, total_paid=paid, balance=balance)
# =========================
# CONSIGNOR MANAGEMENT
# =========================

@app.route("/consignors")
@require_perm("consignors_view")  # keep your existing permission decorator
def consignors_list():
    """
    Consignor list + basic performance stats + search.
    """
    q = (request.args.get("q") or "").strip()

    # Subquery: total items per consignor
    items_sub = (
        db.session.query(
            Item.consignor_id.label("consignor_id"),
            func.count(Item.id).label("total_items"),
        )
        .group_by(Item.consignor_id)
        .subquery()
    )

    # Subquery: SOLD items per consignor, plus cost & sales in cents
    sold_sub = (
        db.session.query(
            Item.consignor_id.label("consignor_id"),
            func.count(Item.id).label("sold_items"),
            func.coalesce(func.sum(Item.sale_price_cents), 0).label("sales_cents"),
            func.coalesce(func.sum(Item.cost_cents), 0).label("cost_cents"),
        )
        .filter(Item.status == "sold")
        .group_by(Item.consignor_id)
        .subquery()
    )

    # Base query
    query = (
        db.session.query(
            Consignor,
            func.coalesce(items_sub.c.total_items, 0).label("total_items"),
            func.coalesce(sold_sub.c.sold_items, 0).label("sold_items"),
            func.coalesce(sold_sub.c.sales_cents, 0).label("sales_cents"),
            func.coalesce(sold_sub.c.cost_cents, 0).label("cost_cents"),
        )
        .outerjoin(items_sub, items_sub.c.consignor_id == Consignor.id)
        .outerjoin(sold_sub, sold_sub.c.consignor_id == Consignor.id)
    )

    # Optional search filter
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Consignor.name.ilike(like),
                Consignor.email.ilike(like),
                Consignor.phone.ilike(like),
            )
        )

    query = query.order_by(Consignor.name)

    rows = []
    for c, total_items, sold_items, sales_cents, cost_cents in query.all():
        sales = (sales_cents or 0) / 100.0
        cost = (cost_cents or 0) / 100.0
        profit = sales - cost
        rows.append({
            "consignor": c,
            "total_items": total_items or 0,
            "sold_items": sold_items or 0,
            "sales": sales,
            "cost": cost,
            "profit": profit,
        })

    return render_template("consignors.html", rows=rows, q=q)
@app.route("/consignors/<int:consignor_id>")
def consignor_detail(consignor_id):
    consignor = Consignor.query.get_or_404(consignor_id)
    stats = get_consignor_stats(consignor_id)


    # Recent items for this consignor (new)
    items = (
        Item.query
        .filter_by(consignor_id=consignor_id)
        .order_by(Item.created_at.desc())
        .limit(50)
        .all()
    )

    return render_template(
        "consignor_detail.html",
        consignor=consignor,
        stats=stats,
        items=items,
    )




def get_consignor_stats(consignor_id):
    """Basic stats for a consignor based on the items table."""
    # Total items they have
    total_items = Item.query.filter_by(consignor_id=consignor_id).count()

    # How many items have a sale price
    sold_items = (
        Item.query
        .filter(
            Item.consignor_id == consignor_id,
            Item.sale_price_cents != None
        )
        .count()
    )

    # Sum of sale_price_cents (cents -> dollars)
    total_sales_cents = (
        db.session.query(db.func.sum(Item.sale_price_cents))
        .filter(
            Item.consignor_id == consignor_id,
            Item.sale_price_cents != None
        )
        .scalar() or 0
    )
    total_sales = round(total_sales_cents / 100.0, 2)

    return {
        "total_items": total_items,
        "sold_items": sold_items,
        "total_sales": total_sales,
    }

@app.route("/consignors/export")
@require_perm("consignors:edit")
def export_consignors():
    # Use the same filters as the consignors list
    search = (request.args.get("search") or request.args.get("q") or "").strip()
    sort_by = request.args.get("sort_by", "created_at")
    sort_dir = request.args.get("sort_dir", "desc")
    missing_dl = request.args.get("missing_dl") == "1"

    query = Consignor.query

    # Apply search
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                Consignor.name.ilike(like),
                Consignor.email.ilike(like),
                Consignor.phone.ilike(like),
            )
        )

    # Apply "missing DL" filter
    if missing_dl:
        query = query.filter(
            (Consignor.license_image == None) | (Consignor.license_image == "")
        )

    # Sorting map (same as consignors_list)
    sort_map = {
        "name": Consignor.name,
        "email": Consignor.email,
        "phone": Consignor.phone,
        "commission_pct": Consignor.commission_pct,
        "advance_balance": Consignor.advance_balance,
        "created_at": Consignor.created_at,
    }

    sort_column = sort_map.get(sort_by, Consignor.created_at)

    if sort_dir == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    consignors = query.all()

    # Build CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Name",
        "Email",
        "Phone",
        "Commission %",
        "Advance Balance",
        "DL Filename",
        "Created At",
        "Updated At",
    ])

    # Data rows
    for c in consignors:
        writer.writerow([
            c.name or "",
            c.email or "",
            c.phone or "",
            (c.commission_pct if c.commission_pct is not None else 0),
            (c.advance_balance if c.advance_balance is not None else 0),
            c.license_image or "",
            getattr(c, "created_at", "") or "",
            getattr(c, "updated_at", "") or "",
        ])

    csv_data = output.getvalue()
    output.close()

    response = Response(csv_data, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=consignors_export.csv"
    return response



@app.route("/consignors/export")
@require_perm("consignors:edit")
def consignors_export():
    consignors = Consignor.query.order_by(Consignor.created_at.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "ID",
        "Name",
        "Email",
        "Phone",
        "Commission %",
        "Advance Balance",
        "Notes",
        "License Image",
        "Created At",
        "Updated At",
    ])

    # Data rows
    for c in consignors:
        writer.writerow([
            c.id,
            c.name or "",
            c.email or "",
            c.phone or "",
            c.commission_pct or 0,
            c.advance_balance or 0,
            (c.notes or "").replace("\n", " ").replace("\r", " "),
            c.license_image or "",
            c.created_at,
            c.updated_at,
        ])

    csv_data = output.getvalue()
    output.close()

    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=consignors.csv"
    return resp



    consignors = base_q.order_by(Consignor.created_at.desc()).all()

    # Stats (item counts per consignor)
    stats_by_id = {}
    if consignors:
        rows = (
            db.session.query(
                Item.consignor_id.label("cid"),
                db.func.count(Item.id).label("total_items"),
                db.func.sum(
                    db.case(
                        (Item.status == "sold", 1),
                        else_=0,
                    )
                ).label("sold_items"),
            )
            .filter(Item.consignor_id.in_([c.id for c in consignors]))
            .group_by(Item.consignor_id)
            .all()
        )
        for r in rows:
            stats_by_id[r.cid] = {
                "total": r.total_items or 0,
                "sold": r.sold_items or 0,
            }

    return render_template(
        "consignors.html",  # or "consignors_list.html" if that’s your file name
        consignors=consignors,
        stats_by_id=stats_by_id,
        q=q,
    )


    
# ---------------------------
# CONSIGNORS: NEW (GET + POST)
# ---------------------------

# ---------------- Consignors: create ----------------

@app.route("/consignors/new", methods=["GET", "POST"])
@require_perm("consignors_edit")
def consignor_create():
    if request.method == "POST":
        name   = (request.form.get("name")   or "").strip()
        email  = (request.form.get("email")  or "").strip() or None
        phone  = (request.form.get("phone")  or "").strip() or None
        street = (request.form.get("street") or "").strip() or None
        city   = (request.form.get("city")   or "").strip() or None
        state  = (request.form.get("state")  or "").strip() or None
        postal = (request.form.get("postal_code") or "").strip() or None
        notes  = request.form.get("notes") or None

        commission_pct_raw = (request.form.get("commission_pct") or "").strip()
        advance_balance_raw = (request.form.get("advance_balance") or "").strip()
        license_file = request.files.get("license_image")
        # ✅ Sales channel checkboxes
        sell_at_auction = bool(request.form.get("sell_at_auction"))
        sell_in_store   = bool(request.form.get("sell_in_store"))
        sell_on_ebay    = bool(request.form.get("sell_on_ebay"))
        # Commission %
        try:
            commission_pct = float(commission_pct_raw) if commission_pct_raw else 0.0
        except ValueError:
            commission_pct = 0.0

        # Advance balance
        try:
            advance_balance = float(advance_balance_raw) if advance_balance_raw else 0.0
        except ValueError:
            advance_balance = 0.0

        if not name:
            flash("Name is required")
            return render_template("consignor_form.html", consignor=None)

        # Create consignor (set license_image after we know the ID)
        c = Consignor(
            name=name,
            email=email,
            phone=phone,
            city=city,
            state=state,
            postal_code=postal,
            notes=notes,
            commission_pct=commission_pct,
            advance_balance=advance_balance,
            license_image=None,
            sell_at_auction=sell_at_auction,   # ✅
            sell_in_store=sell_in_store,       # ✅
            sell_on_ebay=sell_on_ebay,         # ✅
        )
        db.session.add(c)
        db.session.commit()  # now c.id is available

        # Handle driver's license upload
        if license_file and license_file.filename:
            if allowed_license_file(license_file.filename):
                ext = license_file.filename.rsplit(".", 1)[1].lower()
                filename = secure_filename(f"license_{c.id}.{ext}")
                save_path = os.path.join(LICENSE_UPLOAD_FOLDER, filename)
                license_file.save(save_path)

                # store relative path for url_for('static', ...)
                c.license_image = f"licenses/{filename}"
                db.session.commit()
            else:
                flash("Invalid license file type. Allowed: png, jpg, jpeg, gif, pdf", "error")

        flash("Consignor created.")
        return redirect(url_for("consignors_list"))

    # GET: show blank form
    return render_template("consignor_form.html", consignor=None)


# ---------------- Consignors: edit ----------------

@app.route("/consignors/<int:cid>/edit", methods=["GET", "POST"])
@require_perm("consignors:edit")
def consignors_edit(cid):
    c = Consignor.query.get_or_404(cid)

    if request.method == "POST":
        name   = (request.form.get("name")   or "").strip()
        email  = (request.form.get("email")  or "").strip() or None
        phone  = (request.form.get("phone")  or "").strip() or None
        street = (request.form.get("street") or "").strip() or None
        city   = (request.form.get("city")   or "").strip() or None
        state  = (request.form.get("state")  or "").strip() or None
        postal = (request.form.get("postal_code") or "").strip() or None
        notes  = request.form.get("notes") or None
        ...
        c.name        = name
        c.email       = email
        c.phone       = phone
        c.street      = street
        c.city        = city
        c.state       = state
        c.postal_code = postal
        c.notes       = notes

        commission_pct_raw = (request.form.get("commission_pct") or "").strip()
        advance_balance_raw = (request.form.get("advance_balance") or "").strip()
        # ✅ Update sales channel permissions
        c.sell_at_auction = bool(request.form.get("sell_at_auction"))
        c.sell_in_store   = bool(request.form.get("sell_in_store"))
        c.sell_on_ebay    = bool(request.form.get("sell_on_ebay"))
        try:
            c.commission_pct = float(commission_pct_raw) if commission_pct_raw else 0.0
        except ValueError:
            c.commission_pct = 0.0

        try:
            c.advance_balance = float(advance_balance_raw) if advance_balance_raw else 0.0
        except ValueError:
            c.advance_balance = 0.0

        c.name = name
        c.email = email
        c.phone = phone
        c.notes = notes

        # Handle driver's license upload (replace or add)
        license_file = request.files.get("license_image")
        if license_file and license_file.filename:
            if allowed_license_file(license_file.filename):
                ext = license_file.filename.rsplit(".", 1)[1].lower()
                safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", c.name or "consignor")
                fname = f"{safe_name}_{int(time.time())}.{ext}"
                fname = secure_filename(fname)

                save_path = os.path.join(app.config["LICENSE_UPLOAD_FOLDER"], fname)
                license_file.save(save_path)
                c.license_image = f"licenses/{fname}"
            else:
                flash(
                    "Invalid license file type. Allowed: png, jpg, jpeg, gif, pdf.",
                    "error",
                )

        db.session.commit()
        flash("Consignor updated.")
        return redirect(url_for("consignors_list"))

    # GET – show populated form
    return render_template("consignor_form.html", consignor=c)

@app.post("/consignors/<int:cid>/delete")
@require_perm("consignors:edit")
def consignors_delete(cid):
    c = Consignor.query.get_or_404(cid)

    # Optional: prevent deletion if consignor has items
    has_items = Item.query.filter_by(consignor_id=cid).first()
    if has_items:
        flash("Cannot delete — consignor still has items.", "error")
        return redirect(url_for("consignors_list"))

    db.session.delete(c)
    db.session.commit()

    flash("Consignor deleted.", "info")
    return redirect(url_for("consignors_list"))
@app.get("/admin")
def admin_view():
    s = get_settings()
    return render_template("admin.html", s=s)

@app.get("/admin/import")
@require_perm("items:edit")
def admin_import():
    # Reuse the existing Upload screen
    return redirect(url_for("upload"))
    
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

@app.post("/consignors/<int:consignor_id>/delete")
@require_perm("consignors_edit")
def consignor_delete(consignor_id):
    """Delete a consignor, but only if they have no items."""
    c = Consignor.query.get_or_404(consignor_id)

    # Don't allow deleting a consignor that still has items
    item_count = Item.query.filter_by(consignor_id=c.id).count()
    if item_count > 0:
        flash(
            f"Cannot delete {c.name}: they still have {item_count} item(s).",
            "error",
        )
        # 👇 change 'consignors_list' to your actual list endpoint name if needed
        return redirect(url_for("consignors_list"))

    db.session.delete(c)
    db.session.commit()
    flash("Consignor deleted.", "success")
    # 👇 same here – use the correct endpoint for your consignor list page
    return redirect(url_for("consignors_list"))
# =========================
# UPGRADE D: DATA EXPORTS
# =========================

def _csv_items_string():
    """Return all items as a CSV string."""
    output = io.StringIO()
    w = csv.writer(output)

    w.writerow([
        "id", "sku", "title", "category", "ownership",
        "cost_cents", "asking_cents",
        "status", "sale_price_cents", "sale_date",
        "buyer_name",
        "consignor_id", "consignor_name",
        "notes",
        "created_at", "updated_at",
    ])

    for it in Item.query.order_by(Item.id.asc()).all():
        w.writerow([
            it.id,
            it.sku or "",
            it.title or "",
            it.category or "",
            it.ownership or "",
            it.cost_cents or 0,
            it.asking_cents or 0,
            it.status or "",
            it.sale_price_cents or 0,
            it.sale_date.isoformat() if it.sale_date else "",getattr(it, "buyer", None) or getattr(it, "buyer_name", None) or "",
            it.consignor_id or "",
            it.consignor or "",
            (it.notes or "").replace("\n", " ").replace("\r", " "),
            str(it.created_at or ""),
            str(it.updated_at or ""),
        ])

    csv_data = output.getvalue()
    output.close()
    return csv_data


def _csv_consignors_string():
    """Return all consignors as a CSV string."""
    output = io.StringIO()
    w = csv.writer(output)

    w.writerow([
        "id",
        "name",
        "email",
        "phone",
        "street",
        "city",
        "state",
        "postal_code",
        "commission_pct",
        "advance_balance",
        "license_image",
        "sell_at_auction",
        "sell_in_store",
        "sell_on_ebay",
        "notes",
        "created_at",
        "updated_at",
    ])

    for c in Consignor.query.order_by(Consignor.created_at.asc()).all():
        w.writerow([
            c.id,
            c.name or "",
            c.email or "",
            c.phone or "",
            getattr(c, "street", "") or "",
            getattr(c, "city", "") or "",
            getattr(c, "state", "") or "",
            getattr(c, "postal_code", "") or "",
            c.commission_pct if c.commission_pct is not None else 0,
            c.advance_balance if c.advance_balance is not None else 0,
            c.license_image or "",
            bool(getattr(c, "sell_at_auction", False)),
            bool(getattr(c, "sell_in_store", False)),
            bool(getattr(c, "sell_on_ebay", False)),
            (c.notes or "").replace("\n", " ").replace("\r", " "),
            c.created_at.isoformat() if c.created_at else "",
            c.updated_at.isoformat() if c.updated_at else "",
        ])

    csv_data = output.getvalue()
    output.close()
    return csv_data


def _csv_contracts_string():
    """Return all contracts as a CSV string."""
    output = io.StringIO()
    w = csv.writer(output)

    w.writerow([
        "id",
        "consignor_id",
        "consignor_name",
        "status",
        "created_at",
        "total_items",
        "total_estimated_value_cents",
        "notes",
    ])

    rows = (
        Contract.query
        .order_by(Contract.created_at.asc())
        .all()
    )

    for ct in rows:
        consignor = ct.consignor
        w.writerow([
            ct.id,
            ct.consignor_id,
            consignor.name if consignor else "",
            ct.status or "",
            ct.total_items or 0,
            ct.total_estimated_value_cents or 0,
            (ct.notes or "").replace("\n", " ").replace("\r", " "),
            str(ct.created_at or ""),
            ""   # no updated_at field on Contract objects
        ])

    csv_data = output.getvalue()
    output.close()
    return csv_data


def _csv_statements_string():
    """
    Export SOLD items with consignor payout + house net.
    This gives you a CSV of all statement-style info.
    """
    output = io.StringIO()
    w = csv.writer(output)

    w.writerow([
        "sku",
        "title",
        "sale_date",
        "sale_price",
        "consignor_name",
        "consignor_payout",
        "house_net",
        "rate_percent",
    ])

    items = (
        Item.query
        .filter(Item.status == "sold")
        .order_by(Item.sale_date.asc().nullslast(), Item.id.asc())
        .all()
    )

    for it in items:
        sale = it.sale_price or 0.0
        payout = (it.consignor_payout_dollars or 0.0)
        house = (it.house_net_dollars or 0.0)

        rate_pct = 0.0
        if sale:
            try:
                rate_pct = round((payout / sale) * 100.0, 2)
            except Exception:
                rate_pct = 0.0

        w.writerow([
            it.sku or "",
            (it.title or "").replace(",", " "),
            it.sale_date.isoformat() if it.sale_date else "",
            f"{sale:.2f}",
            it.consignor or "",
            f"{payout:.2f}",
            f"{house:.2f}",
            rate_pct,
        ])

    csv_data = output.getvalue()
    output.close()
    return csv_data


@require_perm("reports:view")
@app.get("/admin/export/items")
def admin_export_items():
    """Download Items CSV (used by Admin > Data Export buttons)."""
    csv_data = _csv_items_string()
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=items_export.csv"
    return resp


@require_perm("reports:view")
@app.get("/admin/export/consignors")
def admin_export_consignors():
    """Download Consignors CSV (used by Admin > Data Export buttons)."""
    csv_data = _csv_consignors_string()
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=consignors_export.csv"
    return resp


@require_perm("reports:view")
@app.get("/admin/export/contracts")
def admin_export_contracts():
    """Download Contracts CSV."""
    csv_data = _csv_contracts_string()
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=contracts_export.csv"
    return resp


@require_perm("reports:view")
@app.get("/admin/export/statements")
def admin_export_statements():
    """Download Statements-style CSV (sold items with payouts)."""
    csv_data = _csv_statements_string()
    resp = make_response(csv_data)
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = "attachment; filename=statements_export.csv"
    return resp


@require_perm("reports:view")
@app.get("/admin/export/full-backup")
def admin_export_full_backup():
    """
    Create a ZIP with all CSV exports:
    - items.csv
    - consignors.csv
    - contracts.csv
    - statements.csv
    """
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("items.csv", _csv_items_string())
        zf.writestr("consignors.csv", _csv_consignors_string())
        zf.writestr("contracts.csv", _csv_contracts_string())
        zf.writestr("statements.csv", _csv_statements_string())

    mem.seek(0)
    resp = Response(mem.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = "attachment; filename=flashbidz_backup.zip"
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
    
# ---------- USERS (Admin) ----------
def _require_admin():
    """Simple helper to ensure the current session is an admin."""
    if not session.get("user_id"):
        # Not logged in → send to login
        return redirect(url_for("login", next=request.path))
    if (session.get("role") or "").lower() != "admin":
        flash("Admin access required.")
        return redirect(url_for("home"))
    return None


@app.get("/users")
def users_list():
    # Guard
    maybe_resp = _require_admin()
    if maybe_resp:
        return maybe_resp

    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("manage_users.html", users=users)


@app.post("/users/new")
def users_new():
    if session.get("role") != "admin":
        return "Forbidden", 403

    username    = (request.form.get("username") or "").strip()
    password    = (request.form.get("password") or "").strip()
    role        = (request.form.get("role") or "staff").strip()
    permissions = (request.form.get("permissions") or "").strip()

    if not username or not password:
        flash("Username and password are required")
        return redirect(url_for("users_list"))

    # allow admin / staff / viewer
    if role not in ("admin", "staff", "viewer"):
        role = "staff"

    if User.query.filter_by(username=username).first():
        flash("That username is taken")
        return redirect(url_for("users_list"))

    u = User(username=username, role=role, permissions=permissions)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash(f"User '{username}' created")
    return redirect(url_for("users_list"))


@app.post("/users/<int:uid>/role")
def users_set_role(uid):
    if session.get("role") != "admin":
        return "Forbidden", 403

    role        = (request.form.get("role") or "staff").strip()
    permissions = (request.form.get("permissions") or "").strip()

    if role not in ("admin", "staff", "viewer"):
        role = "staff"

    u = User.query.get_or_404(uid)
    u.role = role
    u.permissions = permissions  # <-- save the comma-separated perms

    db.session.commit()
    flash(f"Role/permissions updated for {u.username}")
    return redirect(url_for("users_list"))


@app.post("/users/<int:uid>/delete")
def users_delete(uid):
    # Guard
    maybe_resp = _require_admin()
    if maybe_resp:
        return maybe_resp

    u = User.query.get_or_404(uid)

    # Don’t let you delete the main admin account by accident
    if u.username == "admin":
        flash("You cannot delete the primary 'admin' user.")
        return redirect(url_for("users_list"))

    db.session.delete(u)
    db.session.commit()

    flash(f"Deleted user '{u.username}'.")
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
# ---------- Helpers ----------
def cents(n): 
    try: return int(round(float(n)*100))
    except: return 0

# ---------- SUPPLIERS ----------
@app.route("/suppliers")
@require_perm("suppliers:view")
def suppliers_list():
    q = request.args.get("q","").strip()
    rows = Supplier.query
    if q:
        like = f"%{q}%"
        rows = rows.filter(
            db.or_(Supplier.name.ilike(like),
                   Supplier.phone.ilike(like),
                   Supplier.email.ilike(like))
        )
    rows = rows.order_by(Supplier.created_at.desc()).all()
    return render_template("suppliers_list.html", rows=rows, q=q)

@app.route("/suppliers/new", methods=["GET","POST"])
@require_perm("suppliers:edit")
def suppliers_new():
    if request.method == "POST":
        s = Supplier(
            name=request.form.get("name","").strip(),
            phone=request.form.get("phone","").strip(),
            email=request.form.get("email","").strip(),
            notes=request.form.get("notes","").strip(),
        )
        if not s.name:
            flash("Name is required.")
            return render_template("supplier_form.html", s=s)
        db.session.add(s); db.session.commit()
        flash("Supplier added.")
        return redirect(url_for("suppliers_list"))
    return render_template("supplier_form.html", s=None)

@app.route("/suppliers/<int:sid>/edit", methods=["GET","POST"])
@require_perm("suppliers:edit")
def suppliers_edit(sid):
    s = Supplier.query.get_or_404(sid)
    if request.method == "POST":
        s.name  = request.form.get("name","").strip()
        s.phone = request.form.get("phone","").strip()
        s.email = request.form.get("email","").strip()
        s.notes = request.form.get("notes","").strip()
        s.updated_at = datetime.utcnow()
        if not s.name:
            flash("Name is required.")
            return render_template("supplier_form.html", s=s)
        db.session.commit()
        flash("Saved.")
        return redirect(url_for("suppliers_list"))
    return render_template("supplier_form.html", s=s)
# =========================
# QUICK CHECKOUT (SCAN-TO-SELL)
# =========================

# cart is stored in session as a list of {"item_id": int, "qty": int}
def _get_checkout_cart():
    cart = session.get("checkout_cart")
    if not isinstance(cart, list):
        cart = []
    return cart

def _save_checkout_cart(cart):
    session["checkout_cart"] = cart
    session.modified = True

def _get_discount_cents():
    try:
        return int(session.get("checkout_discount_cents") or 0)
    except Exception:
        return 0

def _set_discount_cents(cents_val):
    session["checkout_discount_cents"] = max(0, int(cents_val or 0))
    session.modified = True

@require_perm("items:sell")
@app.get("/checkout")
def checkout_view():
    """Scanner-friendly checkout screen with discount + sounds."""
    cart = _get_checkout_cart()
    item_ids = [row["item_id"] for row in cart]
    items_by_id = {}

    if item_ids:
        items = Item.query.filter(Item.id.in_(item_ids)).all()
        items_by_id = {it.id: it for it in items}

    lines = []
    subtotal_cents = 0

    for row in cart:
        it = items_by_id.get(row["item_id"])
        if not it:
            continue

        qty = row.get("qty", 1) or 1

        # Asking price → list price → cost → 0
        price_cents = (
            (it.asking_cents if it.asking_cents is not None else None)
            or (it.price_cents if it.price_cents is not None else None)
            or (it.cost_cents or 0)
        )

        line_total = price_cents * qty
        subtotal_cents += line_total

        lines.append({
            "item": it,
            "sku": it.sku,
            "qty": qty,
            "price_dollars": price_cents / 100.0,
            "line_total_dollars": line_total / 100.0,
        })

    # Discount stored in session
    discount_cents = int(session.get("checkout_discount_cents", 0) or 0)
    if discount_cents < 0:
        discount_cents = 0

    total_cents = max(subtotal_cents - discount_cents, 0)

    beep = session.pop("checkout_beep", "")
    last_sku = session.get("checkout_last_sku")

    return render_template(
        "checkout.html",
        cart_lines=lines,
        subtotal_dollars=subtotal_cents / 100.0,
        discount_dollars=discount_cents / 100.0,
        total_dollars=total_cents / 100.0,
        today=date.today(),
        beep=beep,
        last_sku=last_sku,
    )


@require_perm("items:sell")
@app.get("/quick-checkout")
def quick_checkout_view():
    """Shortcut URL – just send them to the main checkout screen."""
    return redirect(url_for("checkout_view"))


@require_perm("items:sell")
@app.post("/checkout/scan")
def checkout_scan():
    """Scan or type a SKU, add to cart (with duplicate alert)."""
    sku = (request.form.get("sku") or "").strip()
    if not sku:
        flash("Scan or enter a SKU.", "error")
        session["checkout_beep"] = "error"
        return redirect(url_for("checkout_view"))

    item = Item.query.filter_by(sku=sku).first()
    if not item:
        flash(f"Item with SKU {sku} not found.", "error")
        session["checkout_beep"] = "error"
        return redirect(url_for("checkout_view"))

    if item.status == "sold":
        flash(f"{sku} is already marked SOLD.", "error")
        session["checkout_beep"] = "error"
        return redirect(url_for("checkout_view"))

    cart = _get_checkout_cart()

    # Duplicate scan → bump qty + special beep
    for row in cart:
        if row["item_id"] == item.id:
            row["qty"] = row.get("qty", 1) + 1
            _save_checkout_cart(cart)
            flash(f"Scanned again: {item.title} (x{row['qty']})", "info")
            session["checkout_beep"] = "duplicate"
            session["checkout_last_sku"] = sku
            return redirect(url_for("checkout_view"))

    # First time in cart
    cart.append({"item_id": item.id, "qty": 1})
    _save_checkout_cart(cart)
    flash(f"Added: {item.title}", "success")
    session["checkout_beep"] = "ok"
    session["checkout_last_sku"] = sku
    return redirect(url_for("checkout_view"))


@require_perm("items:sell")
@app.post("/checkout/undo")
def checkout_undo():
    """Undo last scan (or a specific SKU if provided)."""
    sku = (request.form.get("sku") or "").strip() or session.get("checkout_last_sku")

    if not sku:
        flash("Nothing to undo yet.", "error")
        session["checkout_beep"] = "error"
        return redirect(url_for("checkout_view"))

    item = Item.query.filter_by(sku=sku).first()
    if not item:
        flash(f"No item found with SKU {sku} to undo.", "error")
        session["checkout_beep"] = "error"
        return redirect(url_for("checkout_view"))

    cart = _get_checkout_cart()
    for idx, row in enumerate(cart):
        if row["item_id"] == item.id:
            qty = row.get("qty", 1)
            if qty > 1:
                row["qty"] = qty - 1
            else:
                cart.pop(idx)
            _save_checkout_cart(cart)
            flash(f"Undid one {item.title}.", "info")
            session["checkout_beep"] = "undo"
            return redirect(url_for("checkout_view"))

    flash(f"{sku} was not in the cart.", "error")
    session["checkout_beep"] = "error"
    return redirect(url_for("checkout_view"))


@require_perm("items:sell")
@app.post("/checkout/discount")
def checkout_discount():
    """Apply a dollar discount to the whole cart."""
    amount = request.form.get("discount") or ""
    cents = _dollars_to_cents(amount) or 0
    session["checkout_discount_cents"] = max(cents, 0)
    session.modified = True
    flash(f"Discount set to ${cents / 100.0:.2f}.", "info")
    session["checkout_beep"] = "ok"
    return redirect(url_for("checkout_view"))


@require_perm("items:sell")
@app.post("/checkout/clear")
def checkout_clear():
    """Clear cart + discount."""
    session["checkout_cart"] = []
    session["checkout_discount_cents"] = 0
    session.modified = True
    flash("Checkout cleared.", "info")
    session["checkout_beep"] = "ok"
    return redirect(url_for("checkout_view"))

def _csv_response(filename: str, rows: list[dict]):
    """Return a CSV file download from a list of dict rows."""
    # Figure out column order from the rows
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
    
def _csv_response(filename: str, rows: list[dict]):
    """Turn a list of dicts into a CSV download."""
    import io
    import csv
    from flask import Response

    # Make sure we always have at least the header row
    if not rows:
        rows = [{}]

    # Use keys of first row as fieldnames
    fieldnames = list(rows[0].keys())

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    csv_data = output.getvalue()
    output.close()

    response = Response(csv_data, mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response
    
# ---------- SALES ----------
@app.route("/sales/new", methods=["GET","POST"])
@require_perm("sales:edit")
def sales_new():
    items = Item.query.order_by(Item.created_at.desc()).limit(300).all()
    if request.method == "POST":
        item_id = int(request.form.get("item_id") or 0)
        item = Item.query.get(item_id)
        if not item:
            flash("Pick an item."); return render_template("sale_form.html", items=items)
        qty = max(1, int(request.form.get("qty") or 1))
        if item.qty_on_hand < qty:
            flash("Not enough quantity on hand.")
            return render_template("sale_form.html", items=items)
        sale = Sale(
            item_id=item.id,
            channel=request.form.get("channel") or "auction",
            buyer_name=request.form.get("buyer_name","").strip(),
            qty=qty,
            sale_price_cents=cents(request.form.get("sale_price") or 0),
            shipping_fee_cents=cents(request.form.get("shipping_fee") or 0),
            marketplace_fee_cents=cents(request.form.get("marketplace_fee") or 0),
            tax_cents=cents(request.form.get("tax") or 0),
            notes=request.form.get("notes","").strip()
        )
        item.qty_on_hand = item.qty_on_hand - qty
        db.session.add(sale); db.session.commit()
        flash("Sale recorded.")
        return redirect(url_for("sales_new"))
    return render_template("sale_form.html", items=items)

# ---------- PAYOUTS ----------
@app.route("/payouts")
@require_perm("payouts:view")
def payouts_list():
    rows = Payout.query.order_by(Payout.created_at.desc()).limit(200).all()
    return render_template("payouts_list.html", rows=rows)

@app.route("/payouts/generate", methods=["GET","POST"])
@require_perm("payouts:edit")
def payouts_generate():
    consignors = db.session.execute(db.text("SELECT DISTINCT consignor_id FROM items WHERE consignor_id IS NOT NULL")).fetchall()
    consignor_ids = [r[0] for r in consignors]
    if request.method == "POST":
        consignor_id = int(request.form.get("consignor_id") or 0)
        start = request.form.get("start") or ""
        end   = request.form.get("end") or ""
        q = db.session.query(
            db.func.coalesce(db.func.sum(Sale.sale_price_cents),0),
            db.func.coalesce(db.func.sum(Sale.shipping_fee_cents + Sale.marketplace_fee_cents),0)
        ).join(Item, Item.id==Sale.item_id)
        if consignor_id:
            q = q.filter(Item.consignor_id==consignor_id)
        if start: q = q.filter(Sale.sale_date >= start)
        if end:   q = q.filter(Sale.sale_date <  end + " 23:59:59")
        total_cents, fee_cents = q.first()
        amount_due = max(0, total_cents - fee_cents)
        p = Payout(
            consignor_id=consignor_id or 0,
            period_start=start or None,
            period_end=end or None,
            total_sales_cents=total_cents,
            fees_cents=fee_cents,
            amount_due_cents=amount_due,
            status="draft"
        )
        db.session.add(p); db.session.commit()
        flash("Payout draft created.")
        return redirect(url_for("payouts_list"))
    return render_template("payouts_generate.html", consignor_ids=consignor_ids)

# ---------- REPORTS ----------

@app.after_request
def add_no_cache_headers(response):
    # Prevent Safari/Chrome from caching admin pages
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
@app.get("/admin/upgrade/sales_channels")
def upgrade_sales_channels():
    maybe = _require_admin()
    if maybe:
        return maybe

    from sqlalchemy import text
    with db.engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE consignors ADD COLUMN IF NOT EXISTS sell_at_auction BOOLEAN DEFAULT TRUE"
        ))
        conn.execute(text(
            "ALTER TABLE consignors ADD COLUMN IF NOT EXISTS sell_in_store BOOLEAN DEFAULT FALSE"
        ))
        conn.execute(text(
            "ALTER TABLE consignors ADD COLUMN IF NOT EXISTS sell_on_ebay BOOLEAN DEFAULT FALSE"
        ))
    return "OK – sales channel columns added (or already existed)."

@app.get("/admin/upgrade/item_locations")
def upgrade_item_locations():
    maybe = _require_admin()
    if maybe:
        return maybe

    from sqlalchemy import text
    with db.engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE items ADD COLUMN IF NOT EXISTS building VARCHAR(80)"
        ))
        conn.execute(text(
            "ALTER TABLE items ADD COLUMN IF NOT EXISTS room VARCHAR(80)"
        ))
        conn.execute(text(
            "ALTER TABLE items ADD COLUMN IF NOT EXISTS shelf VARCHAR(80)"
        ))
        conn.execute(text(
            "ALTER TABLE items ADD COLUMN IF NOT EXISTS tote VARCHAR(80)"
        ))
        conn.execute(text(
            "ALTER TABLE items ADD COLUMN IF NOT EXISTS location VARCHAR(120)"
        ))
        conn.execute(text(
            "ALTER TABLE items ADD COLUMN IF NOT EXISTS location_detail VARCHAR(200)"
        ))

    return "OK – item location columns added (or already existed)."

# ✅ ALWAYS run on import (local + Render)
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    # Local dev server
    app.run(host="0.0.0.0", port=5001, debug=False)
