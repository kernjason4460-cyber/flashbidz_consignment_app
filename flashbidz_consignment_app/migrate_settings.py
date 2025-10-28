from sqlalchemy import text
from app import app, db

def safe(sql):
    try:
        db.session.execute(text(sql))
        db.session.commit()
        print("OK:", sql.splitlines()[0])
    except Exception as e:
        db.session.rollback()
        print("SKIP/ERR:", sql.splitlines()[0], "->", e)

with app.app_context():
    safe("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        brand_name VARCHAR(120),
        brand_color VARCHAR(16),
        logo_url VARCHAR(400),
        default_consignor_rate FLOAT,
        store_address VARCHAR(240),
        store_phone VARCHAR(40),
        mail_from VARCHAR(200),
        mail_smtp VARCHAR(200),
        mail_port INTEGER,
        mail_username VARCHAR(200),
        mail_password VARCHAR(200),
        mail_use_tls BOOLEAN
    )
    """)
    # make sure there’s at least one row to start with
    row = db.session.execute(text("SELECT id FROM settings WHERE id=1")).fetchone()
    if not row:
        db.session.execute(text("""
            INSERT INTO settings (id, brand_name, brand_color, default_consignor_rate, mail_smtp, mail_port, mail_use_tls)
            VALUES (1, 'FlashBidz', '#e60000', 0.65, 'smtp.gmail.com', 587, 1)
        """))
        db.session.commit()
    print("✅ Settings table ready (id=1)")

