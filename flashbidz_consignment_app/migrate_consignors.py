# migrate_consignors.py
from sqlalchemy import text
from app import app, db

def safe(sql):
    try:
        db.session.execute(text(sql))
        db.session.commit()
        print("OK:", sql.strip().splitlines()[0])
    except Exception as e:
        db.session.rollback()
        print("SKIP/ERR:", sql.strip().splitlines()[0], "->", e)

with app.app_context():
    safe("""
    CREATE TABLE IF NOT EXISTS consignor (
        id INTEGER PRIMARY KEY,
        name VARCHAR(160) NOT NULL,
        email VARCHAR(200),
        phone VARCHAR(50),
        default_rate FLOAT,
        notes TEXT,
        created_at DATETIME
    )
    """)
    safe("ALTER TABLE item ADD COLUMN consignor_id INTEGER")

