# migrate_add_sku_sql.py
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
    # Add columns if missing
    safe("ALTER TABLE item ADD COLUMN sku VARCHAR(32)")
    safe("ALTER TABLE item ADD COLUMN consignor_rate FLOAT")

    # Fill any NULL/empty SKUs deterministically from created_at/id
    safe("""
    UPDATE item
    SET sku = COALESCE(
        NULLIF(sku, ''),
        'FBZ-' || strftime('%Y%m%d', COALESCE(created_at, CURRENT_TIMESTAMP)) || '-' || printf('%04d', id)
    )
    """)

