# migrate_add_sku.py
from datetime import datetime
from sqlalchemy import text
from app import app, db, Item

def safe_exec(sql):
    try:
        db.session.execute(text(sql))
        db.session.commit()
        print("OK:", sql)
    except Exception as e:
        db.session.rollback()
        print("SKIP/ERR:", sql, "->", e)

with app.app_context():
    # Add columns if missing (safe to re-run)
    safe_exec("ALTER TABLE item ADD COLUMN sku VARCHAR(32)")
    safe_exec("ALTER TABLE item ADD COLUMN consignor_rate FLOAT")

    # Populate SKUs that are NULL/empty
    items = Item.query.order_by(Item.id).all()
    for it in items:
        if not getattr(it, "sku", None):
            dt = it.created_at or datetime.utcnow()
            it.sku = f"FBZ-{dt.strftime('%Y%m%d')}-{it.id:04d}"
    db.session.commit()
    print(f"Done. Ensured {len(items)} items have SKUs.")

