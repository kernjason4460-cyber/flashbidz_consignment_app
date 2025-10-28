from sqlalchemy import text
from datetime import datetime
from app import app, db

def safe(sql):
    try:
        db.session.execute(text(sql))
        db.session.commit()
        print("OK:", sql.strip().splitlines()[0])
    except Exception as e:
        db.session.rollback
        print("SKIP/ERR:", sql.strip().splitlines()[0], "->", e)

with app.app_context():
    # Add columns if missing (SQLite allows ADD COLUMN)
    safe("ALTER TABLE item ADD COLUMN created_at DATETIME")
    safe("ALTER TABLE item ADD COLUMN updated_at DATETIME")

    # Backfill nulls with current time so ORDER BY works
    safe("UPDATE item SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")
    safe("UPDATE item SET updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP)")


