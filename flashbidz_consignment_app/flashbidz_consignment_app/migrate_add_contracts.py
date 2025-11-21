from flashbidz_consignment_app.app import db
from sqlalchemy import inspect

def run():
    inspector = inspect(db.engine)

    # 1. Create contracts table if it doesn't exist
    if "contracts" not in inspector.get_table_names():
        db.engine.execute("""
            CREATE TABLE contracts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                consignor_id INTEGER,
                created_at TEXT,
                signed_at TEXT,
                signature_data TEXT,
                notes TEXT,
                FOREIGN KEY(consignor_id) REFERENCES consignors(id)
            );
        """)

    # 2. Add contract_id column to items if missing
    item_cols = [col["name"] for col in inspector.get_columns("items")]
    if "contract_id" not in item_cols:
        db.engine.execute("""
            ALTER TABLE items ADD COLUMN contract_id INTEGER REFERENCES contracts(id);
        """)

    print("Migration complete: contracts + contract_id added.")
