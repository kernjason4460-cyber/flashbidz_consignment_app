import sqlite3

DB_PATH = "flashbidz.db"


def column_exists(cursor, table_name, column_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    cols = [row[1] for row in cursor.fetchall()]
    return column_name in cols


def table_exists(cursor, table_name):
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return cursor.fetchone() is not None


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 1) Create contracts table if it doesn’t exist
    if not table_exists(cur, "contracts"):
        print("Creating contracts table...")
        cur.execute(
            """
            CREATE TABLE contracts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                consignor_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                total_items INTEGER,
                total_estimated_value_cents INTEGER,
                signature_data TEXT,
                notes TEXT
            )
            """
        )
    else:
        print("contracts table already exists, skipping create.")

    # 2) Add contract_id column to items if needed
    if not column_exists(cur, "items", "contract_id"):
        print("Adding contract_id column to items...")
        cur.execute("ALTER TABLE items ADD COLUMN contract_id INTEGER")
    else:
        print("items.contract_id already exists, skipping alter.")

    conn.commit()
    conn.close()
    print("Migration complete.")


if __name__ == "__main__":
    main()
