from app import app, db, User


with app.app_context():
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    role = input("Enter role (admin/staff/viewer): ").strip().lower() or "staff"

    existing = User.query.filter_by(username=username).first()
    if existing:
        print(f"User '{username}' already exists.")
    else:
        u = User(username=username, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        print(f"✅ Created user '{username}' with role '{role}'.")


