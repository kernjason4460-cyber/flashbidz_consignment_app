from flashbidz_consignement_app.app import app, db  # adjust path if needed
with app.app_context():
    from flashbidz_consignement_app.app import Sale, Payout
    db.create_all()
    print("Ensured tables sales & payouts exist.")
