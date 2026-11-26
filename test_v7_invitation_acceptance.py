import os
import tempfile
from contextlib import closing
from app.storage import SQLiteTransactionTracker

fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(fd)

try:
    db = SQLiteTransactionTracker(database_path=db_path)

    owner_id = db.create_user(
        "owner@example.com", "hash1", "salt1", 1000
    )
    invited_id = db.create_user(
        "developer@example.com", "hash2", "salt2", 1000
    )
    wrong_id = db.create_user(
        "wrong@example.com", "hash3", "salt3", 1000
    )
    expired_id = db.create_user(
        "expired@example.com", "hash4", "salt4", 1000
    )

    with closing(db._connect()) as connection:
        with connection:
            connection.execute(
                "UPDATE users SET email_verified = 1"
            )

    org_id = db.create_organization(
        owner_id, "V7 Acceptance Test", 1000
    )

    invitation = db.create_organization_invitation(
        org_id, owner_id, "developer@example.com",
        "DEVELOPER", 1100
    )

    result = db.accept_organization_invitation(
        invited_id, invitation["token"], 1200
    )
    assert result["role"] == "DEVELOPER"
    print("Correct invitation acceptance: PASS")

    try:
        db.accept_organization_invitation(
            invited_id, invitation["token"], 1201
        )
        raise AssertionError("Replay was incorrectly accepted")
    except ValueError:
        print("Repeated acceptance protection: PASS")

    wrong_invitation = db.create_organization_invitation(
        org_id, owner_id, "anotherperson@example.com",
        "VIEWER", 1300
    )

    try:
        db.accept_organization_invitation(
            wrong_id, wrong_invitation["token"], 1400
        )
        raise AssertionError("Wrong email was incorrectly accepted")
    except ValueError as error:
        assert "does not match" in str(error)
        print("Wrong email protection: PASS")

    expired_invitation = db.create_organization_invitation(
        org_id, owner_id, "expired@example.com",
        "VIEWER", 1500, expires_in_seconds=60
    )

    try:
        db.accept_organization_invitation(
            expired_id, expired_invitation["token"], 1560
        )
        raise AssertionError("Expired invitation was incorrectly accepted")
    except ValueError as error:
        assert "expired" in str(error)
        print("Expired invitation protection: PASS")

    print("\nAll four invitation acceptance tests passed.")

finally:
    if os.path.exists(db_path):
        os.remove(db_path)
