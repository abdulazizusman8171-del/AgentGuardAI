import os
import tempfile
from contextlib import closing
from app.storage import SQLiteTransactionTracker

fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(fd)

try:
    db = SQLiteTransactionTracker(database_path=db_path)

    def make_user(email):
        return db.create_user(email, "test_hash", "test_salt", 1000)

    owner = make_user("owner@example.com")
    admin = make_user("admin@example.com")
    developer = make_user("developer@example.com")

    with closing(db._connect()) as connection:
        with connection:
            connection.execute("UPDATE users SET email_verified = 1")

    org = db.create_organization(owner, "Revocation Test Org", 1000)
    db.add_organization_member(org, owner, admin, "ADMINISTRATOR", 1100)
    db.add_organization_member(org, owner, developer, "DEVELOPER", 1100)

    # Owner revokes invitation.
    invite1 = db.create_organization_invitation(
        org, owner, "one@example.com", "DEVELOPER", 1200
    )
    result = db.revoke_organization_invitation(
        org, owner, invite1["invitation_id"], 1300
    )
    assert result["status"] == "REVOKED"
    print("Owner revocation: PASS")

    # Administrator revokes viewer invitation.
    invite2 = db.create_organization_invitation(
        org, owner, "two@example.com", "VIEWER", 1400
    )
    result = db.revoke_organization_invitation(
        org, admin, invite2["invitation_id"], 1500
    )
    assert result["status"] == "REVOKED"
    print("Administrator viewer revocation: PASS")

    # Administrator cannot revoke security officer invitation.
    invite3 = db.create_organization_invitation(
        org, owner, "three@example.com", "SECURITY_OFFICER", 1600
    )
    try:
        db.revoke_organization_invitation(
            org, admin, invite3["invitation_id"], 1700
        )
        raise AssertionError("Administrator privilege escalation")
    except ValueError:
        print("Administrator role restriction: PASS")

    # Developer cannot revoke invitations.
    invite4 = db.create_organization_invitation(
        org, owner, "four@example.com", "VIEWER", 1800
    )
    try:
        db.revoke_organization_invitation(
            org, developer, invite4["invitation_id"], 1900
        )
        raise AssertionError("Developer revoked invitation")
    except ValueError:
        print("Developer access restriction: PASS")

    # Repeated revocation is rejected.
    try:
        db.revoke_organization_invitation(
            org, owner, invite1["invitation_id"], 2000
        )
        raise AssertionError("Repeated revocation accepted")
    except ValueError:
        print("Repeated revocation protection: PASS")

    print("\nAll five revocation tests passed.")

finally:
    if os.path.exists(db_path):
        os.remove(db_path)
