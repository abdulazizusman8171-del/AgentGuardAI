import os
import tempfile
from app.storage import SQLiteTransactionTracker

fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(fd)

try:
    db = SQLiteTransactionTracker(database_path=db_path)

    def user(email):
        return db.create_user(email, "hash", "salt", 1000)

    owner = user("owner@example.com")
    admin = user("admin@example.com")
    security = user("security@example.com")
    developer = user("developer@example.com")
    viewer = user("viewer@example.com")
    extra = user("extra@example.com")

    org = db.create_organization(owner, "Corrected Removal Tests", 1000)

    db.add_organization_member(org, owner, admin, "ADMINISTRATOR", 1100)
    db.add_organization_member(org, owner, security, "SECURITY_OFFICER", 1100)
    db.add_organization_member(org, owner, developer, "DEVELOPER", 1100)
    db.add_organization_member(org, owner, viewer, "VIEWER", 1100)
    db.add_organization_member(org, owner, extra, "VIEWER", 1100)

    # Administrator is active but cannot remove Security Officer.
    try:
        db.remove_organization_member(org, admin, security, 1200)
        raise AssertionError("Administrator removed Security Officer")
    except ValueError as error:
        assert "only remove developers or viewers" in str(error)
        print("Active administrator role restriction: PASS")

    # Developer is active but cannot remove another member.
    try:
        db.remove_organization_member(org, developer, extra, 1201)
        raise AssertionError("Developer removed another member")
    except ValueError as error:
        assert "Insufficient" in str(error)
        print("Active developer permission restriction: PASS")

    # Owner can remove administrator.
    result = db.remove_organization_member(org, owner, admin, 1202)
    assert result["status"] == "REMOVED"
    print("Owner removes administrator: PASS")

    # Owner can remove developer.
    result = db.remove_organization_member(org, owner, developer, 1203)
    assert result["status"] == "REMOVED"
    print("Owner removes developer: PASS")

    # Removed member cannot be restored.
    try:
        db.restore_organization_member(org, owner, developer, 1204)
        raise AssertionError("Removed member was restored")
    except ValueError:
        print("Removed member restoration protection: PASS")

    print("\nAll corrected permission tests passed.")

finally:
    if os.path.exists(db_path):
        os.remove(db_path)
