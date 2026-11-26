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

    org = db.create_organization(owner, "Removal Test Org", 1000)

    db.add_organization_member(org, owner, admin, "ADMINISTRATOR", 1100)
    db.add_organization_member(org, owner, security, "SECURITY_OFFICER", 1100)
    db.add_organization_member(org, owner, developer, "DEVELOPER", 1100)
    db.add_organization_member(org, owner, viewer, "VIEWER", 1100)

    result = db.remove_organization_member(org, owner, developer, 1200)
    assert result["status"] == "REMOVED"
    print("Owner removes developer: PASS")

    result = db.remove_organization_member(org, owner, admin, 1201)
    assert result["status"] == "REMOVED"
    print("Owner removes administrator: PASS")

    result = db.remove_organization_member(org, owner, viewer, 1202)
    assert result["status"] == "REMOVED"
    print("Owner removes viewer: PASS")

    # Administrator cannot remove security officer.
    try:
        db.remove_organization_member(org, admin, security, 1300)
        raise AssertionError("Administrator removed security officer")
    except ValueError:
        print("Administrator role restriction: PASS")

    # Developer cannot remove members.
    try:
        db.remove_organization_member(org, developer, security, 1301)
        raise AssertionError("Developer removed member")
    except ValueError:
        print("Developer permission restriction: PASS")

    # Owner protection.
    try:
        db.remove_organization_member(org, security, owner, 1302)
        raise AssertionError("Owner was removed")
    except ValueError:
        print("Owner protection: PASS")

    # Self-removal protection.
    try:
        db.remove_organization_member(org, security, security, 1303)
        raise AssertionError("Self-removal was allowed")
    except ValueError:
        print("Self-removal protection: PASS")

    # Repeated removal protection.
    try:
        db.remove_organization_member(org, owner, developer, 1304)
        raise AssertionError("Repeated removal was allowed")
    except ValueError:
        print("Repeated removal protection: PASS")

    # Removed members cannot use restoration.
    try:
        db.restore_organization_member(org, owner, developer, 1305)
        raise AssertionError("Removed member was restored")
    except ValueError:
        print("Removed member restoration protection: PASS")

    print("\nAll member removal security tests passed.")

finally:
    if os.path.exists(db_path):
        os.remove(db_path)
