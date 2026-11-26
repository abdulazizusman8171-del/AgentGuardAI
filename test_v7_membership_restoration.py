import os
import tempfile
from app.storage import SQLiteTransactionTracker

fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(fd)

try:
    db = SQLiteTransactionTracker(database_path=db_path)

    def make_user(email):
        return db.create_user(email, "test_hash", "test_salt", 1000)

    owner = make_user("owner@example.com")
    admin = make_user("admin@example.com")
    security = make_user("security@example.com")
    developer = make_user("developer@example.com")
    viewer = make_user("viewer@example.com")

    org = db.create_organization(owner, "Restoration Test Org", 1000)

    db.add_organization_member(org, owner, admin, "ADMINISTRATOR", 1100)
    db.add_organization_member(org, owner, security, "SECURITY_OFFICER", 1100)
    db.add_organization_member(org, owner, developer, "DEVELOPER", 1100)
    db.add_organization_member(org, owner, viewer, "VIEWER", 1100)

    # Suspend all test members first.
    db.suspend_organization_member(org, owner, admin, 1200)
    db.suspend_organization_member(org, owner, security, 1201)
    db.suspend_organization_member(org, owner, developer, 1202)
    db.suspend_organization_member(org, owner, viewer, 1203)

    # 1. Owner restores administrator.
    result = db.restore_organization_member(org, owner, admin, 1300)
    assert result["role"] == "ADMINISTRATOR"
    print("Owner restores administrator: PASS")

    # 2. Owner restores security officer.
    result = db.restore_organization_member(org, owner, security, 1301)
    assert result["role"] == "SECURITY_OFFICER"
    print("Owner restores security officer: PASS")

    # 3. Administrator restores developer.
    result = db.restore_organization_member(org, admin, developer, 1302)
    assert result["role"] == "DEVELOPER"
    print("Administrator restores developer: PASS")

    # 4. Administrator restores viewer.
    result = db.restore_organization_member(org, admin, viewer, 1303)
    assert result["role"] == "VIEWER"
    print("Administrator restores viewer: PASS")

    # 5. Administrator cannot restore security officer.
    db.suspend_organization_member(org, owner, security, 1400)
    try:
        db.restore_organization_member(org, admin, security, 1401)
        raise AssertionError("Administrator restored security officer")
    except ValueError:
        print("Administrator role restriction: PASS")

    # 6. Developer cannot restore members.
    db.suspend_organization_member(org, owner, viewer, 1402)
    try:
        db.restore_organization_member(org, developer, viewer, 1403)
        raise AssertionError("Developer restored viewer")
    except ValueError:
        print("Developer permission restriction: PASS")

    # 7. Self-restoration blocked.
    db.suspend_organization_member(org, owner, admin, 1404)
    try:
        db.restore_organization_member(org, admin, admin, 1405)
        raise AssertionError("Self-restoration allowed")
    except ValueError:
        print("Self-restoration protection: PASS")

    # 8. Owner restoration blocked.
    try:
        db.restore_organization_member(org, admin, owner, 1406)
        raise AssertionError("Owner restoration allowed")
    except ValueError:
        print("Owner protection: PASS")

    # 9. Repeated restoration blocked.
    try:
        db.restore_organization_member(org, owner, developer, 1407)
        raise AssertionError("Repeated restoration allowed")
    except ValueError:
        print("Repeated restoration protection: PASS")

    print("\nAll nine restoration tests passed.")

finally:
    if os.path.exists(db_path):
        os.remove(db_path)
