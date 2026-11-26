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
    security = make_user("security@example.com")
    developer = make_user("developer@example.com")
    viewer = make_user("viewer@example.com")

    org = db.create_organization(owner, "Suspension Test Org", 1000)

    db.add_organization_member(org, owner, admin, "ADMINISTRATOR", 1100)
    db.add_organization_member(org, owner, security, "SECURITY_OFFICER", 1100)
    db.add_organization_member(org, owner, developer, "DEVELOPER", 1100)
    db.add_organization_member(org, owner, viewer, "VIEWER", 1100)

    # 1. Owner suspends developer.
    result = db.suspend_organization_member(org, owner, developer, 1200)
    assert result["status"] == "SUSPENDED"
    print("Owner suspension permission: PASS")

    # 2. Administrator suspends viewer.
    result = db.suspend_organization_member(org, admin, viewer, 1300)
    assert result["status"] == "SUSPENDED"
    print("Administrator suspension permission: PASS")

    # 3. Administrator cannot suspend security officer.
    try:
        db.suspend_organization_member(org, admin, security, 1400)
        raise AssertionError("Administrator suspended security officer")
    except ValueError:
        print("Administrator role restriction: PASS")

    # 4. Developer cannot suspend another member.
    try:
        db.suspend_organization_member(org, developer, admin, 1500)
        raise AssertionError("Developer suspended administrator")
    except ValueError:
        print("Developer permission restriction: PASS")

    # 5. Self-suspension is blocked.
    try:
        db.suspend_organization_member(org, admin, admin, 1600)
        raise AssertionError("Self-suspension was allowed")
    except ValueError:
        print("Self-suspension protection: PASS")

    # 6. Owner cannot be suspended.
    try:
        db.suspend_organization_member(org, admin, owner, 1700)
        raise AssertionError("Owner suspension was allowed")
    except ValueError:
        print("Owner protection: PASS")

    # 7. Repeated suspension is blocked.
    try:
        db.suspend_organization_member(org, owner, developer, 1800)
        raise AssertionError("Repeated suspension was allowed")
    except ValueError:
        print("Repeated suspension protection: PASS")

    print("\nAll seven membership suspension tests passed.")

finally:
    if os.path.exists(db_path):
        os.remove(db_path)
