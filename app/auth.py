import hashlib
import hmac
import secrets


PBKDF2_ITERATIONS = 600_000


def hash_password(password):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    salt = secrets.token_bytes(32)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return password_hash.hex(), salt.hex()


def verify_password(password, password_hash, password_salt):
    if not all(
        isinstance(value, str) and value
        for value in (password, password_hash, password_salt)
    ):
        return False

    try:
        salt = bytes.fromhex(password_salt)
        expected_hash = bytes.fromhex(password_hash)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS
        )

        return hmac.compare_digest(actual_hash, expected_hash)

    except (ValueError, TypeError):
        return False


def generate_session_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    if not isinstance(token, str) or not token:
        raise ValueError("Token is required.")

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_approval_key():
    return secrets.token_urlsafe(32)


def verify_approval_key(provided_key, stored_hash):
    if not isinstance(provided_key, str) or not provided_key:
        return False

    if not isinstance(stored_hash, str) or not stored_hash:
        return False

    provided_hash = hash_token(provided_key)

    return hmac.compare_digest(provided_hash, stored_hash)
