import os
from typing import Optional

import firebase_admin
from firebase_admin import auth, credentials, firestore

_firebase_app: Optional[firebase_admin.App] = None
_firestore_client: Optional[firestore.Client] = None


def init_firebase() -> firebase_admin.App:
    """
    Initializes Firebase Admin SDK once.
    Uses GOOGLE_APPLICATION_CREDENTIALS env var pointing to a service account json.
    """
    global _firebase_app, _firestore_client

    if _firebase_app is not None:
        return _firebase_app

    # Prefer explicit FIREBASE_SERVICE_ACCOUNT_PATH if provided, else fallback to GOOGLE_APPLICATION_CREDENTIALS
    cred_path = (
        os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH")
        or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        or ""
    ).strip()
    if not cred_path:
        raise RuntimeError(
            "Firebase service account path not set. Set FIREBASE_SERVICE_ACCOUNT_PATH or GOOGLE_APPLICATION_CREDENTIALS to your service account json path."
        )

    if not os.path.exists(cred_path):
        raise RuntimeError(f"Service account json not found at: {cred_path}")

    cred = credentials.Certificate(cred_path)
    _firebase_app = firebase_admin.initialize_app(cred)
    _firestore_client = firestore.client(_firebase_app)
    return _firebase_app


def get_firestore() -> firestore.Client:
    if _firestore_client is None:
        init_firebase()
    return _firestore_client  # type: ignore[return-value]


def verify_id_token(id_token: str) -> dict:
    init_firebase()
    # Allow small clock skew to tolerate minor host/container drift
    return auth.verify_id_token(id_token, clock_skew_seconds=10)


def create_session_cookie(id_token: str, expires_in_seconds: int) -> str:
    init_firebase()
    return auth.create_session_cookie(id_token, expires_in=expires_in_seconds)


def verify_session_cookie(session_cookie: str) -> dict:
    init_firebase()
    return auth.verify_session_cookie(session_cookie, check_revoked=True)


def revoke_user_refresh_tokens(uid: str) -> None:
    init_firebase()
    auth.revoke_refresh_tokens(uid)
