import json
import os
from typing import Optional

import firebase_admin
from firebase_admin import auth, credentials, firestore

_firebase_app: Optional[firebase_admin.App] = None
_firestore_client: Optional[firestore.Client] = None


def init_firebase() -> firebase_admin.App:
    """
    Initializes Firebase Admin SDK once.
    Prefers FIREBASE_SERVICE_ACCOUNT_JSON in production and falls back to
    file-path based credentials for local development.
    """
    global _firebase_app, _firestore_client

    if _firebase_app is not None:
        return _firebase_app

    service_account_json = (os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON") or "").strip()
    if service_account_json:
        try:
            parsed = json.loads(service_account_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "FIREBASE_SERVICE_ACCOUNT_JSON is set but is not valid JSON."
            ) from exc
        if not isinstance(parsed, dict):
            raise RuntimeError(
                "FIREBASE_SERVICE_ACCOUNT_JSON must be a JSON object."
            )
        cred = credentials.Certificate(parsed)
    else:
        # Local dev fallback: explicit path first, then ADC path variable.
        cred_path = (
            os.environ.get("FIREBASE_SERVICE_ACCOUNT_PATH")
            or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            or ""
        ).strip()
        if not cred_path:
            raise RuntimeError(
                "Firebase Admin credentials are not set. Set FIREBASE_SERVICE_ACCOUNT_JSON "
                "or FIREBASE_SERVICE_ACCOUNT_PATH/GOOGLE_APPLICATION_CREDENTIALS."
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
