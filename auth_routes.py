import os
import json
import re
from datetime import datetime, timezone
from functools import wraps
from user_profile import (
    ensure_user_doc,
    update_streak_if_needed,
    get_leaderboard,
    update_avatar,
    update_display_name,
    get_user_rank,
)

from flask import Blueprint, jsonify, redirect, render_template, request, g, current_app
from flask_babel import gettext as _

from firebase_admin_init import (
    create_session_cookie,
    verify_session_cookie,
    verify_id_token,
    revoke_user_refresh_tokens,
    get_firestore,
)

auth_bp = Blueprint("auth_bp", __name__)

SESSION_COOKIE_NAME = "cb_session"
SESSION_EXPIRES_DAYS = 14


def _is_safe_internal_next(next_path: str) -> bool:
    candidate = (next_path or "").strip()
    if not candidate:
        return False
    if not candidate.startswith("/"):
        return False
    if candidate.startswith("//"):
        return False
    if "\\" in candidate:
        return False
    if "://" in candidate:
        return False
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", candidate.lstrip("/")):
        return False
    return True


def _is_https_request() -> bool:
    """
    In local dev you are likely on http, in prod you should be on https.
    This controls Secure cookie flag.
    """
    if request.is_secure:
        return True
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    return forwarded_proto.lower() == "https"


def set_current_user_from_session_cookie() -> None:
    """
    Attach user data to flask.g if a valid Firebase session cookie exists.
    """
    g.user = None
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        return
    try:
        decoded = verify_session_cookie(cookie)
        g.user = {
            "uid": decoded.get("uid"),
            "email": decoded.get("email"),
            "name": decoded.get("name"),
            "admin": bool(decoded.get("admin", False)),
        }
    except Exception:
        g.user = None


def _get_bearer_token() -> str:
    authz = request.headers.get("Authorization", "").strip()
    if not authz:
        return ""
    if authz.lower().startswith("bearer "):
        return authz[7:].strip()
    return ""


def get_request_user() -> dict | None:
    """
    Resolve the current user either from a verified session cookie or an
    Authorization: Bearer <ID_TOKEN> header. Returns a dict with uid/email/name
    if valid, otherwise None.
    """
    # Prefer the already-attached user if available (session cookie path)
    if getattr(g, "user", None):
        return g.user

    # Fallback to Authorization Bearer header with an ID token
    token = _get_bearer_token()
    if not token:
        return None
    try:
        decoded = verify_id_token(token)
        return {
            "uid": decoded.get("uid"),
            "email": decoded.get("email"),
            "name": decoded.get("name"),
            "admin": bool(decoded.get("admin", False)),
        }
    except Exception:
        return None


def api_login_required(view_func):
    """
    Decorator for API endpoints. Verifies either session cookie (if present)
    or Authorization: Bearer <ID_TOKEN>. Returns 401 JSON on failure.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_request_user()
        if not user:
            return jsonify({"ok": False, "error": _("Unauthorized")}), 401
        # attach for downstream handlers
        g.user = user
        return view_func(*args, **kwargs)
    return wrapper


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not getattr(g, "user", None):
            return redirect("/login")
        return view_func(*args, **kwargs)
    return wrapper


@auth_bp.get("/login")
@auth_bp.get("/login/")
def login_page():
    # Optionally supply Firebase Web config via environment to avoid hardcoding
    # These should be set in Vercel Project Settings → Environment Variables
    cfg = {
        k: os.environ.get(v, "").strip()
        for k, v in {
            "apiKey": "FIREBASE_API_KEY",
            "authDomain": "FIREBASE_AUTH_DOMAIN",
            "projectId": "FIREBASE_PROJECT_ID",
            "storageBucket": "FIREBASE_STORAGE_BUCKET",
            "messagingSenderId": "FIREBASE_MESSAGING_SENDER_ID",
            "appId": "FIREBASE_APP_ID",
            "measurementId": "FIREBASE_MEASUREMENT_ID",
        }.items()
    }
    # Only pass non-empty values; client falls back to inline defaults when missing
    cfg = {k: v for k, v in cfg.items() if v}
    next_path = (request.args.get("next") or "").strip()
    safe_next = next_path if _is_safe_internal_next(next_path) else "/dashboard"
    return render_template(
        "auth/login.html",
        firebase_config_json=json.dumps(cfg),
        login_next=safe_next,
    )


@auth_bp.post("/sessionLogin")
def session_login():
    """
    Receives Firebase ID token from browser, returns an HttpOnly session cookie.
    Body: { "idToken": "..." }
    """
    data = request.get_json(silent=True) or {}
    id_token = (data.get("idToken") or "").strip()
    if not id_token:
        return jsonify({"ok": False, "error": _("Missing idToken")}), 400

    try:
        decoded = verify_id_token(id_token)
        uid = decoded.get("uid")
        if not uid:
            return jsonify({"ok": False, "error": _("Invalid token")}), 401
        if not decoded.get("email_verified", False):
            return jsonify({"ok": False, "error": _("Email not verified")}), 403
    except Exception as e:
        current_app.logger.exception("Token verification failed: %s", e)
        return jsonify({"ok": False, "error": _("Token verification failed")}), 401

    expires_in_seconds = SESSION_EXPIRES_DAYS * 24 * 60 * 60

    try:
        session_cookie = create_session_cookie(id_token, expires_in_seconds)
    except Exception:
        return jsonify({"ok": False, "error": _("Could not create session")}), 500

    resp = jsonify({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        session_cookie,
        max_age=expires_in_seconds,
        httponly=True,
        secure=_is_https_request(),
        samesite="Lax",
        path="/",
    )
    return resp


@auth_bp.post("/logout")
def logout():
    """
    Clears cookie and revokes refresh tokens so session cookies become invalid quickly.
    """
    cookie = request.cookies.get(SESSION_COOKIE_NAME)

    if cookie:
        try:
            decoded = verify_session_cookie(cookie)
            uid = decoded.get("uid")
            if uid:
                revoke_user_refresh_tokens(uid)
        except Exception:
            pass

    resp = jsonify({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        "",
        expires=0,
        httponly=True,
        secure=_is_https_request(),
        samesite="Lax",
        path="/",
    )
    return resp


@auth_bp.get("/api/me")
@api_login_required
def api_me():
    """
    Returns minimal profile for the authenticated user. Useful for testing
    header-based ID token verification from the client.
    """
    return jsonify({
        "ok": True,
        "user": {
            "uid": g.user.get("uid"),
            "email": g.user.get("email"),
            "name": g.user.get("name"),
        }
    })


@auth_bp.get("/dashboard")
@login_required
def dashboard():
    """
    Placeholder dashboard view for now.
    Next step we will add streak, display name, avatar choice, leaderboard.
    """
    user = g.user
    uid = user.get("uid")
    email = user.get("email")
    profile = ensure_user_doc(uid, email=email)
    profile = update_streak_if_needed(uid)
    leaderboard = get_leaderboard(limit=10)
    user_rank = get_user_rank(uid)
    return render_template(
        "auth/dashboard.html",
        user=user,
        profile=profile,
        leaderboard=leaderboard,
        user_rank=user_rank,
        now=datetime.now(timezone.utc),
    )


@auth_bp.post("/profile/avatar")
@login_required
def update_avatar_route():
    data = request.get_json(silent=True) or {}
    avatar_key = (data.get("avatar_key") or "").strip()
    allowed = {f"avatar_{i:02d}" for i in range(1, 9)}
    if avatar_key not in allowed:
        return jsonify({"ok": False, "error": _("Invalid avatar")}), 400
    try:
        update_avatar(g.user.get("uid"), avatar_key)
        return jsonify({"ok": True})
    except Exception:
        current_app.logger.exception("Avatar update failed")
        return jsonify({"ok": False, "error": _("Update failed")}), 400


@auth_bp.post("/profile/display-name")
@login_required
def update_display_name_route():
    import re
    from datetime import timedelta

    data = request.get_json(silent=True) or {}
    raw = (data.get("display_name") or "").strip()

    # Normalize: collapse multiple spaces
    norm = re.sub(r"\s+", " ", raw)

    # Length 4..16
    if not (4 <= len(norm) <= 16):
        return jsonify({"ok": False, "error": _("Display name must be 4-16 characters.")}), 400

    # Allowed chars check (letters, numbers, space, underscore, dot)
    if not re.fullmatch(r"[A-Za-z0-9 _\.]+", norm):
        return jsonify({"ok": False, "error": _("Only letters, numbers, space, underscore and dot are allowed.")}), 400

    # Blocklist and token rules
    blocked = {
        "admin","administrator","root","system","sysadmin","moderator","mod","owner","support","staff","security","cyberbase","null","undefined","test","guest","anonymous","superuser","god","api","dev","developer","sys"
    }
    low = norm.lower().strip()
    tokens = re.findall(r"[a-z0-9]+", low)
    if any(t in blocked for t in tokens):
        return jsonify({"ok": False, "error": _("That name is not allowed.")}), 400
    if low.startswith(("admin", "root", "sys", "system")):
        return jsonify({"ok": False, "error": _("That name is not allowed.")}), 400

    uid = g.user.get("uid")

    try:
        db = get_firestore()
        ref = db.collection("users").document(uid)
        snap = ref.get()
        cur = (snap.to_dict() or {}) if snap.exists else {}
        current_name = (cur.get("display_name") or "").strip()

        # If unchanged, succeed without updating changed_at
        if current_name == norm:
            return jsonify({"ok": True})

        # Cooldown: once per 7 days
        changed_at = cur.get("display_name_changed_at")
        if changed_at is not None:
            try:
                # Firestore returns datetime for timestamps
                now = datetime.now(timezone.utc)
                # Ensure tz-aware
                if getattr(changed_at, "tzinfo", None) is None:
                    # Treat naive as UTC
                    changed_at = changed_at.replace(tzinfo=timezone.utc)
                elapsed = now - changed_at
                if elapsed < timedelta(days=7):
                    remaining = 7 - max(0, int(elapsed.days))
                    return jsonify({"ok": False, "error": _("You can change your name again in %(days)s day(s).", days=remaining)}), 429
            except Exception:
                # If parsing fails, allow update and reset the marker
                pass

        # Perform update and stamp changed_at
        update_display_name(uid, norm)
        ref.set({"display_name_changed_at": firestore.SERVER_TIMESTAMP}, merge=True)
        return jsonify({"ok": True})
    except Exception:
        current_app.logger.exception("Display name update failed")
        return jsonify({"ok": False, "error": _("Update failed")}), 400
