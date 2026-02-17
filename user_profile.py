from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Optional

from firebase_admin import firestore, auth
from firebase_admin_init import get_firestore

STOCKHOLM_TZ = ZoneInfo("Europe/Stockholm")


def _today_str_stockholm() -> str:
    return datetime.now(STOCKHOLM_TZ).date().isoformat()


def _yesterday_str_stockholm() -> str:
    return (datetime.now(STOCKHOLM_TZ).date() - timedelta(days=1)).isoformat()


def _users_col():
    db = get_firestore()
    return db.collection("users")


def ensure_user_doc(uid: str, email: Optional[str] = None) -> Dict[str, Any]:
    doc_ref = _users_col().document(uid)
    snap = doc_ref.get()

    if snap.exists:
        return snap.to_dict() or {}

    now = firestore.SERVER_TIMESTAMP
    data = {
        "display_name": (email.split("@")[0] if email and "@" in email else "New user"),
        "avatar_key": "avatar_01",
        "streak": 0,
        "best_streak": 0,
        "last_login_date": None,
        "created_at": now,
        "updated_at": now,
    }
    doc_ref.set(data)
    return data


def update_streak_if_needed(uid: str) -> Dict[str, Any]:
    doc_ref = _users_col().document(uid)
    snap = doc_ref.get()
    data = snap.to_dict() if snap.exists else {}
    if data is None:
        data = {}

    today = _today_str_stockholm()
    yesterday = _yesterday_str_stockholm()
    last = data.get("last_login_date")

    streak = int(data.get("streak") or 0)
    best = int(data.get("best_streak") or 0)

    changed = False

    if last == today:
        pass
    elif last == yesterday:
        streak += 1
        changed = True
    else:
        streak = 1
        changed = True

    if streak > best:
        best = streak
        changed = True

    if changed:
        doc_ref.set(
            {
                "streak": streak,
                "best_streak": best,
                "last_login_date": today,
                "updated_at": firestore.SERVER_TIMESTAMP,
            },
            merge=True,
        )

    data["streak"] = streak
    data["best_streak"] = best
    data["last_login_date"] = today
    return data


def get_leaderboard(limit: int = 10) -> List[Dict[str, Any]]:
    qs = (
        _users_col()
        .order_by("best_streak", direction=firestore.Query.DESCENDING)
        .limit(limit)
    )
    out: List[Dict[str, Any]] = []
    for snap in qs.stream():
        d = snap.to_dict() or {}
        # Determine admin from Firebase Auth custom claims
        is_admin = False
        try:
            u = auth.get_user(snap.id)
            claims = getattr(u, "custom_claims", None) or {}
            is_admin = bool(claims.get("admin", False))
        except Exception:
            is_admin = False
        out.append({
            "uid": snap.id,
            "display_name": d.get("display_name") or "Unknown",
            "avatar_key": d.get("avatar_key") or "avatar_01",
            "best_streak": int(d.get("best_streak") or 0),
            "is_admin": is_admin,
        })
    return out


def update_avatar(uid: str, avatar_key: str) -> None:
    doc_ref = _users_col().document(uid)
    doc_ref.set(
        {
            "avatar_key": avatar_key,
            "updated_at": firestore.SERVER_TIMESTAMP,
        },
        merge=True,
    )


def update_display_name(uid: str, display_name: str) -> None:
    doc_ref = _users_col().document(uid)
    doc_ref.set(
        {
            "display_name": display_name,
            "updated_at": firestore.SERVER_TIMESTAMP,
        },
        merge=True,
    )


def get_user_rank(uid: str) -> Dict[str, Any]:
    """Compute user's rank by best_streak desc, tie-break by uid asc."""
    # Fetch minimal fields for ranking
    docs = list(_users_col().stream())
    rows: List[Dict[str, Any]] = []
    for s in docs:
        d = s.to_dict() or {}
        rows.append(
            {
                "uid": s.id,
                "best_streak": int(d.get("best_streak") or 0),
                "display_name": d.get("display_name") or "Unknown",
                "avatar_key": d.get("avatar_key") or "avatar_01",
            }
        )

    rows.sort(key=lambda r: (-r["best_streak"], r["uid"]))

    rank = None
    for idx, r in enumerate(rows, start=1):
        if r["uid"] == uid:
            rank = idx
            me = r
            break

    if rank is None:
        # If user missing entirely, ensure doc and recompute a default entry
        me_doc = ensure_user_doc(uid)
        me = {
            "uid": uid,
            "best_streak": int(me_doc.get("best_streak") or 0),
            "display_name": me_doc.get("display_name") or "Unknown",
            "avatar_key": me_doc.get("avatar_key") or "avatar_01",
        }
        rows.append(me)
        rows.sort(key=lambda r: (-r["best_streak"], r["uid"]))
        rank = next((i for i, r in enumerate(rows, start=1) if r["uid"] == uid), len(rows))

    # Check admin claim for this uid
    is_admin = False
    try:
        u = auth.get_user(uid)
        claims = getattr(u, "custom_claims", None) or {}
        is_admin = bool(claims.get("admin", False))
    except Exception:
        is_admin = False

    return {
        "rank": int(rank),
        "best_streak": me["best_streak"],
        "display_name": me["display_name"],
        "avatar_key": me["avatar_key"],
        "uid": uid,
        "is_admin": is_admin,
    }
