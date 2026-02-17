import os
from typing import Optional

from pymongo import MongoClient

_client: Optional[MongoClient] = None


def get_client() -> MongoClient:
    global _client
    if _client is not None:
        return _client

    uri = (os.environ.get("MONGODB_URI") or "").strip()
    if not uri:
        raise RuntimeError("MONGODB_URI is not set")

    _client = MongoClient(uri, appname="CyberBase")
    return _client


def get_db():
    client = get_client()
    # Database name is fixed per requirements
    return client["CyberBase"]
