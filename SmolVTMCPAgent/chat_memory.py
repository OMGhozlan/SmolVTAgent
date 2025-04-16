import os
import json
from typing import List, Dict, Any

MEMORY_DIR = "chat_memories"
SESSION_NAMES_FILE = os.path.join(MEMORY_DIR, "session_names.json")

# Ensure the directory exists
os.makedirs(MEMORY_DIR, exist_ok=True)

def _load_session_names():
    if os.path.exists(SESSION_NAMES_FILE):
        with open(SESSION_NAMES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def _save_session_names(names):
    with open(SESSION_NAMES_FILE, "w", encoding="utf-8") as f:
        json.dump(names, f, ensure_ascii=False, indent=2)

def set_session_name(session_id: str, name: str):
    names = _load_session_names()
    names[session_id] = name
    _save_session_names(names)

def get_session_name(session_id: str) -> str:
    names = _load_session_names()
    return names.get(session_id, "")

def get_memory_path(session_id: str) -> str:
    """Return the file path for a session's memory."""
    return os.path.join(MEMORY_DIR, f"{session_id}.json")

def save_chat_history(session_id: str, messages: List[Dict[str, Any]], hash_cache: dict = None):
    """Persist chat history and hash cache for a session as a JSON file with top-level keys."""
    path = get_memory_path(session_id)
    data = {
        "messages": messages,
        "hash_cache": hash_cache if hash_cache is not None else {}
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_chat_history(session_id: str):
    """Load chat history and hash cache for a session if it exists. Returns a dict with keys 'messages' and 'hash_cache'."""
    path = get_memory_path(session_id)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Backward compatibility: if it's a list, treat as messages only
            if isinstance(data, list):
                return {"messages": data, "hash_cache": {}}
            return data
    return {"messages": [], "hash_cache": {}}


def list_sessions() -> list:
    """List all session IDs with stored memory."""
    return [f[:-5] for f in os.listdir(MEMORY_DIR) if f.endswith(".json")]
