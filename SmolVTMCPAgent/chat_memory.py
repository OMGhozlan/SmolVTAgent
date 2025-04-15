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

def save_chat_history(session_id: str, messages: List[Dict[str, Any]]):
    """Persist chat history for a session as a JSON file."""
    path = get_memory_path(session_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)

def load_chat_history(session_id: str) -> List[Dict[str, Any]]:
    """Load chat history for a session if it exists."""
    path = get_memory_path(session_id)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def list_sessions() -> list:
    """List all session IDs with stored memory."""
    return [f[:-5] for f in os.listdir(MEMORY_DIR) if f.endswith(".json")]
