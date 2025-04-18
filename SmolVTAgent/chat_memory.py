import os
from rich_logger import RichLogger
import json
from typing import List, Dict, Any
from datetime import datetime, timezone

logger_memory = RichLogger.get_logger(__name__)

MEMORY_DIR = "chat_memories"
SESSION_NAMES_FILE = os.path.join(MEMORY_DIR, "session_names.json")

# Ensure the directory exists
os.makedirs(MEMORY_DIR, exist_ok=True)

def replay_memory(agent):
    """
    Replay the agent's memory using SmolAgents built-in replay() method.
    """
    if hasattr(agent, 'replay'):
        return agent.replay()
    return None

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

def save_agent_memory(session_id: str, agent) -> None:
    """
    Persist the agent's memory as a JSON file using SmolAgents' memory structure.
    """
    path = get_memory_path(session_id)
    memory_steps = agent.memory.get_full_steps() if hasattr(agent, 'memory') else []
    with open(path, "w", encoding="utf-8") as f:
        json.dump(memory_steps, f, ensure_ascii=False, indent=2)

def load_agent_memory(session_id: str):
    """
    Load agent memory steps from file for a session. Returns a list of memory steps (dicts).
    """
    path = get_memory_path(session_id)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        memory_steps = json.load(f)
    return memory_steps


def list_sessions() -> list:
    """List all session IDs with stored memory."""
    return [f[:-5] for f in os.listdir(MEMORY_DIR) if f.endswith(".json")]
