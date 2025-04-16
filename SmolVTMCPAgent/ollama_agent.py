import logging
import asyncio
import re
import json
import time
from fastmcp import Client
from fastmcp.client.transports import SSETransport  # Use SSETransport for HTTP/SSE communication
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from datetime import datetime, timezone

from config import OLLAMA_MODEL_ID, OLLAMA_API_BASE # Assuming these are still in config.py

import re

def extract_hashes(text):
    """Extract all valid MD5, SHA1, or SHA256 hashes from the input text."""
    patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b',  # SHA256
    ]
    matches = []
    for pat in patterns:
        matches.extend(re.findall(pat, text))
    return list(set(matches))


# Constants 
# Deprecated, now using FastMCP Client
FASTMCP_TOOL_ENDPOINT = "http://localhost:8000/tools/check_hash_reputation/call"

class VirusTotalMCPClient:
    def __init__(self, url="http://localhost:8000/sse"):
        self.transport = SSETransport(url)

    async def check_hash(self, file_hash: str):
        try:
            async with Client(self.transport) as client:
                if not client.is_connected():
                    logger.error("Could not connect to FastMCP server.")
                    return "Error: Could not connect to FastMCP server."
                try:
                    # Optionally, list tools to check connection
                    tools = await client.list_tools()
                    if not any(tool.name == "check_hash_reputation" for tool in tools):
                        logger.error("'check_hash_reputation' tool not found on FastMCP server.")
                        return "Error: 'check_hash_reputation' tool not found on FastMCP server."
                    result = await client.call_tool("check_hash_reputation", {"hash_input": {"file_hash": file_hash}})
                    return result
                except Exception as e:
                    logger.error(f"Exception calling FastMCP tool: {e}", exc_info=True)
                    return f"Error: Exception calling FastMCP tool: {e}"
        except Exception as e:
            logger.error(f"Could not connect to FastMCP server: {e}", exc_info=True)
            return f"Error: Could not connect to FastMCP server: {e}"

def check_hash_sync(file_hash: str, url="http://localhost:8000/sse"):
    client = VirusTotalMCPClient(url)
    try:
        return asyncio.run(client.check_hash(file_hash))
    except Exception as e:
        logger.error(f"MCP client connection/call failed: {e}", exc_info=True)
        return f"Error: MCP client connection/call failed: {e}"

# Logging 
logger = logging.getLogger(__name__)

# Agent Class 
class VirusTotalOllamaAgent:
    def __init__(self, model_name=None):
        if model_name is None:
            model_name = OLLAMA_MODEL_ID
        try:
            self.llm = OllamaLLM(model=model_name, base_url=OLLAMA_API_BASE)
            logger.info(f"Ollama LLM initialized with model: {model_name} at {OLLAMA_API_BASE}")
        except Exception as e:
            logger.error(f"Failed to initialize Ollama LLM: {e}", exc_info=True)
            self.llm = None

        # Basic prompt template
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a helpful assistant. If the user provides a file hash (MD5, SHA1, SHA256), you MUST first check its reputation using the available tool before answering. If it's not a hash, answer normally."),
            ("user", "{input}")
        ])
        self.output_parser = StrOutputParser()
        
        if self.llm:
            self.chain = self.prompt | self.llm | self.output_parser
        else:
            self.chain = None

    def _call_fastmcp_tool(self, file_hash: str):
        """Calls the FastMCP server's hash check tool using FastMCP Client and always returns a dictionary if possible."""
        try:
            result = check_hash_sync(file_hash)
            # If result is a string, try to parse as JSON, else return as-is
            if isinstance(result, str):
                try:
                    parsed = json.loads(result)
                    return parsed
                except Exception:
                    pass
            return result
        except Exception as e:
            logger.exception(f"Unexpected error calling FastMCP tool: {e}")
            return {"error": f"An unexpected error occurred while calling the VirusTotal tool: {e}"}

    def _extract_family_names(self, vt_result):
        """
        Try to extract malware family names from VT result (string or dict).
        Returns a list of family names (may be empty).
        """
        import re
        family_names = set()
        # Try to parse JSON if string
        if isinstance(vt_result, str):
            try:
                vt_data = json.loads(vt_result)
            except Exception:
                vt_data = None
        else:
            vt_data = vt_result
        # Try to extract from known keys
        if vt_data and isinstance(vt_data, dict):
            # Look for 'names', 'malware_family', 'family', etc.
            candidates = []
            if 'attributes' in vt_data:
                attrs = vt_data['attributes']
                # VT format: detected by engines
                if 'popular_threat_classification' in attrs:
                    fams = attrs['popular_threat_classification'].get('suggested_threat_label', None)
                    if fams:
                        if isinstance(fams, str):
                            family_names.add(fams)
                        elif isinstance(fams, list):
                            family_names.update(fams)
                # Some engines may list names
                if 'popular_threat_names' in attrs:
                    fams = attrs['popular_threat_names']
                    if isinstance(fams, list):
                        family_names.update(fams)
            # Fallback: regex for known malware family patterns
            if not family_names and vt_result:
                fam_match = re.findall(r"family: ([A-Za-z0-9_\-.]+)", str(vt_result))
                family_names.update(fam_match)
        # If still empty, try regex on the whole string
        if not family_names and vt_result:
            fam_match = re.findall(r"family: ([A-Za-z0-9_\-.]+)", str(vt_result))
            family_names.update(fam_match)
        return list(family_names)

    async def _call_malpedia_tool(self, family_name: str) -> dict:
        """
        Call the FastMCP malpedia_family_writeup tool for a given family name.
        Returns a dict with 'summary' and 'url'.
        """
        from fastmcp import Client
        from fastmcp.client.transports import SSETransport
        tool_input = {"family_name": family_name}
        try:
            async with Client(SSETransport("http://localhost:8000/sse")) as client:
                if not client.is_connected():
                    logger.warning("Could not connect to FastMCP server for Malpedia tool.")
                    return {"summary": None, "url": None, "error": "MCP not connected"}
                result = await client.call_tool("malpedia_family_writeup", tool_input)
                return result
        except Exception as e:
            logger.warning(f"Failed to call Malpedia tool for {family_name}: {e}")
            return {"summary": None, "url": None, "error": str(e)}

    def run(self, messages: list, hash_cache=None, max_cache_size=100) -> str:
        """Process a list of messages (OpenAI/ChatML format) as context. If the latest user message contains hashes, process them with the tool before responding."""
        if not self.chain:
            return "Error: LLM is not initialized. Cannot process request."

        prompt = ""
        for m in messages:
            prompt += f"{m['role'].capitalize()}: {m['content']}\n"

        # Check for hashes in the latest user message only
        latest_user_msg = next((m['content'] for m in reversed(messages) if m['role'] == 'user'), None)
        hashes = extract_hashes(latest_user_msg) if latest_user_msg else []
        logger.info(f"[run] Latest user message: {latest_user_msg}")
        logger.info(f"[run] Hashes found: {hashes}")

        # Use a cache if provided, else use a temporary dict
        cache = hash_cache if hash_cache is not None else {}
        tool_results = {}
        if hashes:
            for h in hashes:
                h_key = h.strip().lower()
                if h_key in cache:
                    logger.info(f"[run] Hash {h_key} found in cache. Skipping tool call.")
                    tool_results[h] = cache[h_key]
                else:
                    logger.info(f"[run] Calling VT tool for hash: {h}")
                    vt_result = self._call_fastmcp_tool(h)
                    # Build a cache entry that contains the raw VT response and summary fields
                    cache_entry = {
                        'raw': vt_result,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                    tool_results[h] = cache_entry
                    cache[h_key] = cache_entry
            import json
            # Tag hashes in the user message after processing
            tagged_msg = latest_user_msg
            vt_raw_sections = []
            for h in hashes:
                tagged_msg = re.sub(rf'{re.escape(h)}', f'<checkedhash>{h}</checkedhash>', tagged_msg)
                vt_data = tool_results[h]
                vt_raw = vt_data.get('raw', vt_data) if isinstance(vt_data, dict) else vt_data
                vt_raw_json = json.dumps(vt_raw, ensure_ascii=False, indent=2, default=str)
                vt_raw_sections.append(f"Hash {h} VT Data:\n{vt_raw_json}")
            # Compose context for LLM
            vt_context = "\n\n".join(vt_raw_sections)
            # Replace the latest user message in the prompt with tagged version and VT context
            new_prompt = ""
            tagged = False
            for m in messages:
                if m['role'] == 'user' and m['content'] == latest_user_msg and not tagged:
                    new_prompt += f"User: {tagged_msg}\n"
                    if vt_context:
                        new_prompt += f"[Hash Reputation Raw Data]\n{vt_context}\n"
                    tagged = True
                else:
                    new_prompt += f"{m['role'].capitalize()}: {m['content']}\n"
            logger.info(f"[run] Prompt with tagged hashes and VT RAW context: {new_prompt}")
            return self.chain.invoke({"input": new_prompt})
        else:
            logger.info("Invoking LLM with chat history context (no hashes found).")
            return self.chain.invoke({"input": prompt})



# Helper function to get agent instance (similar to original setup) 
_agent_instance = None

def get_agent(model_name=None) -> VirusTotalOllamaAgent:
    global _agent_instance
    if _agent_instance is None or (model_name is not None and getattr(_agent_instance.llm, 'model', None) != model_name):
        logger.info(f"Creating new VirusTotalOllamaAgent instance for model: {model_name}")
        _agent_instance = VirusTotalOllamaAgent(model_name)
    return _agent_instance
