import logging
import requests
import asyncio
from fastmcp import Client
from fastmcp.client.transports import SSETransport  # Use SSETransport for HTTP/SSE communication
import json
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from config import OLLAMA_MODEL_ID, OLLAMA_API_BASE # Assuming these are still in config.py
from vt_helper import is_valid_hash, format_vt_result # Keep format_vt_result here for now

import re
from collections import OrderedDict

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

    def _call_fastmcp_tool(self, file_hash: str) -> str:
        """Calls the FastMCP server's hash check tool using FastMCP Client."""
        try:
            result = check_hash_sync(file_hash)
            return result
        except Exception as e:
            logger.exception(f"Unexpected error calling FastMCP tool: {e}")
            return f"Error: An unexpected error occurred while calling the VirusTotal tool."

    def _extract_family_names(self, vt_result):
        """
        Try to extract malware family names from VT result (string or dict).
        Returns a list of family names (may be empty).
        """
        import re
        import json
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
        import asyncio
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

    from collections import OrderedDict
    def run(self, user_input: str, hash_cache=None, max_cache_size=100) -> str:
        """Process user input, checking for any hashes and summarizing results if found. If malicious, search Malpedia for family writeups. Uses LRU cache for hash results."""
        if not self.chain:
            return "Error: LLM is not initialized. Cannot process request."

        if hash_cache is None:
            hash_cache = OrderedDict()
        elif not isinstance(hash_cache, OrderedDict):
            hash_cache = OrderedDict(hash_cache)

        cleaned_input = user_input.strip()
        hashes = extract_hashes(cleaned_input)

        malpedia_extras = []

        if hashes:
            tool_results = []
            for h in hashes:
                h_key = h.strip().lower()
                if h_key in hash_cache:
                    tool_result = hash_cache[h_key]
                    hash_cache.move_to_end(h_key)
                else:
                    tool_result = self._call_fastmcp_tool(h)
                    hash_cache[h_key] = tool_result
                    if len(hash_cache) > max_cache_size:
                        hash_cache.popitem(last=False)
                tool_results.append(f"Hash `{h}`: {tool_result}")
                # If malicious, try to extract family and search Malpedia (via MCP tool)
                if (isinstance(tool_result, str) and ("malicious" in tool_result.lower() or "💀" in tool_result)) or (isinstance(tool_result, dict) and tool_result.get('malicious', 0) > 0):
                    families = self._extract_family_names(tool_result)
                    logger.debug(f"Extracted families for hash {h}: {families}")
                    if families:
                        for fam in families:
                            logger.info(f"Calling Malpedia tool for family: {fam}")
                            import asyncio
                            malpedia_result = asyncio.run(self._call_malpedia_tool(fam))
                            summary = malpedia_result.get("summary")
                            url = malpedia_result.get("url")
                            if summary:
                                malpedia_extras.append(f"**Malpedia Writeup for {fam}:** {summary}\n[Read more on Malpedia]({url})")
                            elif url:
                                malpedia_extras.append(f"[Malpedia page for {fam}]({url}) (no summary found)")
                    else:
                        logger.info(f"No malware family extracted for hash {h}; skipping Malpedia lookup.")
            tool_results_str = "\n".join(tool_results)
            prompt_with_context = (
                f"You are a malware analysis assistant. The user provided these hashes: {', '.join(hashes)}.\n"
                f"You checked them using a tool, and the results were:\n{tool_results_str}\n"
                f"Please summarize or inform the user based on these results."
            )
            logger.info("Invoking LLM with hash check context for multiple hashes.")
            llm_response = self.chain.invoke({"input": prompt_with_context})
            # Append Malpedia info if found
            if malpedia_extras:
                llm_response += "\n\n" + "\n\n".join(malpedia_extras)
            return llm_response
        else:
            logger.info("No hashes detected. Invoking LLM directly.")
            return self.chain.invoke({"input": user_input})


# Helper function to get agent instance (similar to original setup) 
_agent_instance = None

def get_agent(model_name=None) -> VirusTotalOllamaAgent:
    global _agent_instance
    if _agent_instance is None or (model_name is not None and getattr(_agent_instance.llm, 'model', None) != model_name):
        logger.info(f"Creating new VirusTotalOllamaAgent instance for model: {model_name}")
        _agent_instance = VirusTotalOllamaAgent(model_name)
    return _agent_instance
