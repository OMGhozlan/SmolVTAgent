import streamlit as st
from smolagents import ToolCallingAgent, LiteLLMModel, Tool, tool
from rich_logger import RichLogger
from typing import Union, Dict, Any

# Import functions/config needed for the tool and agent
from config import OLLAMA_MODEL_ID, OLLAMA_API_BASE
from vt_helper import get_file_reputation_from_vt, is_valid_hash
import requests
import re

# Tool Definition 

logger_agent = RichLogger.get_logger(__name__)

class ExplainTextTool(Tool):
    name = "explain_text_tool"
    description = (
        "As a senior cybersecurity analyst, use this tool to explain or summarize provided text ONLY if it is complex, technical, cybersecurity-related, or the user explicitly requests an explanation. "
        "Do NOT use this tool for greetings, obvious language, or simple conversational input. "
        "Focus on malware, threat intelligence, digital forensics, incident response, and both offensive (red team) and defensive (blue team) topics."
    )
    inputs = {
        "text": {"type": "string", "description": "The text to be explained or summarized."}
    }
    output_type = "string"

    def forward(self, text: str) -> str:
        logger_agent.info(f"Tool 'explain_text_tool' called with text: {text[:50]}...")
        if not hasattr(self, 'model') or self.model is None:
            logger_agent.error("No model instance available in ExplainTextTool.")
            return "Error: No model instance available in ExplainTextTool."
        try:
            prompt = f"Explain or summarize the following text in simple terms:\n{text}"
            response = self.model(prompt)
            return response
        except Exception as e:
            logger_agent.error(f"Error in ExplainTextTool: {e}", exc_info=True)
            return f"Error: {e}"

explain_text_tool = ExplainTextTool()

# Attach the model instance to the explain_text_tool after creating the LiteLLMModel
# This is done in get_chat_agent so the tool always has access to the correct model


class MalpediaFamilyWriteupTool(Tool):
    name = "malpedia_family_writeup_tool"
    description = (
        "As a senior cybersecurity analyst, use this tool to retrieve detailed writeups and intelligence on malware families from Malpedia. "
        "Use ONLY if the user asks for malware family details, or if further threat intelligence is required for analysis. "
        "Do NOT use for general questions, greetings, or non-malware-related topics."
    )
    inputs = {
        "family_name": {"type": "string", "description": "The malware family name to search on Malpedia."}
    }
    output_type = "object"

    def forward(self, family_name: str) -> dict:
        base_url = "https://malpedia.caad.fkie.fraunhofer.de/details/"
        fam_url_name = family_name.lower().replace(' ', '_').replace('-', '_')
        url = base_url + fam_url_name
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                summary_match = re.search(r'<div class="card-body">\s*<p>(.*?)</p>', resp.text, re.DOTALL)
                if summary_match:
                    summary = summary_match.group(1).strip()
                else:
                    summary = None
                return {"summary": summary, "url": url}
            else:
                return {"summary": None, "url": url}
        except Exception as e:
            logger_agent.warning(f"Malpedia search failed for {family_name}: {e}")
            return {"summary": None, "url": url, "error": str(e)}

malpedia_family_writeup_tool = MalpediaFamilyWriteupTool()

class CheckFileHashReputationTool(Tool):
    name = "check_file_hash_reputation_tool"
    description = (
        "As a senior cybersecurity analyst, use this tool to check the reputation of a given file hash (MD5, SHA1, or SHA256) using the VirusTotal API. "
        "Only use if the user provides a file hash for investigation, or if malware analysis or threat hunting is requested. "
        "Do NOT use for general questions, greetings, or non-hash-related topics. "
        "If the file is found malicious, extract the detected family, search Malpedia for a writeup, and provide recommended next steps based on the writeup."
    )
    inputs = {
        "file_hash": {"type": "string", "description": "The file hash (MD5, SHA1, or SHA256) to check. It must be a valid hash string."}
    }
    output_type = "string"

    def forward(self, file_hash: str) -> str:
        logger_agent.info(f"Tool 'check_file_hash_reputation_tool' called with hash: {file_hash}")
        if not isinstance(file_hash, str) or not file_hash:
            logger_agent.warning("Invalid input type or empty string received by tool.")
            return "Error: Invalid input provided to the hash check tool."
        cleaned_hash = file_hash.strip()
        if not is_valid_hash(cleaned_hash):
            logger_agent.warning(f"Invalid hash provided: {file_hash}")
            return f"Input '{file_hash}' is not a valid MD5, SHA1, or SHA256 hash. Cannot check reputation."
        logger_agent.info(f"Calling VT helper for hash: {cleaned_hash}")
        result = get_file_reputation_from_vt(cleaned_hash)
        if isinstance(result, dict):
            logger_agent.info(f"VT helper returned a dictionary for {cleaned_hash}. Keys: {list(result.keys())}")
            from vt_helper import format_vt_result
            return format_vt_result(result)
        elif isinstance(result, str):
            logger_agent.info(f"VT helper returned an error string for {cleaned_hash}: {result}")
            return result
        else:
            logger_agent.warning(f"VT helper returned an unexpected type for {cleaned_hash}: {type(result)}")
            return str(result)

check_file_hash_reputation_tool = CheckFileHashReputationTool()

# Agent Initialization (Cached) 

@st.cache_resource 
def get_chat_agent():
    """Initializes and returns the SmolAgents ToolCallingAgent with all available tools.
    Tools:
        - check_file_hash_reputation_tool: Looks up file hash reputation via VirusTotal.
        - explain_text_tool: Uses the LLM to explain or summarize provided text.
    """
    logger_agent.info("Initializing SmolAgents ToolCallingAgent...")
    try:
        logger_agent.debug(f"Creating LiteLLMModel with ID: {OLLAMA_MODEL_ID} and Base: {OLLAMA_API_BASE}")
        system_prompt = (
            "You are a senior cybersecurity analyst, highly skilled in both offensive (red team) and defensive (blue team) techniques.\n"
            "If the user asks about your identity (e.g., 'Who are you?', 'What is your role?', 'Are you an AI?', 'Tell me about yourself'), respond: 'I am a senior cybersecurity analyst AI assistant, here to help with malware analysis, threat intelligence, digital forensics, and security operations.'\n"
            "Your responsibilities include: \n"
            "- Providing expert analysis on malware, threat intelligence, digital forensics, incident response, and security operations.\n"
            "- Using tools ONLY when the user asks for an explanation, or when the text is complex, technical, or cybersecurity-related.\n"
            "- NEVER use tools for greetings, obvious language, or simple conversational input.\n"
            "- For general conversation or greetings, respond naturally without invoking tools.\n"
            "- Clearly outline your actions and reasoning step-by-step when using tools.\n"
            "- If you are unsure whether to use a tool, ask a clarifying question first.\n"
        )
        ollama_model = LiteLLMModel(
            model_id=OLLAMA_MODEL_ID,
            api_base=OLLAMA_API_BASE,
            system_prompt=system_prompt
        )
        # Log the system prompt for debugging
        logger_agent.info(f"System prompt being sent to model:\n{system_prompt}")
        # Attach the model instance to the tool so it can use it in forward()
        explain_text_tool.model = ollama_model
        agent = ToolCallingAgent(
            tools=[check_file_hash_reputation_tool, malpedia_family_writeup_tool, explain_text_tool],
            model=ollama_model,
            max_steps=7
        )
        logger_agent.info("SmolAgents ToolCallingAgent initialized successfully.")
        return agent
    except Exception as e:
        logger_agent.error(f"Failed to initialize LLM agent: {e}", exc_info=True)
        try:
            st.error(f"Failed to initialize LLM agent: {e}", icon="🔥")
            st.error(f"Ensure Ollama is running at {OLLAMA_API_BASE} and model '{OLLAMA_MODEL_ID}' is pulled.", icon="🔌")
        except Exception:
            pass
        return None