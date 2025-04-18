import re
from rich_logger import RichLogger
logger_think = RichLogger.get_logger(__name__)

def extract_think_blocks(text):
    """
    Extracts all <think>...</think> blocks from the input text.
    Returns a tuple (main_text, think_blocks), where:
      - main_text is the input text with <think>...</think> blocks removed
      - think_blocks is a list of strings (the content inside each <think>...</think> tag)
    """
    think_pattern = re.compile(r'<think>(.*?)</think>', re.DOTALL)
    think_blocks = think_pattern.findall(text)
    main_text = think_pattern.sub('', text)
    return main_text.strip(), think_blocks
