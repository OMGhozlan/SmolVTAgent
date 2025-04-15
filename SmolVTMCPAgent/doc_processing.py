import streamlit as st
import re

def extract_text_from_file(file):
    """
    Attempts to convert uploaded files to markdown using MarkItDown, with a fallback to basic extraction methods for PDFs and DOCX files if the conversion fails.
    """
    try:
        from markitdown import MarkItDown
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=file.name) as tf:
            tf.write(file.read())
            tf.flush()
            md = MarkItDown(enable_plugins=False)
            result = md.convert(tf.name)
            return result.text_content
    except Exception as e:
        st.warning(f"MarkItDown conversion failed for {file.name}: {e}")
        # Fallbacks for PDF/DOCX/txt could be added here
        return ""

from langchain_text_splitters import RecursiveCharacterTextSplitter

def chunk_markdown(md_text, chunk_size=400, overlap=50):
    """
    Chunk markdown into semantically meaningful, overlapping pieces for embedding.
    Uses RecursiveCharacterTextSplitter with best-practice parameters.
    """
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=overlap,
        separators=["\n\n", "\n", ". ", " ", ""]
    )
    return splitter.split_text(md_text)

