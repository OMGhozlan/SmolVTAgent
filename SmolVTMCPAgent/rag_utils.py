from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings
from config import OLLAMA_API_BASE

def create_vectorstore(chunks, emb_model_choice, persist_directory=None):
    """
    Create a Chroma vector store from document chunks using the specified embedding model.
    If persist_directory is provided, persist the DB to disk.
    """
    embeddings = OllamaEmbeddings(model=emb_model_choice, base_url=OLLAMA_API_BASE)
    vs = Chroma.from_texts(chunks, embeddings, persist_directory=persist_directory) if persist_directory else Chroma.from_texts(chunks, embeddings)
    if persist_directory:
        vs.persist()
    return vs

def load_vectorstore(emb_model_choice, persist_directory):
    """
    Load a persistent Chroma vector store from disk.
    """
    embeddings = OllamaEmbeddings(model=emb_model_choice, base_url=OLLAMA_API_BASE)
    return Chroma(embedding_function=embeddings, persist_directory=persist_directory)
