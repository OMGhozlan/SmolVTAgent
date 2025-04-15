from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
from config import OLLAMA_API_BASE

def create_vectorstore(chunks, emb_model_choice, persist_directory=None):
    """
    Create a Chroma vector store from document chunks using the specified embedding model.
    If persist_directory is provided, persist the DB to disk (automatic with langchain-chroma).
    """
    embeddings = OllamaEmbeddings(model=emb_model_choice, base_url=OLLAMA_API_BASE)
    if persist_directory:
        vs = Chroma.from_texts(chunks, embeddings=embeddings, persist_directory=persist_directory)
    else:
        vs = Chroma.from_texts(chunks, embeddings=embeddings)
    return vs

def load_vectorstore(emb_model_choice, persist_directory):
    """
    Load a persistent Chroma vector store from disk.
    """
    embeddings = OllamaEmbeddings(model=emb_model_choice, base_url=OLLAMA_API_BASE)
    # For langchain-chroma, use embedding_function for loading persistent DB
    return Chroma(persist_directory=persist_directory, embedding_function=embeddings)
