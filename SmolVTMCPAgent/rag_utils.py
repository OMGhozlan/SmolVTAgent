from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
from config import OLLAMA_API_BASE

def list_vectorstore_files(vectorstore):
    """
    List unique filenames or sources stored in the Chroma vectorstore's metadata.
    Returns a set of filenames or sources if present in metadata.
    """
    try:
        # Chroma API: get() returns dict with 'metadatas' key
        all_metadata = vectorstore.get()["metadatas"]
        files = set()
        for meta in all_metadata:
            # Try common keys for file/source
            for key in ("source", "file", "filename", "file_name"):
                if key in meta:
                    files.add(meta[key])
        return sorted(files)
    except Exception as e:
        return [f"Error retrieving files from vectorstore: {e}"]

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
