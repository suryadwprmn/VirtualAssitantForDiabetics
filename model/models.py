from langchain.chains import create_retrieval_chain
from langchain_core.prompts import ChatPromptTemplate
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import FAISS
from langchain_experimental.text_splitter import SemanticChunker
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_groq import ChatGroq


def initialize_llm(groq_api_key=None):
    llm = ChatGroq(temperature=0, model_name="llama3-8b-8192", groq_api_key=groq_api_key)
    return llm

def initialize_embeddings():
    model_name = "BAAI/bge-small-en"
    model_kwargs = {"device": "cpu"}
    encode_kwargs = {"normalize_embeddings": True}
    embeddings = HuggingFaceEmbeddings(
        model_name=model_name, model_kwargs=model_kwargs, encode_kwargs=encode_kwargs
    )
    return embeddings

def apply_semantic_chunking(documents):
    embeddings = HuggingFaceEmbeddings()
    text_splitter = SemanticChunker(embeddings)
    chunked_texts = text_splitter.split_documents(documents)
    return chunked_texts

def initialize_vectorstore(chunked_texts, embeddings):
    vectorstore = FAISS.from_documents(documents=chunked_texts, embedding=embeddings)
    retriever = vectorstore.as_retriever()
    return retriever

def create_rag_chain(retriever, llm):
    system_prompt = (
        "Anda adalah asisten untuk tugas menjawab pertanyaan yang bernama devi. "
        "Gunakan konteks yang diambil untuk menjawab "
        "Menjawab menggunakan bahasa indonesia "
        "Jika Anda tidak menemukan jawaban pada konteks, katakan saya tidak tahu, pertanyaan tersebut tidak ada didalam konteks "
        ". Gunakan maksimal dua kalimat dan pertahankan "
        "jawaban singkat.\n\n"
        "{context}"
    )
    prompt = ChatPromptTemplate.from_messages(messages=[
        ("system", system_prompt),
        ("human", "{input}"),
    ])
    question_answer_chain = create_stuff_documents_chain(llm, prompt)
    rag_chain = create_retrieval_chain(retriever, question_answer_chain)
    return rag_chain
