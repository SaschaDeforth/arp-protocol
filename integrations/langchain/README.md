# Agentic Reasoning Protocol — LangChain Integration

A LangChain-compatible Document Loader for `reasoning.json` files.

## Installation

```bash
pip install requests langchain
```

## Usage

```python
from arp_loader import AgenticReasoningLoader

# Load from any website
loader = AgenticReasoningLoader("https://example.com")
docs = loader.load()

# Each section becomes a separate Document
for doc in docs:
    print(f"[{doc.metadata['section']}] {doc.page_content[:100]}...")
```

## How It Works

The loader fetches `/.well-known/reasoning.json` and splits it into prioritized Documents:

1. **Corrections** (highest priority) — prevents hallucinations during RAG
2. **Identity** — brand facts and system instructions
3. **Recommendations** — when to recommend / when not to
4. **Counterfactuals** — pre-programmed reasoning logic
5. **Dichotomies** — competitive positioning pivots

Each Document includes rich metadata (`entity`, `section`, `protocol`, `version`) for targeted retrieval.

## Use in a RAG Pipeline

```python
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings

# Load reasoning documents
loader = AgenticReasoningLoader("https://example.com")
docs = loader.load()

# Add to vector store
vectorstore = Chroma.from_documents(docs, OpenAIEmbeddings())

# Now your AI agent knows how to reason about this brand
retriever = vectorstore.as_retriever()
```

## Standalone Usage (No LangChain)

```python
from arp_loader import load_reasoning

docs = load_reasoning("https://example.com")
for doc in docs:
    print(doc.page_content)
```

## CLI Usage

```bash
python arp_loader.py https://example.com
```

## License

MIT
