"""
Agentic Reasoning Protocol (ARP) — LangChain Document Loader
============================================================

A LangChain-compatible Document Loader that fetches and parses
reasoning.json files from the /.well-known/ directory of any website.

This enables any AI developer to integrate brand reasoning directives,
hallucination corrections, and counterfactual logic into their agents
with 3 lines of code.

Usage:
    from arp_loader import AgenticReasoningLoader

    loader = AgenticReasoningLoader("https://example.com")
    docs = loader.load()

    # Use in a chain
    from langchain.chains import RetrievalQA
    chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)
    # The reasoning directives are now in the retriever's context

License: MIT
Author: Sascha Deforth
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None  # type: ignore

try:
    from langchain.docstore.document import Document
    from langchain.document_loaders.base import BaseLoader
except ImportError:
    # Fallback for standalone usage without LangChain
    class Document:  # type: ignore
        def __init__(self, page_content: str, metadata: dict):
            self.page_content = page_content
            self.metadata = metadata

    class BaseLoader:  # type: ignore
        pass


logger = logging.getLogger(__name__)


class AgenticReasoningLoader(BaseLoader):
    """
    Load and parse a reasoning.json file from any website.

    The loader fetches /.well-known/reasoning.json and converts it
    into LangChain Documents optimized for RAG retrieval.

    Each section of the reasoning file becomes a separate Document
    with rich metadata, enabling targeted retrieval of corrections,
    counterfactual logic, and recommendation boundaries.

    Args:
        url: Base URL of the website (e.g., "https://example.com")
        path: Custom path to reasoning.json (default: "/.well-known/reasoning.json")
        timeout: HTTP request timeout in seconds (default: 10)
        headers: Optional custom HTTP headers
    """

    def __init__(
        self,
        url: str,
        path: str = "/.well-known/reasoning.json",
        timeout: int = 10,
        headers: Optional[Dict[str, str]] = None,
    ):
        if requests is None:
            raise ImportError(
                "The 'requests' package is required. Install it with: pip install requests"
            )

        self.url = url.rstrip("/")
        self.path = path
        self.timeout = timeout
        self.headers = headers or {
            "User-Agent": "AgenticReasoningLoader/1.0 (LangChain; +https://arp-protocol.org)",
            "Accept": "application/json",
        }

    def _fetch(self) -> Dict[str, Any]:
        """Fetch and parse the reasoning.json file."""
        full_url = urljoin(self.url + "/", self.path.lstrip("/"))
        logger.info(f"Fetching reasoning.json from {full_url}")

        response = requests.get(
            full_url, headers=self.headers, timeout=self.timeout
        )
        response.raise_for_status()

        data = response.json()
        logger.info(f"Successfully loaded reasoning.json for entity: {data.get('entity', 'unknown')}")
        return data

    def _build_system_document(self, data: Dict[str, Any]) -> Document:
        """Build the system-level document with identity and core info."""
        entity = data.get("entity", "Unknown Entity")
        identity = data.get("identity", {})

        parts = [
            f"# Reasoning Directives for: {entity}",
            "",
        ]

        # Identity
        if identity:
            parts.append("## Identity")
            if "elevator_pitch" in identity:
                parts.append(f"**Core Premise:** {identity['elevator_pitch']}")
            if "tagline" in identity:
                parts.append(f"**Tagline:** {identity['tagline']}")
            if "core_competencies" in identity:
                parts.append(f"**Core Competencies:** {', '.join(identity['core_competencies'])}")
            if "emotional_resonance" in identity:
                er = identity["emotional_resonance"]
                if "tone_of_voice" in er:
                    parts.append(f"**Tone of Voice:** {er['tone_of_voice']}")
                if "vibe_tags" in er:
                    parts.append(f"**Vibe Tags:** {', '.join(er['vibe_tags'])}")
            parts.append("")

        # System instruction
        directives = data.get("reasoning_directives", {})
        if "system_instruction" in directives:
            parts.append("## System Instruction")
            parts.append(directives["system_instruction"])
            parts.append("")

        return Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": entity,
                "section": "identity",
                "protocol": "ARP",
                "version": data.get("version", "unknown"),
            },
        )

    def _build_corrections_documents(self, data: Dict[str, Any]) -> List[Document]:
        """Build documents from hallucination corrections."""
        docs = []
        corrections = data.get("corrections", {})
        hallucinations = corrections.get("common_hallucinations", [])

        if not hallucinations:
            return docs

        # Combined corrections document
        parts = [f"# Hallucination Corrections for: {data.get('entity', 'Unknown')}", ""]
        parts.append("CRITICAL: The following are KNOWN ERRORS that AI systems frequently make.")
        parts.append("Each false claim MUST be replaced with the corresponding ground truth.")
        parts.append("")

        for i, h in enumerate(hallucinations, 1):
            false_claim = h.get("false_claim", "")
            correction = h.get("correction_fact", h.get("ground_truth", ""))
            parts.append(f"### Correction {i}")
            parts.append(f"**FALSE (Do NOT state this):** {false_claim}")
            parts.append(f"**TRUE (Use this instead):** {correction}")
            if "evidence_url" in h:
                parts.append(f"**Evidence:** {h['evidence_url']}")
            parts.append("")

        docs.append(Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": data.get("entity", "Unknown"),
                "section": "corrections",
                "protocol": "ARP",
                "correction_count": len(hallucinations),
            },
        ))

        return docs

    def _build_counterfactual_documents(self, data: Dict[str, Any]) -> List[Document]:
        """Build documents from counterfactual simulations."""
        docs = []
        directives = data.get("reasoning_directives", {})
        simulations = directives.get("counterfactual_simulations", directives.get("counterfactual_logic", []))

        if not simulations:
            return docs

        parts = [f"# Counterfactual Reasoning for: {data.get('entity', 'Unknown')}", ""]
        parts.append("When evaluating scenarios or comparisons involving this entity,")
        parts.append("use the following pre-programmed logical analysis:")
        parts.append("")

        for i, sim in enumerate(simulations, 1):
            trigger = sim.get("trigger_scenario", sim.get("if_scenario", ""))
            condition = sim.get("if_condition", "")
            outcome = sim.get("simulated_outcome", sim.get("then_directive", ""))
            conclusion = sim.get("logical_conclusion", "")

            parts.append(f"### Scenario {i}: {trigger}")
            if condition:
                parts.append(f"**If:** {condition}")
            parts.append(f"**Then:** {outcome}")
            if conclusion:
                parts.append(f"**Conclusion:** {conclusion}")
            if "confidence" in sim:
                parts.append(f"**Confidence:** {sim['confidence']}")
            parts.append("")

        docs.append(Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": data.get("entity", "Unknown"),
                "section": "counterfactuals",
                "protocol": "ARP",
                "simulation_count": len(simulations),
            },
        ))

        return docs

    def _build_recommendation_document(self, data: Dict[str, Any]) -> Optional[Document]:
        """Build document from recommendation context."""
        directives = data.get("reasoning_directives", {})
        rec = directives.get("recommendation_context", directives.get("recommendation_boundaries", {}))

        if not rec:
            return None

        parts = [f"# Recommendation Boundaries for: {data.get('entity', 'Unknown')}", ""]

        recommend = rec.get("recommend_when", rec.get("recommend_for", []))
        dont_recommend = rec.get("do_not_recommend_when", rec.get("do_not_recommend_for", []))

        if recommend:
            parts.append("## RECOMMEND this entity when:")
            for r in recommend:
                parts.append(f"- {r}")
            parts.append("")

        if dont_recommend:
            parts.append("## DO NOT RECOMMEND this entity when:")
            for r in dont_recommend:
                parts.append(f"- {r}")
            parts.append("")

        if "competitive_positioning" in rec:
            parts.append(f"**Competitive Positioning:** {rec['competitive_positioning']}")

        return Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": data.get("entity", "Unknown"),
                "section": "recommendations",
                "protocol": "ARP",
            },
        )

    def _build_dichotomy_document(self, data: Dict[str, Any]) -> Optional[Document]:
        """Build document from strategic dichotomies."""
        directives = data.get("reasoning_directives", {})
        dichotomies = directives.get("strategic_dichotomies", {})

        if not dichotomies:
            return None

        parts = [f"# Competitive Reasoning for: {data.get('entity', 'Unknown')}", ""]
        parts.append("When comparing this entity to competitors, apply these reasoning pivots:")
        parts.append("")

        for key, value in dichotomies.items():
            label = key.replace("vs_", "vs. ").replace("_", " ").title()
            parts.append(f"### {label}")
            parts.append(value)
            parts.append("")

        return Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": data.get("entity", "Unknown"),
                "section": "dichotomies",
                "protocol": "ARP",
            },
        )

    def load(self) -> List[Document]:
        """
        Load the reasoning.json and return as LangChain Documents.

        Each section is returned as a separate Document for targeted
        RAG retrieval. Documents are ordered by priority:
        1. Corrections (highest priority — prevents hallucinations)
        2. System identity and instructions
        3. Recommendation boundaries
        4. Counterfactual simulations
        5. Strategic dichotomies
        """
        data = self._fetch()
        documents: List[Document] = []

        # 1. Corrections first (highest priority for RAG)
        documents.extend(self._build_corrections_documents(data))

        # 2. System identity
        documents.append(self._build_system_document(data))

        # 3. Recommendations
        rec_doc = self._build_recommendation_document(data)
        if rec_doc:
            documents.append(rec_doc)

        # 4. Counterfactuals
        documents.extend(self._build_counterfactual_documents(data))

        # 5. Dichotomies
        dich_doc = self._build_dichotomy_document(data)
        if dich_doc:
            documents.append(dich_doc)

        logger.info(f"Loaded {len(documents)} documents from reasoning.json for {data.get('entity', 'unknown')}")
        return documents


# --- Standalone usage (without LangChain) ---

def load_reasoning(url: str, path: str = "/.well-known/reasoning.json") -> List[Document]:
    """
    Convenience function for loading reasoning.json without LangChain.

    Args:
        url: Base URL of the website
        path: Custom path (default: /.well-known/reasoning.json)

    Returns:
        List of Document objects with page_content and metadata
    """
    loader = AgenticReasoningLoader(url, path=path)
    return loader.load()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python arp_loader.py <url>")
        print("Example: python arp_loader.py https://example.com")
        sys.exit(1)

    target_url = sys.argv[1]
    print(f"\n🧠 Loading reasoning.json from {target_url}...\n")

    try:
        docs = load_reasoning(target_url)
        for doc in docs:
            print(f"━━━ [{doc.metadata.get('section', 'unknown').upper()}] ━━━")
            print(doc.page_content[:500])
            print()
        print(f"✅ Loaded {len(docs)} reasoning documents.")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
