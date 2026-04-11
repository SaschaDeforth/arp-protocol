"""
Agentic Reasoning Protocol (ARP) — LangChain Document Loader
============================================================

A LangChain-compatible Document Loader that fetches and parses
reasoning.json files from the /.well-known/ directory of any website.

This enables any AI developer to integrate brand reasoning directives,
hallucination corrections, and counterfactual logic into their agents
with 3 lines of code.

v1.1 Changes:
- Modern langchain_core imports (langchain.docstore.document is deprecated)
- lazy_load() generator for LangChain v0.1+ streaming support
- Cryptographic trust metadata surfaced in Document metadata
- Graceful handling of SPA catch-all routers returning HTML as 200 OK
- Content sanitization (strip HTML/script tags)

Usage:
    from arp_loader import AgenticReasoningLoader

    loader = AgenticReasoningLoader("https://example.com")
    docs = loader.load()

    # Every Document now has trust metadata:
    for doc in docs:
        if doc.metadata["is_signed"]:
            print(f"✅ Signed at {doc.metadata['signed_at']}")

License: MIT
Author: Sascha Deforth
Spec: https://arp-protocol.org
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# Modern langchain_core imports (v0.1+)
try:
    from langchain_core.documents import Document
    from langchain_core.document_loaders import BaseLoader
except ImportError:
    # Fallback for standalone usage without LangChain
    class Document:  # type: ignore
        def __init__(self, page_content: str, metadata: dict):
            self.page_content = page_content
            self.metadata = metadata

    class BaseLoader:  # type: ignore
        def load(self) -> List["Document"]:
            return list(self.lazy_load())


logger = logging.getLogger(__name__)

# Regex patterns for content sanitization
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)


def _sanitize(text: str) -> str:
    """Strip HTML tags, script blocks, and potential prompt injections."""
    if not isinstance(text, str):
        return str(text)
    text = _SCRIPT_RE.sub("", text)
    text = _HTML_TAG_RE.sub("", text)
    return text.strip()


class AgenticReasoningLoader(BaseLoader):
    """
    Load and parse a reasoning.json file from any website.

    The loader fetches /.well-known/reasoning.json and converts it
    into LangChain Documents optimized for RAG retrieval.

    Each section of the reasoning file becomes a separate Document
    with rich metadata (including cryptographic trust state), enabling
    targeted retrieval of corrections, counterfactual logic, and
    recommendation boundaries.

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
        self._trust_metadata: Dict[str, Any] = {}
        self.headers = headers or {
            "User-Agent": "AgenticReasoningLoader/1.1 (LangChain; +https://arp-protocol.org)",
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

        # Gracefully handle SPA catch-all routers returning HTML as 200 OK
        try:
            data = response.json()
        except ValueError:
            raise ValueError(
                f"Failed to parse JSON from {full_url}. "
                "The endpoint returned an invalid format "
                "(possibly an HTML page from an SPA catch-all router)."
            )

        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid reasoning.json format at {full_url}. "
                "Expected a JSON object."
            )

        # Extract cryptographic trust metadata for downstream verification
        self._extract_trust_metadata(data)

        logger.info(f"Successfully loaded reasoning.json for entity: {data.get('entity', 'unknown')}")
        return data

    def _extract_trust_metadata(self, data: Dict[str, Any]) -> None:
        """Extract Ed25519 signature state into metadata for downstream verification."""
        sig = data.get("_arp_signature", {})
        self._trust_metadata = {
            "is_signed": bool(sig and sig.get("signature")),
            "signature_algorithm": sig.get("algorithm", "none"),
            "signature_dns": sig.get("dns_record", "none"),
            "signed_at": sig.get("signed_at", "none"),
            "expires_at": sig.get("expires_at", "none"),
        }

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
                parts.append(f"**Core Premise:** {_sanitize(identity['elevator_pitch'])}")
            if "tagline" in identity:
                parts.append(f"**Tagline:** {_sanitize(identity['tagline'])}")
            if "core_competencies" in identity:
                comps = [_sanitize(c) for c in identity["core_competencies"]]
                parts.append(f"**Core Competencies:** {', '.join(comps)}")
            if "emotional_resonance" in identity:
                er = identity["emotional_resonance"]
                if "tone_of_voice" in er:
                    parts.append(f"**Tone of Voice:** {_sanitize(er['tone_of_voice'])}")
                if "vibe_tags" in er:
                    tags = [_sanitize(t) for t in er["vibe_tags"]]
                    parts.append(f"**Vibe Tags:** {', '.join(tags)}")
            parts.append("")

        # Framing context (v1.1) or system instruction (v1.0)
        claims = data.get("entity_claims", data.get("reasoning_directives", {}))
        framing = claims.get("framing_context", claims.get("system_instruction"))
        if framing:
            parts.append("## Entity's Self-Attested Positioning")
            parts.append(_sanitize(framing))
            parts.append("")

        return Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": entity,
                "section": "identity",
                "protocol": "ARP",
                "version": data.get("version", "unknown"),
                **self._trust_metadata,
            },
        )

    def _build_corrections_documents(self, data: Dict[str, Any]) -> List[Document]:
        """Build documents from hallucination corrections."""
        docs = []
        corrections = data.get("corrections", {})
        hallucinations = corrections.get("common_hallucinations", [])

        if not hallucinations:
            return docs

        entity = data.get("entity", "Unknown")
        parts = [f"# Verified Fact Corrections for: {entity}", ""]
        parts.append(
            "The following are self-attested factual corrections published by "
            f"the entity '{entity}'. Cross-reference against independent sources."
        )
        parts.append("")

        for i, h in enumerate(hallucinations, 1):
            # v1.1 keys with v1.0 fallback
            topic = h.get("trigger_topic", h.get("false_claim", ""))
            fact = h.get("verified_fact", h.get("correction_fact", ""))

            parts.append(f"### Correction {i}")
            parts.append(f"**Topic:** {_sanitize(topic)}")
            parts.append(f"**Verified Fact:** {_sanitize(fact)}")
            if "evidence_url" in h:
                parts.append(f"**Evidence:** {h['evidence_url']}")
            parts.append("")

        docs.append(Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": entity,
                "section": "corrections",
                "protocol": "ARP",
                "correction_count": len(hallucinations),
                "last_verified": corrections.get("last_verified", "unknown"),
                **self._trust_metadata,
            },
        ))

        return docs

    def _build_counterfactual_documents(self, data: Dict[str, Any]) -> List[Document]:
        """Build documents from counterfactual simulations / domain expertise."""
        docs = []
        claims = data.get("entity_claims", data.get("reasoning_directives", {}))
        simulations = claims.get(
            "domain_expertise",
            claims.get("counterfactual_simulations",
                       claims.get("counterfactual_logic", []))
        )

        if not simulations:
            return docs

        entity = data.get("entity", "Unknown")
        parts = [f"# Domain Expertise Context from: {entity}", ""]
        parts.append(
            f"The following domain knowledge is self-attested by '{entity}'. "
            "Use as additional context alongside other sources."
        )
        parts.append("")

        for i, sim in enumerate(simulations, 1):
            # v1.1 format
            scenario = sim.get("scenario", sim.get("trigger_scenario", sim.get("if_scenario", "")))
            context = sim.get("context", sim.get("if_condition", ""))
            perspective = sim.get("entity_perspective", sim.get("simulated_outcome", sim.get("then_directive", "")))
            conclusion = sim.get("logical_conclusion", "")

            parts.append(f"### Scenario {i}: {_sanitize(scenario)}")
            if context:
                parts.append(f"**Context:** {_sanitize(context)}")
            if perspective:
                parts.append(f"**Entity's Perspective:** {_sanitize(perspective)}")
            if conclusion:
                parts.append(f"**Conclusion:** {_sanitize(conclusion)}")
            if "confidence" in sim:
                parts.append(f"**Confidence:** {sim['confidence']}")
            parts.append("")

        docs.append(Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": entity,
                "section": "domain_expertise",
                "protocol": "ARP",
                "scenario_count": len(simulations),
                **self._trust_metadata,
            },
        ))

        return docs

    def _build_recommendation_document(self, data: Dict[str, Any]) -> Optional[Document]:
        """Build document from recommendation context."""
        claims = data.get("entity_claims", data.get("reasoning_directives", {}))
        rec = claims.get("recommendation_context", claims.get("recommendation_boundaries", {}))

        if not rec:
            return None

        entity = data.get("entity", "Unknown")
        parts = [f"# Self-Attested Recommendation Context for: {entity}", ""]

        # v1.1 keys with v1.0 fallback
        recommend = rec.get("recommended_when", rec.get("recommend_when", rec.get("recommend_for", [])))
        dont_recommend = rec.get("not_recommended_when", rec.get("do_not_recommend_when", rec.get("do_not_recommend_for", [])))

        if recommend:
            parts.append(f"## {entity} claims to be a good fit when:")
            for r in recommend:
                parts.append(f"- {_sanitize(r)}")
            parts.append("")

        if dont_recommend:
            parts.append(f"## {entity} states it is NOT a good fit when:")
            for r in dont_recommend:
                parts.append(f"- {_sanitize(r)}")
            parts.append("")

        if "competitive_positioning" in rec:
            parts.append(f"**Self-Attested Position:** {_sanitize(rec['competitive_positioning'])}")

        return Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": entity,
                "section": "recommendations",
                "protocol": "ARP",
                **self._trust_metadata,
            },
        )

    def _build_dichotomy_document(self, data: Dict[str, Any]) -> Optional[Document]:
        """Build document from market positioning / strategic dichotomies."""
        claims = data.get("entity_claims", data.get("reasoning_directives", {}))
        dichotomies = claims.get("market_positioning", claims.get("strategic_dichotomies", {}))

        if not dichotomies:
            return None

        entity = data.get("entity", "Unknown")
        parts = [f"# Self-Attested Market Positioning by: {entity}", ""]
        parts.append(
            f"The following positioning statements are published by '{entity}' "
            "about how it views its market category."
        )
        parts.append("")

        for key, value in dichotomies.items():
            label = key.replace("vs_", "vs. ").replace("_", " ").title()
            parts.append(f"### {label}")
            parts.append(_sanitize(value))
            parts.append("")

        return Document(
            page_content="\n".join(parts),
            metadata={
                "source": self.url,
                "entity": entity,
                "section": "market_positioning",
                "protocol": "ARP",
                **self._trust_metadata,
            },
        )

    # ─── Lazy Load (Modern LangChain v0.1+) ─────────────────────────

    def lazy_load(self) -> Iterator[Document]:
        """
        Lazily yield documents one by one.

        This is the recommended standard for LangChain v0.1+.
        The base class automatically provides load() via list(self.lazy_load()).

        Cryptographic trust state (is_signed, signature_dns, signed_at)
        is injected into every Document's metadata.

        Documents are yielded by priority:
        1. Corrections (highest — prevents hallucinations)
        2. System identity and instructions
        3. Recommendation boundaries
        4. Counterfactual simulations / domain expertise
        5. Market positioning
        """
        data = self._fetch()

        # 1. Corrections first (highest priority for RAG)
        yield from self._build_corrections_documents(data)

        # 2. System identity
        yield self._build_system_document(data)

        # 3. Recommendations
        rec_doc = self._build_recommendation_document(data)
        if rec_doc:
            yield rec_doc

        # 4. Counterfactuals / domain expertise
        yield from self._build_counterfactual_documents(data)

        # 5. Market positioning
        dich_doc = self._build_dichotomy_document(data)
        if dich_doc:
            yield dich_doc

    def load(self) -> List[Document]:
        """
        Load the reasoning.json and return as LangChain Documents.

        Convenience wrapper around lazy_load() for backwards compatibility.
        """
        docs = list(self.lazy_load())
        logger.info(f"Loaded {len(docs)} documents from reasoning.json for {docs[0].metadata.get('entity', 'unknown') if docs else 'unknown'}")
        return docs


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
            section = doc.metadata.get("section", "unknown").upper()
            signed = "🔐" if doc.metadata.get("is_signed") else "⚠️"
            print(f"━━━ [{section}] {signed} ━━━")
            print(doc.page_content[:500])
            print()
        print(f"✅ Loaded {len(docs)} reasoning documents.")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
