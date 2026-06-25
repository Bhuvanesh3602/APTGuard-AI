"""
Live CERT-In advisory RAG retrieval over Qdrant.

Queries the ``certin_advisories`` Qdrant collection that is seeded by
``scripts/seed_certin_rag.py``. The India APT attribution agent and the
CERT-In compliance agent call this to *ground* their findings in real
CERT-In advisory text rather than relying only on the static in-code
catalog.

Retrieval strategy (priority order, each step degrades gracefully):

  1. **Vector search** — embed the query with the *same* model the seeder
     used (``all-MiniLM-L6-v2``, 384-dim) and run a Qdrant ANN search. This
     is true semantic retrieval.
  2. **Lexical fallback** — if ``sentence-transformers`` is not importable
     (e.g. the agents image was built without the heavy ML extra), scroll
     the collection and rank by lexical token overlap on the advisory
     ``text``/``tags`` payload. Still hits the *live* Qdrant collection.
  3. **Empty** — if Qdrant itself is unreachable or the collection has not
     been seeded, return ``[]`` so callers fall back to the static catalog.

The module never raises: a missing vector store must never break an
investigation. ``QDRANT_URL`` selects the server (default
``http://localhost:6333``).

IMPORTANT: ``CERTIN_EMBED_MODEL`` here MUST match the model used by the
seeder. If you change one, change the other, or vector search silently
returns garbage (mismatched embedding spaces) and the agent will fall back
to lexical ranking.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Keep in lock-step with scripts/seed_certin_rag.py
CERTIN_COLLECTION = "certin_advisories"
CERTIN_EMBED_MODEL = "all-MiniLM-L6-v2"

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]*")


def _tokenise(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(text.lower()) if len(t) > 2}


class CertInRAG:
    """Async retriever over the seeded CERT-In advisory collection."""

    def __init__(self, qdrant_url: str | None = None, collection: str = CERTIN_COLLECTION) -> None:
        self._url = qdrant_url or os.getenv("QDRANT_URL", "http://localhost:6333")
        self._collection = collection
        self._client: Any = None
        self._model: Any = None
        self._model_loaded = False  # distinguishes "not tried" from "tried and unavailable"

    # ─── public API ───────────────────────────────────────────────────────────

    async def available(self) -> bool:
        """True when Qdrant is reachable and the collection has been seeded."""
        client = await self._get_client()
        if client is None:
            return False
        try:
            cols = await client.get_collections()
            return self._collection in {c.name for c in cols.collections}
        except Exception:  # noqa: BLE001
            return False

    async def search(
        self,
        query: str,
        limit: int = 3,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return up to ``limit`` CERT-In advisory chunks relevant to ``query``.

        Each result: ``{doc_id, title, source, category, text, tags, score,
        retrieval}``. Returns ``[]`` (never raises) when nothing is available.
        """
        client = await self._get_client()
        if client is None:
            return []

        try:
            cols = await client.get_collections()
            if self._collection not in {c.name for c in cols.collections}:
                logger.debug("certin_rag.collection_missing", collection=self._collection)
                return []
        except Exception as exc:  # noqa: BLE001
            logger.debug("certin_rag.qdrant_unreachable", error=str(exc))
            return []

        # 1) vector search
        vector = await self._embed(query)
        if vector is not None:
            try:
                hits = await client.search(
                    collection_name=self._collection,
                    query_vector=vector,
                    limit=limit,
                    query_filter=self._category_filter(category),
                )
                results = [self._format(h.payload, float(h.score), "vector") for h in hits if h.payload]
                if results:
                    return results
            except Exception as exc:  # noqa: BLE001
                logger.debug("certin_rag.vector_search_failed", error=str(exc))

        # 2) lexical fallback over the live collection
        return await self._lexical_search(client, query, limit, category)

    # ─── retrieval internals ──────────────────────────────────────────────────

    def _category_filter(self, category: str | None) -> Any:
        if not category:
            return None
        try:
            from qdrant_client.models import FieldCondition, Filter, MatchValue

            return Filter(must=[FieldCondition(key="category", match=MatchValue(value=category))])
        except Exception:  # noqa: BLE001
            return None

    async def _lexical_search(
        self,
        client: Any,
        query: str,
        limit: int,
        category: str | None,
    ) -> list[dict[str, Any]]:
        """Scroll the collection and rank by token overlap (no embeddings)."""
        try:
            points, _ = await client.scroll(
                collection_name=self._collection,
                limit=512,
                with_payload=True,
                with_vectors=False,
                scroll_filter=self._category_filter(category),
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("certin_rag.scroll_failed", error=str(exc))
            return []

        q_tokens = _tokenise(query)
        if not q_tokens:
            return []

        scored: list[tuple[float, dict[str, Any]]] = []
        for p in points:
            payload = p.payload or {}
            haystack = f"{payload.get('title', '')} {payload.get('text', '')} {' '.join(payload.get('tags', []))}"
            doc_tokens = _tokenise(haystack)
            if not doc_tokens:
                continue
            overlap = len(q_tokens & doc_tokens)
            if overlap == 0:
                continue
            score = overlap / len(q_tokens)
            scored.append((score, self._format(payload, round(score, 3), "lexical")))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [r for _, r in scored[:limit]]

    @staticmethod
    def _format(payload: dict[str, Any], score: float, retrieval: str) -> dict[str, Any]:
        text = payload.get("text", "")
        return {
            "doc_id": payload.get("doc_id"),
            "title": payload.get("title"),
            "source": payload.get("source"),
            "category": payload.get("category"),
            "text": text,
            "snippet": (text[:280] + "…") if len(text) > 280 else text,
            "tags": payload.get("tags", []),
            "score": score,
            "retrieval": retrieval,
        }

    # ─── lazy resources ───────────────────────────────────────────────────────

    async def _get_client(self) -> Any:
        if self._client is None:
            try:
                from qdrant_client import AsyncQdrantClient

                self._client = AsyncQdrantClient(url=self._url)
            except Exception as exc:  # noqa: BLE001
                logger.debug("certin_rag.client_init_failed", error=str(exc))
                return None
        return self._client

    async def _embed(self, text: str) -> list[float] | None:
        """Embed ``text`` with the seeder's model. ``None`` if unavailable."""
        model = await asyncio.to_thread(self._load_model)
        if model is None:
            return None
        try:
            vec = await asyncio.to_thread(lambda: model.encode(text).tolist())
            return vec
        except Exception as exc:  # noqa: BLE001
            logger.debug("certin_rag.embed_failed", error=str(exc))
            return None

    def _load_model(self) -> Any:
        if self._model_loaded:
            return self._model
        self._model_loaded = True
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(CERTIN_EMBED_MODEL)
            logger.info("certin_rag.embed_model_loaded", model=CERTIN_EMBED_MODEL)
        except Exception as exc:  # noqa: BLE001
            # No torch / sentence-transformers in this image → lexical fallback.
            logger.info("certin_rag.embed_model_unavailable_lexical_fallback", error=str(exc))
            self._model = None
        return self._model


_singleton: CertInRAG | None = None


def get_certin_rag() -> CertInRAG:
    """Process-wide singleton so the embedding model loads at most once."""
    global _singleton
    if _singleton is None:
        _singleton = CertInRAG()
    return _singleton
