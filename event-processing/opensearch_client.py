"""
OpenSearch SIEM Client: Index management, document indexing, and fast analytical log search.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import structlog

log = structlog.get_logger(__name__)

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
EVENT_INDEX_PREFIX = "securewatch-events"


class OpenSearchSIEMClient:
    def __init__(self, url: str = OPENSEARCH_URL) -> None:
        self.url = url
        self.client = None
        self._init_client()

    def _init_client(self) -> None:
        try:
            from opensearchpy import OpenSearch
            self.client = OpenSearch(
                hosts=[self.url],
                http_compress=True,
                use_ssl=False,
                verify_certs=False,
                ssl_show_warn=False,
            )
            log.info("OpenSearch client initialized", url=self.url)
        except Exception as e:
            log.warning("OpenSearch client could not connect. Running in standalone PostgreSQL mode.", error=str(e))
            self.client = None

    def _get_target_index(self) -> str:
        """Monthly rolling index name, e.g. securewatch-events-2026.11"""
        now = datetime.now(timezone.utc)
        return f"{EVENT_INDEX_PREFIX}-{now.strftime('%Y.%m')}"

    def index_event(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Index a normalized event into OpenSearch."""
        if not self.client:
            return None
        try:
            index_name = self._get_target_index()
            res = self.client.index(
                index=index_name,
                body=event_data,
                id=event_data.get("event_id"),
                refresh=False,
            )
            return res.get("_id")
        except Exception as e:
            log.error("Failed to index event in OpenSearch", error=str(e))
            return None

    def search_events(
        self,
        query_string: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        size: int = 50,
    ) -> List[Dict[str, Any]]:
        """Execute analytical Lucene / OpenSearch query."""
        if not self.client:
            return []
        try:
            must_clauses = []
            if query_string:
                must_clauses.append({"query_string": {"query": query_string}})
            if filters:
                for k, v in filters.items():
                    must_clauses.append({"term": {k: v}})

            body = {
                "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
                "sort": [{"event_timestamp": {"order": "desc"}}],
                "size": size,
            }

            res = self.client.search(index=f"{EVENT_INDEX_PREFIX}-*", body=body)
            hits = res.get("hits", {}).get("hits", [])
            return [hit["_source"] for hit in hits]
        except Exception as e:
            log.error("OpenSearch query error", error=str(e))
            return []
