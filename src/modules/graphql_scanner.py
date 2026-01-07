"""
GraphQL Security scanner module.
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class GraphQLScanner(BaseScanner):
    """Engine for identifying GraphQL-specific vulnerabilities."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "GraphQLScanner"
        self.description = "Identifies GraphQL introspection, suggestions, and batching issues"
        self.version = "1.0.0"
        self.capabilities = ["Introspection check", "Field suggestion analysis", "Batching query testing"]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform GraphQL scan."""
        logger.info(f"Scanning {url} for GraphQL issues")
        vulnerabilities = []

        # Common GraphQL endpoints
        endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]

        try:
            self._update_progress(progress_callback, 10, "Discovering GraphQL endpoints")

            discovered_endpoints = []
            for ep in endpoints:
                target = self._build_url(url, ep)
                # Check with a simple valid query
                q = {"query": "{ __typename }"}
                res = await self.http_client.post(target, json=q)
                res_dict = await self._response_to_dict(res)
                if res_dict.get("status_code") == 200 and "__typename" in res_dict.get("page_content", ""):
                    discovered_endpoints.append(target)

            if not discovered_endpoints:
                return self._format_result("Clean", "No GraphQL endpoints discovered.", [])

            total_eps = len(discovered_endpoints)
            for idx, ep in enumerate(discovered_endpoints):
                self._update_progress(progress_callback, 30 + int((idx / total_eps) * 60), f"Analyzing {ep}")

                # 1. Introspection check
                introspection_query = {"query": "{ __schema { types { name } } }"}
                i_res = await self.http_client.post(ep, json=introspection_query)
                i_res_dict = await self._response_to_dict(i_res)
                if i_res_dict.get("status_code") == 200 and "types" in i_res_dict.get("page_content", ""):
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="GraphQL Introspection Enabled",
                            description=f"Introspection is enabled at {ep}, which leaks the entire schema.",
                            severity="medium",
                            type="config",
                            evidence={"endpoint": ep},
                            remediation="Disable introspection in production environments.",
                        )
                    )

                # 2. Field Suggestions
                invalid_query = {"query": "{ nonExistentField }"}
                s_res = await self.http_client.post(ep, json=invalid_query)
                s_res_dict = await self._response_to_dict(s_res)
                if "Did you mean" in s_res_dict.get("page_content", ""):
                    vulnerabilities.append(
                        self._create_vulnerability(
                            title="GraphQL Field Suggestions Enabled",
                            description=f"Field suggestions are enabled at {ep}. This can be used to brute-force the schema.",
                            severity="low",
                            type="config",
                            evidence={"endpoint": ep},
                            remediation="Disable field suggestions in production (e.g., using specialized middleware).",
                        )
                    )

                # 3. Batching attack surface
                batch_query = [introspection_query, introspection_query]
                b_res = await self.http_client.post(ep, json=batch_query)
                b_res_dict = await self._response_to_dict(b_res)
                try:
                    if b_res_dict.get("status_code") == 200 and isinstance(
                        json.loads(b_res_dict.get("page_content", "[]")), list
                    ):
                        vulnerabilities.append(
                            self._create_vulnerability(
                                title="GraphQL Query Batching Enabled",
                                description=f"Query batching is enabled at {ep}, which can facilitate brute-force or DoS attacks.",
                                severity="info",
                                type="config",
                                evidence={"endpoint": ep},
                                remediation="Implement limits on the number of batched queries allowed per request.",
                            )
                        )
                except json.JSONDecodeError:
                    logger.debug(f"Response not JSON for GraphQL endpoint {ep}")

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            return self._format_result(status, f"Identified {len(vulnerabilities)} GraphQL issues.", vulnerabilities)

        except Exception as e:
            logger.exception(f"GraphQL scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    def _build_url(self, base: str, path: str) -> str:
        from urllib.parse import urljoin, urlparse

        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(root, path)
