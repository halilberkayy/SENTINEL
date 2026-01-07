"""
JWT Security scanner module - Advanced Implementation.
"""

import base64
import hashlib
import hmac
import json
import logging
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .base_scanner import BaseScanner, Vulnerability

logger = logging.getLogger(__name__)


class JWTScanner(BaseScanner):
    """Advanced JWT vulnerability detection engine."""

    def __init__(self, config, http_client):
        super().__init__(config, http_client)
        self.name = "JWTScanner"
        self.description = "Advanced JWT security analyzer with brute force and algorithm confusion detection"
        self.version = "2.0.0"
        self.capabilities = [
            "None Algorithm Detection",
            "Weak Secret Brute Force",
            "Algorithm Confusion (RS256→HS256)",
            "Expired Token Detection",
            "KID Injection Testing",
            "Signature Verification",
        ]

        # Common weak secrets for brute force
        self.weak_secrets = [
            "secret",
            "password",
            "123456",
            "admin",
            "key",
            "jwt_secret",
            "mysecret",
            "supersecret",
            "changeme",
            "test",
            "development",
            "qwerty",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "secret123",
            "password123",
            "jwt",
            "token",
            "auth",
            "api_key",
            "your-256-bit-secret",
            "your-secret-key",
            "HS256-secret",
            "",
            "null",
            "undefined",
            "none",
            "default",
            "private_key",
        ]

    async def scan(self, url: str, progress_callback: Callable | None = None) -> dict[str, Any]:
        """Perform comprehensive JWT security scan."""
        logger.info(f"Scanning {url} for JWT vulnerabilities")
        vulnerabilities = []

        try:
            self._update_progress(progress_callback, 10, "Extracting JWTs from response")
            resp = await self.http_client.get(url)

            if not resp:
                return self._format_result("Error", "Target unreachable", [])

            # Extract JWTs from various sources
            jwt_candidates = await self._extract_jwts(resp, url)

            if not jwt_candidates:
                return self._format_result("Clean", "No JWT tokens found", [])

            total_jwts = len(jwt_candidates)
            for idx, token in enumerate(jwt_candidates):
                progress = 20 + int((idx / total_jwts) * 70)
                self._update_progress(progress_callback, progress, f"Analyzing JWT {idx+1}/{total_jwts}")

                # Run all JWT tests
                vulns = await self._comprehensive_jwt_analysis(token)
                vulnerabilities.extend(vulns)

            self._update_progress(progress_callback, 100, "completed")

            status = "Vulnerable" if vulnerabilities else "Clean"
            details = f"Analyzed {total_jwts} JWT(s). Found {len(vulnerabilities)} security issues."
            return self._format_result(status, details, vulnerabilities)

        except Exception as e:
            logger.exception(f"JWT scan failed: {e}")
            return self._format_result("Error", f"Internal error: {e}", [])

    async def _extract_jwts(self, response, url: str) -> list[str]:
        """Extract JWT patterns from response headers, cookies, and body."""
        tokens = set()

        # JWT regex pattern
        jwt_pattern = r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*"

        # 1. Check Authorization header in response (rare but possible)
        if hasattr(response, "headers"):
            auth_header = response.headers.get("Authorization", "")
            if "Bearer " in auth_header:
                token = auth_header.replace("Bearer ", "").strip()
                if self._is_valid_jwt_format(token):
                    tokens.add(token)

        # 2. Check Set-Cookie headers
        for cookie_header in response.headers.getall("Set-Cookie", []):
            matches = re.findall(jwt_pattern, cookie_header)
            tokens.update(matches)

        # 3. Check response body
        try:
            body = await response.text()
            matches = re.findall(jwt_pattern, body)
            tokens.update(matches)
        except (UnicodeDecodeError, Exception) as e:
            logger.debug(f"Error extracting JWT from response body: {e}")

        # 4. Check localStorage/sessionStorage patterns in JavaScript
        try:
            body = await response.text()
            storage_patterns = [
                r'localStorage\.setItem\([\'"].*?[\'"]\s*,\s*[\'"](' + jwt_pattern[:-1] + r')[\'"]',
                r'sessionStorage\.setItem\([\'"].*?[\'"]\s*,\s*[\'"](' + jwt_pattern[:-1] + r')[\'"]',
            ]
            for pattern in storage_patterns:
                matches = re.findall(pattern, body)
                tokens.update(matches)
        except (UnicodeDecodeError, Exception) as e:
            logger.debug(f"Error extracting JWT from localStorage/sessionStorage patterns: {e}")

        return list(tokens)

    def _is_valid_jwt_format(self, token: str) -> bool:
        """Validate JWT structure."""
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            # Try to decode header
            header = base64.urlsafe_b64decode(parts[0] + "===")
            json.loads(header)
            return True
        except (ValueError, json.JSONDecodeError):
            return False

    async def _comprehensive_jwt_analysis(self, token: str) -> list[Vulnerability]:
        """Run all JWT security checks."""
        findings = []

        try:
            parts = token.split(".")
            header_b64, payload_b64, signature = parts[0], parts[1], parts[2] if len(parts) > 2 else ""

            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "===").decode())
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "===").decode())

            alg = header.get("alg", "").upper()

            # 1. None Algorithm Attack
            if alg == "NONE" or alg == "":
                findings.append(
                    self._create_vulnerability(
                        title="JWT 'none' Algorithm Vulnerability",
                        description="The JWT uses 'none' algorithm allowing signature bypass. Attackers can forge tokens without knowing the secret.",
                        severity="critical",
                        type="jwt_none_alg",
                        evidence={"header": header, "token_preview": token[:50] + "..."},
                        cwe_id="CWE-327",
                        remediation="Disable 'none' algorithm in JWT library. Use strong algorithms like RS256 or ES256.",
                    )
                )

            # 2. Unsigned/Empty Signature
            if not signature or signature == "":
                findings.append(
                    self._create_vulnerability(
                        title="Unsigned JWT Token",
                        description="JWT has no signature part, allowing token forgery without any cryptographic verification.",
                        severity="critical",
                        type="jwt_unsigned",
                        evidence={"token_preview": token[:50] + "..."},
                        cwe_id="CWE-347",
                        remediation="Ensure all JWTs are cryptographically signed and verify signatures on every request.",
                    )
                )

            # 3. Weak Secret Brute Force (HS256/HS384/HS512)
            if alg.startswith("HS"):
                weak_secret = self._brute_force_hs_secret(token, alg)
                if weak_secret is not None:
                    findings.append(
                        self._create_vulnerability(
                            title="JWT Weak Secret Detected",
                            description=f"The JWT secret is weak and was cracked: '{weak_secret}'. Attackers can forge arbitrary tokens.",
                            severity="critical",
                            type="jwt_weak_secret",
                            evidence={"cracked_secret": weak_secret, "algorithm": alg},
                            cwe_id="CWE-521",
                            remediation="Use a long, random secret (minimum 256 bits). Consider using asymmetric algorithms like RS256.",
                        )
                    )

            # 4. Algorithm Confusion (RS256 → HS256)
            if alg in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]:
                findings.append(
                    self._create_vulnerability(
                        title="Potential Algorithm Confusion Vulnerability",
                        description=f"JWT uses {alg}. Test for algorithm confusion by changing to HS256 and using public key as secret.",
                        severity="medium",
                        type="jwt_alg_confusion",
                        evidence={"current_alg": alg, "attack": "Change header to HS256, sign with public key"},
                        cwe_id="CWE-327",
                        remediation="Explicitly verify the expected algorithm server-side. Never accept HS* when expecting RS*.",
                    )
                )

            # 5. Expired Token Check
            exp = payload.get("exp")
            if exp:
                try:
                    exp_datetime = datetime.fromtimestamp(exp, tz=timezone.utc)
                    if exp_datetime < datetime.now(timezone.utc):
                        findings.append(
                            self._create_vulnerability(
                                title="Expired JWT Token Accepted",
                                description=f"Token expired on {exp_datetime.isoformat()}. Server may not be validating expiration.",
                                severity="medium",
                                type="jwt_expired",
                                evidence={"exp": exp, "expired_at": exp_datetime.isoformat()},
                                cwe_id="CWE-613",
                                remediation="Always validate 'exp' claim server-side and reject expired tokens.",
                            )
                        )
                except (ValueError, OSError) as e:
                    logger.debug(f"Error parsing JWT expiration claim: {e}")
            else:
                findings.append(
                    self._create_vulnerability(
                        title="JWT Missing Expiration",
                        description="Token has no 'exp' claim. Tokens without expiration can be used indefinitely.",
                        severity="low",
                        type="jwt_no_exp",
                        evidence={"payload_claims": list(payload.keys())},
                        cwe_id="CWE-613",
                        remediation="Always include 'exp' claim with reasonable expiration time.",
                    )
                )

            # 6. KID Header Injection
            kid = header.get("kid")
            if kid:
                if any(c in kid for c in ["/", "\\", "..", ";", "|", "$", "`"]):
                    findings.append(
                        self._create_vulnerability(
                            title="Suspicious KID Header Value",
                            description=f"KID value contains special characters: '{kid}'. May be vulnerable to path traversal or injection.",
                            severity="high",
                            type="jwt_kid_injection",
                            evidence={"kid": kid},
                            cwe_id="CWE-22",
                            remediation="Sanitize KID values. Use database lookups instead of file paths.",
                        )
                    )

            # 7. Sensitive Data in Payload
            sensitive_keys = ["password", "passwd", "secret", "api_key", "private", "ssn", "credit_card"]
            found_sensitive = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
            if found_sensitive:
                findings.append(
                    self._create_vulnerability(
                        title="Sensitive Data in JWT Payload",
                        description=f"JWT payload contains potentially sensitive claims: {found_sensitive}. JWTs are base64-encoded, not encrypted.",
                        severity="medium",
                        type="jwt_sensitive_data",
                        evidence={"sensitive_claims": found_sensitive},
                        cwe_id="CWE-312",
                        remediation="Never store sensitive data in JWT payloads. Use encrypted tokens (JWE) if needed.",
                    )
                )

        except Exception as e:
            logger.debug(f"JWT analysis error: {e}")

        return findings

    def _brute_force_hs_secret(self, token: str, alg: str) -> str | None:
        """Attempt to crack HMAC-based JWT signature."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}".encode()
        signature = parts[2]

        # Determine hash algorithm
        hash_alg = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)

        for secret in self.weak_secrets:
            try:
                expected_sig = (
                    base64.urlsafe_b64encode(hmac.new(secret.encode(), message, hash_alg).digest()).decode().rstrip("=")
                )

                if expected_sig == signature.rstrip("="):
                    return secret
            except (ValueError, UnicodeDecodeError):
                continue

        return None
