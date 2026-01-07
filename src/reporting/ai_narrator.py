"""
AI Report Narrator Module

Generates natural language security reports using AI.
Supports Google Gemini, OpenAI, and Anthropic APIs.

Provides:
- Executive summaries for C-level stakeholders
- Technical narratives for security teams
- Risk assessments with business impact
- Attack scenario descriptions
- Prioritized remediation plans
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AIProvider(Enum):
    """Supported AI providers"""

    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


@dataclass
class NarratorConfig:
    """AI Narrator configuration"""

    provider: AIProvider = AIProvider.GEMINI
    api_key: str | None = None
    model: str = "models/gemini-2.0-flash"  # Default Gemini model
    temperature: float = 0.7
    max_tokens: int = 4096
    language: str = "en"  # en, tr, de, fr, es

    def __post_init__(self):
        """Load API key from environment if not provided"""
        if not self.api_key:
            env_keys = {
                AIProvider.GEMINI: "GOOGLE_AI_API_KEY",
                AIProvider.OPENAI: "OPENAI_API_KEY",
                AIProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
            }
            env_key = env_keys.get(self.provider, "")
            self.api_key = os.getenv(env_key, "")


class AINarrator:
    """
    AI-powered security report narrator.

    Generates human-readable security reports and narratives
    using large language models.
    """

    # Report templates by language
    EXECUTIVE_PROMPTS = {
        "en": """You are a senior cybersecurity consultant writing an executive summary for C-level stakeholders.
Based on the following vulnerability scan results, write a clear, non-technical summary that:
1. Highlights the overall security posture
2. Identifies the most critical risks and their business impact
3. Provides actionable recommendations
4. Uses business-friendly language without technical jargon

Scan Results:
{scan_data}

Write a professional executive summary (2-3 paragraphs):""",
        "tr": """Siz C-seviye yöneticiler için yönetici özeti yazan kıdemli bir siber güvenlik danışmanısınız.
Aşağıdaki güvenlik açığı tarama sonuçlarına dayanarak, şunları içeren açık ve teknik olmayan bir özet yazın:
1. Genel güvenlik durumunu vurgulayın
2. En kritik riskleri ve iş etkilerini belirleyin
3. Uygulanabilir öneriler sunun
4. Teknik jargon olmadan iş dostu bir dil kullanın

Tarama Sonuçları:
{scan_data}

Profesyonel bir yönetici özeti yazın (2-3 paragraf):""",
    }

    TECHNICAL_PROMPTS = {
        "en": """You are a penetration tester writing a technical security report.
Analyze the following vulnerability scan results and provide:
1. Technical analysis of each vulnerability type found
2. Attack vectors and exploitation scenarios
3. Impact assessment (CIA triad)
4. Technical remediation steps with code examples where applicable
5. Testing verification steps

Scan Results:
{scan_data}

Write a detailed technical report:""",
        "tr": """Siz teknik güvenlik raporu yazan bir penetrasyon test uzmanısınız.
Aşağıdaki güvenlik açığı tarama sonuçlarını analiz edin ve şunları sağlayın:
1. Bulunan her güvenlik açığı türünün teknik analizi
2. Saldırı vektörleri ve sömürü senaryoları
3. Etki değerlendirmesi (CIA üçlüsü)
4. Uygun olduğunda kod örnekleriyle teknik düzeltme adımları
5. Test doğrulama adımları

Tarama Sonuçları:
{scan_data}

Detaylı bir teknik rapor yazın:""",
    }

    RISK_PROMPTS = {
        "en": """You are a risk analyst assessing cybersecurity threats.
Based on the vulnerability scan results, provide a risk narrative that includes:
1. Overall risk rating and justification
2. Threat actor perspective - how could these be exploited?
3. Potential business impact scenarios
4. Risk prioritization matrix
5. Recommended security investments

Scan Results:
{scan_data}

Write a comprehensive risk assessment narrative:""",
        "tr": """Siz siber güvenlik tehditlerini değerlendiren bir risk analistisisiniz.
Güvenlik açığı tarama sonuçlarına dayanarak şunları içeren bir risk anlatısı sağlayın:
1. Genel risk derecelendirmesi ve gerekçesi
2. Tehdit aktörü perspektifi - bunlar nasıl sömürülebilir?
3. Potansiyel iş etkisi senaryoları
4. Risk önceliklendirme matrisi
5. Önerilen güvenlik yatırımları

Tarama Sonuçları:
{scan_data}

Kapsamlı bir risk değerlendirme anlatısı yazın:""",
    }

    ATTACK_SCENARIO_PROMPT = """You are a red team operator describing an attack scenario.
For the following vulnerability, write a realistic attack scenario that:
1. Describes the attacker's reconnaissance
2. Details the exploitation steps
3. Shows potential post-exploitation activities
4. Estimates the attack timeline
5. Describes potential data/system impact

Vulnerability:
{vulnerability}

Write a detailed attack scenario narrative:"""

    REMEDIATION_PROMPT = """You are a security engineer creating a remediation plan.
For the following vulnerabilities, create a prioritized remediation plan that:
1. Groups vulnerabilities by type and affected component
2. Provides specific fix recommendations with code examples
3. Estimates effort and complexity for each fix
4. Suggests a timeline based on risk priority
5. Includes verification steps after remediation

Vulnerabilities:
{vulnerabilities}

Create a detailed remediation plan:"""

    def __init__(self, config: NarratorConfig | None = None):
        """
        Initialize AI Narrator.

        Args:
            config: NarratorConfig with API settings
        """
        self.config = config or NarratorConfig()
        self._client = None

    @property
    def is_configured(self) -> bool:
        """Check if AI narrator is properly configured with API key."""
        return bool(self.config.api_key and len(self.config.api_key) > 10)

    async def initialize(self):
        """Initialize the AI client"""
        if self.config.provider == AIProvider.GEMINI:
            await self._init_gemini()
        elif self.config.provider == AIProvider.OPENAI:
            await self._init_openai()
        elif self.config.provider == AIProvider.ANTHROPIC:
            await self._init_anthropic()

    async def _init_gemini(self):
        """Initialize Google Gemini client"""
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.config.api_key)
            self._client = genai.GenerativeModel(self.config.model)
            logger.info(f"Gemini initialized with model: {self.config.model}")

        except ImportError:
            logger.error("google-generativeai package not installed. Run: pip install google-generativeai")
            raise

    async def _init_openai(self):
        """Initialize OpenAI client"""
        try:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(api_key=self.config.api_key)
            logger.info("OpenAI client initialized")

        except ImportError:
            logger.error("openai package not installed. Run: pip install openai")
            raise

    async def _init_anthropic(self):
        """Initialize Anthropic client"""
        try:
            from anthropic import AsyncAnthropic

            self._client = AsyncAnthropic(api_key=self.config.api_key)
            logger.info("Anthropic client initialized")

        except ImportError:
            logger.error("anthropic package not installed. Run: pip install anthropic")
            raise

    async def generate_executive_summary(self, scan_data: dict[str, Any]) -> str:
        """
        Generate an executive summary for C-level stakeholders.

        Args:
            scan_data: Scan results from scanner

        Returns:
            Natural language executive summary
        """
        prompt_template = self.EXECUTIVE_PROMPTS.get(self.config.language, self.EXECUTIVE_PROMPTS["en"])

        # Prepare scan data summary
        summary = self._prepare_scan_summary(scan_data)
        prompt = prompt_template.format(scan_data=summary)

        return await self._generate_completion(prompt)

    async def generate_technical_report(self, scan_data: dict[str, Any]) -> str:
        """
        Generate a detailed technical report for security teams.

        Args:
            scan_data: Scan results from scanner

        Returns:
            Technical security report
        """
        prompt_template = self.TECHNICAL_PROMPTS.get(self.config.language, self.TECHNICAL_PROMPTS["en"])

        summary = self._prepare_scan_summary(scan_data, detailed=True)
        prompt = prompt_template.format(scan_data=summary)

        return await self._generate_completion(prompt)

    async def generate_risk_narrative(self, scan_data: dict[str, Any]) -> str:
        """
        Generate a risk assessment narrative.

        Args:
            scan_data: Scan results from scanner

        Returns:
            Risk assessment narrative
        """
        prompt_template = self.RISK_PROMPTS.get(self.config.language, self.RISK_PROMPTS["en"])

        summary = self._prepare_scan_summary(scan_data)
        prompt = prompt_template.format(scan_data=summary)

        return await self._generate_completion(prompt)

    async def generate_attack_scenario(self, vulnerability: dict[str, Any]) -> str:
        """
        Generate an attack scenario for a specific vulnerability.

        Args:
            vulnerability: Single vulnerability dict

        Returns:
            Attack scenario narrative
        """
        vuln_summary = json.dumps(vulnerability, indent=2, default=str)
        prompt = self.ATTACK_SCENARIO_PROMPT.format(vulnerability=vuln_summary)

        return await self._generate_completion(prompt)

    async def generate_remediation_plan(self, vulnerabilities: list[dict[str, Any]]) -> str:
        """
        Generate a prioritized remediation plan.

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            Remediation plan narrative
        """
        vuln_summary = json.dumps(vulnerabilities, indent=2, default=str)
        prompt = self.REMEDIATION_PROMPT.format(vulnerabilities=vuln_summary)

        return await self._generate_completion(prompt)

    async def generate_full_report(self, scan_data: dict[str, Any]) -> dict[str, str]:
        """
        Generate all report sections.

        Args:
            scan_data: Scan results from scanner

        Returns:
            Dict with all narrative sections
        """
        # Initialize if not done
        if not self._client:
            await self.initialize()

        # Generate all sections concurrently
        executive, technical, risk = await asyncio.gather(
            self.generate_executive_summary(scan_data),
            self.generate_technical_report(scan_data),
            self.generate_risk_narrative(scan_data),
            return_exceptions=True,
        )

        # Collect all vulnerabilities for remediation
        all_vulns = []
        for result in scan_data.get("results", []):
            all_vulns.extend(result.get("vulnerabilities", []))

        remediation = ""
        if all_vulns:
            try:
                remediation = await self.generate_remediation_plan(all_vulns[:10])  # Limit to top 10
            except Exception as e:
                logger.warning(f"Remediation plan generation failed: {e}")
                remediation = "Remediation plan generation failed."

        return {
            "executive_summary": executive if isinstance(executive, str) else str(executive),
            "technical_report": technical if isinstance(technical, str) else str(technical),
            "risk_narrative": risk if isinstance(risk, str) else str(risk),
            "remediation_plan": remediation,
            "generated_at": datetime.now().isoformat(),
            "ai_provider": self.config.provider.value,
            "model": self.config.model,
        }

    async def _generate_completion(self, prompt: str) -> str:
        """
        Generate AI completion based on provider.

        Args:
            prompt: The prompt to send to the AI

        Returns:
            AI-generated text
        """
        if not self._client:
            await self.initialize()

        try:
            if self.config.provider == AIProvider.GEMINI:
                return await self._gemini_completion(prompt)
            elif self.config.provider == AIProvider.OPENAI:
                return await self._openai_completion(prompt)
            elif self.config.provider == AIProvider.ANTHROPIC:
                return await self._anthropic_completion(prompt)
        except Exception as e:
            logger.error(f"AI completion failed: {e}")
            return f"[AI Generation Error: {str(e)}]"

    async def _gemini_completion(self, prompt: str) -> str:
        """Generate completion using Google Gemini"""
        # Gemini uses synchronous API, run in thread
        loop = asyncio.get_event_loop()

        def generate():
            response = self._client.generate_content(
                prompt,
                generation_config={
                    "temperature": self.config.temperature,
                    "max_output_tokens": self.config.max_tokens,
                },
            )
            return response.text

        return await loop.run_in_executor(None, generate)

    async def _openai_completion(self, prompt: str) -> str:
        """Generate completion using OpenAI"""
        response = await self._client.chat.completions.create(
            model=self.config.model or "gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity analyst."},
                {"role": "user", "content": prompt},
            ],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        return response.choices[0].message.content

    async def _anthropic_completion(self, prompt: str) -> str:
        """Generate completion using Anthropic Claude"""
        response = await self._client.messages.create(
            model=self.config.model or "claude-3-sonnet-20240229",
            max_tokens=self.config.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _prepare_scan_summary(self, scan_data: dict[str, Any], detailed: bool = False) -> str:
        """
        Prepare scan data summary for AI prompt.

        Args:
            scan_data: Full scan results
            detailed: Include full vulnerability details

        Returns:
            Formatted summary string
        """
        target = scan_data.get("url", "Unknown")
        timestamp = scan_data.get("timestamp", datetime.now().isoformat())
        results = scan_data.get("results", [])

        # Count vulnerabilities by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        all_vulns = []

        for result in results:
            vulns = result.get("vulnerabilities", [])
            for vuln in vulns:
                sev = vuln.get("severity", "info").lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                all_vulns.append(vuln)

        total = sum(severity_counts.values())

        summary_lines = [
            f"Target: {target}",
            f"Scan Date: {timestamp}",
            f"Total Vulnerabilities: {total}",
            "",
            "Severity Breakdown:",
            f"  - Critical: {severity_counts['critical']}",
            f"  - High: {severity_counts['high']}",
            f"  - Medium: {severity_counts['medium']}",
            f"  - Low: {severity_counts['low']}",
            f"  - Info: {severity_counts['info']}",
            "",
        ]

        if all_vulns:
            summary_lines.append("Vulnerabilities Found:")

            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_vulns = sorted(all_vulns, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))

            for vuln in sorted_vulns[:20]:  # Limit to top 20
                summary_lines.append(f"\n- {vuln.get('title', 'Unknown')}")
                summary_lines.append(f"  Severity: {vuln.get('severity', 'Unknown')}")
                summary_lines.append(f"  Type: {vuln.get('type', 'Unknown')}")

                if vuln.get("cvss_score"):
                    summary_lines.append(f"  CVSS: {vuln.get('cvss_score')}")
                if vuln.get("cwe_id"):
                    summary_lines.append(f"  CWE: {vuln.get('cwe_id')}")

                if detailed:
                    summary_lines.append(f"  Description: {vuln.get('description', '')[:200]}")
                    evidence = vuln.get("evidence", {})
                    if evidence.get("url"):
                        summary_lines.append(f"  Affected URL: {evidence['url']}")
                    if evidence.get("parameter"):
                        summary_lines.append(f"  Parameter: {evidence['parameter']}")

        return "\n".join(summary_lines)


# Convenience functions


async def generate_ai_summary(
    scan_data: dict[str, Any],
    provider: str = "gemini",
    api_key: str | None = None,
    model: str = "models/gemini-2.0-flash",
    language: str = "en",
) -> dict[str, str]:
    """
    Generate AI-powered report summary.

    Args:
        scan_data: Scan results
        provider: 'gemini', 'openai', or 'anthropic'
        api_key: API key (or set via environment variable)
        model: Model name
        language: Report language ('en', 'tr', etc.)

    Returns:
        Dict with all narrative sections
    """
    config = NarratorConfig(provider=AIProvider(provider.lower()), api_key=api_key, model=model, language=language)

    narrator = AINarrator(config)
    return await narrator.generate_full_report(scan_data)


def format_ai_report_markdown(ai_report: dict[str, str]) -> str:
    """
    Format AI report sections as markdown document.

    Args:
        ai_report: Dict from generate_ai_summary

    Returns:
        Formatted markdown string
    """
    md = f"""# AI-Generated Security Assessment Report

**Generated:** {ai_report.get('generated_at', 'Unknown')}
**AI Provider:** {ai_report.get('ai_provider', 'Unknown')}
**Model:** {ai_report.get('model', 'Unknown')}

---

## Executive Summary

{ai_report.get('executive_summary', 'Not available')}

---

## Risk Assessment

{ai_report.get('risk_narrative', 'Not available')}

---

## Technical Analysis

{ai_report.get('technical_report', 'Not available')}

---

## Remediation Plan

{ai_report.get('remediation_plan', 'Not available')}

---

*This report was generated using AI and should be reviewed by a qualified security professional.*
"""
    return md
