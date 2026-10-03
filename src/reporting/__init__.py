"""
Report generation and formatting capabilities.

This package contains formatters for different output formats,
template-based report generation, PoC generation, and AI-powered narration.
"""

from .ai_narrator import AINarrator, AIProvider, NarratorConfig, generate_ai_summary
from .formatters import HTMLFormatter, JSONFormatter, TXTFormatter
from .poc_generator import PoCGenerator, generate_poc_for_vulnerability
from .sarif_formatter import SARIFFormatter, format_as_sarif
from .templates import ReportTemplateManager

__all__ = [
    # Formatters
    "JSONFormatter",
    "TXTFormatter",
    "HTMLFormatter",
    "SARIFFormatter",
    "format_as_sarif",
    # Templates
    "ReportTemplateManager",
    # PoC Generator
    "PoCGenerator",
    "generate_poc_for_vulnerability",
    # AI Narrator
    "AINarrator",
    "NarratorConfig",
    "AIProvider",
    "generate_ai_summary",
]
