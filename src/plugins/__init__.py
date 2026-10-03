"""Plugin base interface."""

from .manager import PluginCapability, PluginInterface, PluginManager, PluginMetadata

__all__ = [
    "PluginInterface",
    "PluginManager",
    "PluginCapability",
    "PluginMetadata",
]
