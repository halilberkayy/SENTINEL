"""
Plugin system for extensible scanner modules.
"""

import importlib.util
import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PluginCapability:
    """Plugin capability definition."""

    name: str
    description: str
    supported_platforms: list[str]  # web, api, mobile, etc.


class PluginInterface(ABC):
    """
    Base interface for all scanner plugins.

    Plugins must implement this interface to be loaded by the plugin manager.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name (unique identifier)."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version (semver format)."""
        pass

    @property
    @abstractmethod
    def author(self) -> str:
        """Plugin author."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description."""
        pass

    @abstractmethod
    async def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the plugin with configuration.

        Args:
            config: Plugin-specific configuration
        """
        raise NotImplementedError("Plugin must implement initialize() method")

    @abstractmethod
    async def scan(self, target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Perform the security scan.

        Args:
            target: Target URL or endpoint
            options: Scan-specific options

        Returns:
            Scan results in standardized format
        """
        raise NotImplementedError("Plugin must implement scan() method")

    @abstractmethod
    def get_capabilities(self) -> list[PluginCapability]:
        """
        Get plugin capabilities.

        Returns:
            List of capabilities
        """
        raise NotImplementedError("Plugin must implement get_capabilities() method")

    async def cleanup(self) -> None:
        """Cleanup resources (optional override)."""
        pass

    def validate_config(self, config: dict[str, Any]) -> bool:
        """
        Validate plugin configuration (optional override).

        Args:
            config: Configuration to validate

        Returns:
            True if valid
        """
        return True


class PluginMetadata:
    """Plugin metadata."""

    def __init__(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        capabilities: list[PluginCapability],
        plugin_class: type,
    ):
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.capabilities = capabilities
        self.plugin_class = plugin_class
        self.instance: PluginInterface | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "capabilities": [
                {
                    "name": cap.name,
                    "description": cap.description,
                    "supported_platforms": cap.supported_platforms,
                }
                for cap in self.capabilities
            ],
            "loaded": self.instance is not None,
        }


class PluginManager:
    """
    Manages plugin lifecycle: discovery, loading, execution, and cleanup.

    Features:
    - Dynamic plugin discovery
    - Hot reload support
    - Sandboxed execution (future)
    - Dependency injection
    """

    def __init__(self, plugins_dir: Path | None = None):
        """
        Initialize plugin manager.

        Args:
            plugins_dir: Directory containing plugins (defaults to src/plugins)
        """
        if plugins_dir is None:
            plugins_dir = Path(__file__).parent.parent.parent / "plugins"

        self.plugins_dir = plugins_dir
        self.plugins: dict[str, PluginMetadata] = {}
        self.loaded_plugins: dict[str, PluginInterface] = {}

    async def discover_plugins(self) -> list[PluginMetadata]:
        """
        Discover all plugins in the plugins directory.

        Returns:
            List of discovered plugin metadata
        """
        if not self.plugins_dir.exists():
            logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            self.plugins_dir.mkdir(parents=True, exist_ok=True)
            return []

        discovered = []

        for plugin_file in self.plugins_dir.glob("*_plugin.py"):
            try:
                metadata = self._load_plugin_module(plugin_file)
                if metadata:
                    self.plugins[metadata.name] = metadata
                    discovered.append(metadata)
                    logger.info(f"Discovered plugin: {metadata.name} v{metadata.version}")
            except Exception as e:
                logger.error(f"Failed to discover plugin {plugin_file}: {e}")

        return discovered

    def _load_plugin_module(self, plugin_file: Path) -> PluginMetadata | None:
        """Load a plugin module and extract metadata."""
        spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find plugin class
        plugin_class = None
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, PluginInterface) and obj is not PluginInterface:
                plugin_class = obj
                break

        if plugin_class is None:
            logger.warning(f"No PluginInterface subclass found in {plugin_file}")
            return None

        # Create a temporary instance to extract metadata
        temp_instance = plugin_class()

        metadata = PluginMetadata(
            name=temp_instance.name,
            version=temp_instance.version,
            author=temp_instance.author,
            description=temp_instance.description,
            capabilities=temp_instance.get_capabilities(),
            plugin_class=plugin_class,
        )

        return metadata

    async def load_plugin(self, plugin_name: str, config: dict[str, Any] | None = None) -> bool:
        """
        Load and initialize a plugin.

        Args:
            plugin_name: Name of the plugin to load
            config: Plugin configuration

        Returns:
            True if successfully loaded
        """
        if plugin_name in self.loaded_plugins:
            logger.warning(f"Plugin '{plugin_name}' is already loaded")
            return True

        metadata = self.plugins.get(plugin_name)
        if metadata is None:
            logger.error(f"Plugin '{plugin_name}' not found")
            return False

        try:
            # Create plugin instance
            instance = metadata.plugin_class()

            # Validate config
            if config and not instance.validate_config(config):
                logger.error(f"Invalid configuration for plugin '{plugin_name}'")
                return False

            # Initialize plugin
            await instance.initialize(config or {})

            # Store instance
            metadata.instance = instance
            self.loaded_plugins[plugin_name] = instance

            logger.info(f"Loaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to load plugin '{plugin_name}': {e}")
            return False

    async def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin and cleanup resources.

        Args:
            plugin_name: Name of the plugin to unload

        Returns:
            True if successfully unloaded
        """
        if plugin_name not in self.loaded_plugins:
            logger.warning(f"Plugin '{plugin_name}' is not loaded")
            return False

        try:
            instance = self.loaded_plugins[plugin_name]
            await instance.cleanup()

            del self.loaded_plugins[plugin_name]

            metadata = self.plugins.get(plugin_name)
            if metadata:
                metadata.instance = None

            logger.info(f"Unloaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload plugin '{plugin_name}': {e}")
            return False

    async def reload_plugin(self, plugin_name: str, config: dict[str, Any] | None = None) -> bool:
        """
        Reload a plugin (unload and load again).

        Args:
            plugin_name: Name of the plugin to reload
            config: New plugin configuration

        Returns:
            True if successfully reloaded
        """
        await self.unload_plugin(plugin_name)
        return await self.load_plugin(plugin_name, config)

    def get_plugin(self, plugin_name: str) -> PluginInterface | None:
        """Get a loaded plugin instance."""
        return self.loaded_plugins.get(plugin_name)

    def list_plugins(self, loaded_only: bool = False) -> list[dict[str, Any]]:
        """
        List all plugins.

        Args:
            loaded_only: Only list loaded plugins

        Returns:
            List of plugin metadata dictionaries
        """
        if loaded_only:
            return [self.plugins[name].to_dict() for name in self.loaded_plugins.keys() if name in self.plugins]
        else:
            return [metadata.to_dict() for metadata in self.plugins.values()]

    async def execute_plugin(
        self, plugin_name: str, target: str, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Execute a plugin scan.

        Args:
            plugin_name: Name of the plugin to execute
            target: Target URL or endpoint
            options: Scan options

        Returns:
            Scan results
        """
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            raise ValueError(f"Plugin '{plugin_name}' is not loaded")

        try:
            results = await plugin.scan(target, options)
            return results
        except Exception as e:
            logger.error(f"Plugin '{plugin_name}' execution failed: {e}")
            raise

    async def cleanup_all(self) -> None:
        """Cleanup all loaded plugins."""
        for plugin_name in list(self.loaded_plugins.keys()):
            await self.unload_plugin(plugin_name)
