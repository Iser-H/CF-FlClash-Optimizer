# -*- coding: utf-8 -*-
"""YAML manager wrapper for FlClash profiles.

Alias and facade for ProfileManager to provide explicit YAML management operations.
"""

from profile_manager import ProfileManager

# Alias for external references
YamlManager = ProfileManager

__all__ = ["YamlManager", "ProfileManager"]
