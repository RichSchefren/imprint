"""Fail-closed deterministic domain selection."""

from .selector import DomainRegistry, DomainRule, DomainSelection, registry_from_config

__all__ = ["DomainRegistry", "DomainRule", "DomainSelection", "registry_from_config"]
