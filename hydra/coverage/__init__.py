"""
Coverage Tracking Engine (architecture spec Part 5).

Tracks which (asset × endpoint × method × parameter × auth-area × vuln-class)
tuples have been tested, with a status per tuple, and derives three scores:

  * Coverage score        = tested / total tuples
  * Attack-surface score  = normalized breadth (endpoints, params, auth areas, tech)
  * Risk score            = open-finding severity weight + uncovered high-value weight

Drives the `/next` engine: the highest-value untested tuples to test next.
SQLite-backed (stdlib), deterministic.
"""

from .store import CoverageStore, HIGH_VALUE_CLASSES

__all__ = ["CoverageStore", "HIGH_VALUE_CLASSES"]
