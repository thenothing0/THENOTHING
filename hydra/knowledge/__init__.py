"""
╔══════════════════════════════════════════════════════════════╗
║  hydra.knowledge — Offensive Knowledge OS core (Phase A)     ║
╚══════════════════════════════════════════════════════════════╝

Makes the canonical `wiki/` machine-operable and unifies it with the runtime
attack graph. The wiki (markdown + frontmatter, versioned in git) is the SINGLE
source of truth; the graph index is a derived, rebuildable acceleration layer.

Modules:
  schema      — typed page-type contract (NodeType/Stage/Confidence) + frontmatter serde
  wiki_store  — parse/read/write wiki pages, resolve [[links]], create-from-template
  confidence  — source-weighted confidence, Two-Signal rule, decay
  promotion   — knowledge-hierarchy promotion with hard guardrails
  graph_index — derived graph over wiki pages + links (queries)
  bridge      — wiki <-> graph; materialize assets/graph into wiki pages
  memory      — Offensive Memory search-first recall API
"""

from hydra.knowledge.schema import (  # noqa: F401
    NodeType,
    Stage,
    Confidence,
    STAGE_ORDER,
    FORBIDDEN_PROMOTIONS,
    parse_frontmatter,
    dump_frontmatter,
    split_page,
    extract_wikilinks,
)
