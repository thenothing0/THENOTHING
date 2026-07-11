"""SessionSidebar — collapsible, keyboard-navigable session/knowledge tree.

Sections: Recent sessions · Pinned · Bookmarks · Knowledge graphs · Saved
reports. Hidden by default (toggled with Ctrl+B). It holds no data of its own:
the App fetches lists (off the UI thread) and calls :meth:`populate`; activating
a leaf posts :class:`NavSelected` for the App to act on. ``Tree`` provides native
↑/↓/Enter keyboard navigation.
"""

from __future__ import annotations

from textual.message import Message
from textual.widget import Widget
from textual.widgets import Tree
from textual.widgets.tree import TreeNode

_SECTIONS = [
    ("recent", "Recent sessions"),
    ("pinned", "Pinned"),
    ("bookmarks", "Bookmarks"),
    ("graphs", "Knowledge graphs"),
    ("reports", "Saved reports"),
]


class NavSelected(Message):
    """A sidebar leaf was activated."""

    def __init__(self, section: str, value: str, label: str = ""):
        super().__init__()
        self.section = section
        self.value = value
        self.label = label


class SessionSidebar(Widget):
    """Left navigation tree; data supplied by the App via :meth:`populate`."""

    def compose(self):
        tree: Tree = Tree("HYDRA", id="nav-tree")
        tree.show_root = False
        tree.guide_depth = 2
        yield tree

    def populate(self, data: dict[str, list[dict]]) -> None:
        """Rebuild the tree. ``data`` maps section id → [{label, value}]."""
        try:
            tree = self.query_one("#nav-tree", Tree)
        except Exception:
            return
        tree.clear()
        for section_id, title in _SECTIONS:
            items = data.get(section_id, [])
            node: TreeNode = tree.root.add(f"{title} ({len(items)})", expand=bool(items))
            for item in items:
                leaf = node.add_leaf(item.get("label", item.get("value", "?")))
                leaf.data = {"section": section_id, "value": item.get("value", "")}
        tree.root.expand()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = getattr(event.node, "data", None)
        if data and data.get("value"):
            self.post_message(NavSelected(
                data["section"], data["value"], str(event.node.label)))
