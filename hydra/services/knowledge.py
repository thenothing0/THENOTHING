"""Knowledge service — wraps WikiStore and kb_recall."""

from hydra.services.base import BaseService


class KnowledgeService(BaseService):

    def search(self, query, limit=10):
        try:
            from hydra.wiki import WikiStore
            store = WikiStore()
            return store.search(query, limit=limit)
        except Exception:
            return []

    def recall(self, query, types="", target="", limit=10):
        try:
            from hydra.wiki import WikiStore
            store = WikiStore()
            return store.recall(query, types=types, target=target, limit=limit)
        except Exception:
            return []

    def get_page(self, slug):
        try:
            from hydra.wiki import WikiStore
            store = WikiStore()
            return store.read(slug)
        except Exception:
            return None

    def lint(self):
        try:
            from hydra.wiki import WikiStore
            store = WikiStore()
            return store.lint()
        except Exception:
            return {}
