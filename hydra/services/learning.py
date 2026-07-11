"""Learning service — wraps LearningTiersStore."""

from hydra.services.base import BaseService


class LearningService(BaseService):

    def _store(self):
        from hydra.learning_tiers import LearningTiersStore
        return LearningTiersStore()

    def record(self, *, tier, title, category, lesson, **kw):
        try:
            store = self._store()
            result = store.record(tier=tier, title=title, category=category,
                                  lesson=lesson, **kw)
            self._emit("lesson.recorded", {"tier": tier, "title": title})
            return result
        except Exception as e:
            return {"error": str(e)}

    def search(self, query, tier="all", k=5):
        try:
            store = self._store()
            return store.search(query, tier=tier, k=k)
        except Exception:
            return []

    def stats(self):
        try:
            store = self._store()
            return store.stats()
        except Exception:
            return {}

    def quarantined(self):
        try:
            store = self._store()
            return store.quarantined()
        except Exception:
            return []
