"""Coverage service — wraps CoverageStore."""

from hydra.services.base import BaseService


class CoverageService(BaseService):

    def _store(self):
        from hydra.coverage_store import CoverageStore
        return CoverageStore()

    def get_summary(self, engagement_id):
        try:
            store = self._store()
            return store.summary(engagement_id)
        except Exception:
            return {}

    def record(self, *, engagement_id, endpoint, vuln_class, status="untested", **kw):
        try:
            store = self._store()
            result = store.record(engagement_id=engagement_id, endpoint=endpoint,
                                  vuln_class=vuln_class, status=status, **kw)
            self._emit("coverage.updated", {"engagement_id": engagement_id})
            return result
        except Exception as e:
            return {"error": str(e)}

    def next_targets(self, engagement_id, limit=10):
        try:
            store = self._store()
            return store.next(engagement_id, limit=limit)
        except Exception:
            return []
