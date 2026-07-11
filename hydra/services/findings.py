"""Findings service — wraps FindingsStore."""

from hydra.services.base import BaseService


class FindingsService(BaseService):

    def _store(self):
        from hydra.findings_store import FindingsStore
        return FindingsStore()

    def list_findings(self, engagement_id, state=""):
        try:
            store = self._store()
            return store.list(engagement_id, state=state)
        except Exception:
            return []

    def get_finding(self, finding_id):
        try:
            store = self._store()
            return store.get(finding_id)
        except Exception:
            return None

    def create_finding(self, *, engagement_id, title, vuln_class="", severity="info", **kw):
        try:
            store = self._store()
            result = store.create(engagement_id=engagement_id, title=title,
                                  vuln_class=vuln_class, severity=severity, **kw)
            fid = result.get("finding_id", "")
            self._emit("finding.created", {"finding_id": fid, "severity": severity})
            return result
        except Exception as e:
            return {"error": str(e)}

    def transition(self, finding_id, to_state):
        try:
            store = self._store()
            result = store.transition(finding_id, to_state)
            self._emit("finding.transitioned", {"finding_id": finding_id, "to_state": to_state})
            return result
        except Exception as e:
            return {"error": str(e)}

    def add_evidence(self, finding_id, kind, content):
        try:
            store = self._store()
            return store.add_evidence(finding_id, kind, content)
        except Exception as e:
            return {"error": str(e)}
