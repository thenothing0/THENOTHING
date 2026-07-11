"""Engagement service — wraps EngagementStore."""

from hydra.services.base import BaseService


class EngagementService(BaseService):

    def list_engagements(self):
        try:
            from hydra.engagement import EngagementStore
            store = EngagementStore()
            return store.list()
        except Exception:
            return []

    def get_engagement(self, engagement_id):
        try:
            from hydra.engagement import EngagementStore
            store = EngagementStore()
            return store.get(engagement_id)
        except Exception:
            return None

    def create_engagement(self, *, client, name, scope, owner="operator"):
        try:
            from hydra.engagement import EngagementStore
            store = EngagementStore()
            result = store.create(client=client, name=name, scope=scope, owner=owner)
            self._emit("engagement.created", {"engagement_id": result.get("engagement_id", "")})
            return result
        except Exception as e:
            return {"error": str(e)}

    def get_workflow(self, workflow_id):
        try:
            from hydra.pentest_workflow import PentestWorkflowStore
            store = PentestWorkflowStore()
            return store.status(workflow_id)
        except Exception:
            return None
