"""
Declarative campaign playbook templates (Phase Q).

Data only — pure declarative planning scaffolds (like the capability catalog). NOT executable, NOT
canonical. Each template selects capabilities by category and lists the campaign phases it spans.
"""

from __future__ import annotations

from typing import Dict, List, Optional

TEMPLATES: List[Dict] = [
    {"id": "web_application_assessment", "name": "Web Application Assessment",
     "target_type": "url", "categories": ["reconnaissance", "web", "api", "verification"],
     "phases": ["recon", "enumeration", "initial_access", "execution"]},
    {"id": "cloud_assessment", "name": "Cloud Assessment",
     "target_type": "cloud", "categories": ["reconnaissance", "cloud", "secrets", "verification"],
     "phases": ["recon", "enumeration", "discovery", "initial_access", "execution"]},
    {"id": "container_assessment", "name": "Container / K8s Assessment",
     "target_type": "host", "categories": ["reconnaissance", "cloud", "verification"],
     "phases": ["recon", "enumeration", "discovery", "execution"]},
    {"id": "supply_chain_assessment", "name": "Supply Chain Assessment",
     "target_type": "org", "categories": ["reconnaissance", "source_code", "secrets", "verification"],
     "phases": ["recon", "enumeration", "credential_access", "execution"]},
    {"id": "red_team_prep", "name": "Red Team Preparation",
     "target_type": "domain",
     "categories": ["reconnaissance", "web", "api", "cloud", "secrets", "source_code", "verification"],
     "phases": ["recon", "enumeration", "initial_access", "execution", "credential_access", "discovery"]},
]


def get_template(template_id: str) -> Optional[Dict]:
    return next((t for t in TEMPLATES if t["id"] == template_id), None)
