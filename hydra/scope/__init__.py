"""
╔══════════════════════════════════════════════════════════════╗
║  HackerOne / Bug Bounty Scope Intelligence Integration     ║
║  Program parsing, scope enforcement, program memory        ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

logger = logging.getLogger("hydra.scope")


@dataclass
class ProgramScope:
    """Normalized scope model for any bug bounty platform."""
    program_name: str
    platform: str  # hackerone, bugcrowd, intigriti, yeswehack, custom
    in_scope: List[Dict[str, str]] = field(default_factory=list)
    out_of_scope: List[Dict[str, str]] = field(default_factory=list)
    allowed_testing: List[str] = field(default_factory=list)
    forbidden_testing: List[str] = field(default_factory=list)
    rate_limit: Optional[int] = None
    disclosure_policy: str = ""
    bounty_rules: str = ""
    severity_guidelines: Dict[str, str] = field(default_factory=dict)
    program_url: str = ""
    last_updated: float = field(default_factory=time.time)


@dataclass
class ScopeIntelligenceReport:
    """Pre-scan scope intelligence report."""
    program: ProgramScope
    allowed_testing_matrix: Dict[str, bool] = field(default_factory=dict)
    target_risk_map: List[Dict[str, Any]] = field(default_factory=list)
    recommended_workflow: str = "full_assessment"
    warnings: List[str] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)


class ProgramAdapter(ABC):
    """Abstract adapter for bug bounty platforms."""

    @abstractmethod
    async def fetch_program(self, program_id: str) -> ProgramScope:
        pass

    @abstractmethod
    async def parse_scope(self, raw_data: Dict) -> ProgramScope:
        pass


class HackerOneAdapter(ProgramAdapter):
    """HackerOne program scope adapter."""

    BASE_URL = "https://hackerone.com"

    async def fetch_program(self, program_handle: str) -> ProgramScope:
        """Fetch program scope from HackerOne."""
        try:
            import aiohttp
            url = f"{self.BASE_URL}/{program_handle}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        return self._parse_html_scope(
                            program_handle, html
                        )
        except ImportError:
            logger.warning("aiohttp not available for HackerOne fetch")
        except Exception as e:
            logger.warning(f"HackerOne fetch failed: {e}")

        return ProgramScope(
            program_name=program_handle,
            platform="hackerone",
        )

    async def parse_scope(self, raw_data: Dict) -> ProgramScope:
        """Parse raw HackerOne program data."""
        scope = ProgramScope(
            program_name=raw_data.get("name", ""),
            platform="hackerone",
            program_url=raw_data.get("url", ""),
        )

        for asset in raw_data.get("in_scope", []):
            scope.in_scope.append({
                "asset": asset.get("asset", ""),
                "type": asset.get("type", "url"),
                "instruction": asset.get("instruction", ""),
            })

        for asset in raw_data.get("out_of_scope", []):
            scope.out_of_scope.append({
                "asset": asset.get("asset", ""),
                "type": asset.get("type", "url"),
                "reason": asset.get("reason", ""),
            })

        scope.forbidden_testing = raw_data.get("forbidden", [])
        scope.allowed_testing = raw_data.get("allowed", [])

        return scope

    def _parse_html_scope(self, handle: str, html: str) -> ProgramScope:
        """Best-effort HTML parsing of HackerOne program page."""
        scope = ProgramScope(
            program_name=handle, platform="hackerone",
            program_url=f"{self.BASE_URL}/{handle}",
        )

        # Extract domains from HTML (simplified)
        domain_pattern = r'[\w.-]+\.\w{2,}'
        domains = set(re.findall(domain_pattern, html))
        for d in domains:
            if not any(x in d for x in ["hackerone", "cloudflare", "google"]):
                scope.in_scope.append({"asset": d, "type": "url"})

        return scope


class BugcrowdAdapter(ProgramAdapter):
    """Bugcrowd program scope adapter."""

    async def fetch_program(self, program_id: str) -> ProgramScope:
        return ProgramScope(
            program_name=program_id, platform="bugcrowd",
        )

    async def parse_scope(self, raw_data: Dict) -> ProgramScope:
        return ProgramScope(
            program_name=raw_data.get("name", ""),
            platform="bugcrowd",
        )


class CustomProgramAdapter(ProgramAdapter):
    """Adapter for custom/private programs."""

    async def fetch_program(self, program_id: str) -> ProgramScope:
        return ProgramScope(
            program_name=program_id, platform="custom",
        )

    async def parse_scope(self, raw_data: Dict) -> ProgramScope:
        scope = ProgramScope(
            program_name=raw_data.get("name", "custom"),
            platform="custom",
        )
        for asset in raw_data.get("in_scope", []):
            if isinstance(asset, str):
                scope.in_scope.append({"asset": asset, "type": "url"})
            elif isinstance(asset, dict):
                scope.in_scope.append(asset)
        for asset in raw_data.get("out_of_scope", []):
            if isinstance(asset, str):
                scope.out_of_scope.append({"asset": asset, "type": "url"})
            elif isinstance(asset, dict):
                scope.out_of_scope.append(asset)
        scope.forbidden_testing = raw_data.get("forbidden_testing", [])
        scope.rate_limit = raw_data.get("rate_limit")
        return scope


# Platform → adapter mapping
ADAPTERS = {
    "hackerone": HackerOneAdapter,
    "bugcrowd": BugcrowdAdapter,
    "custom": CustomProgramAdapter,
}


class ScopePolicyEngine:
    """
    Scope-aware execution policy engine.
    
    Before any scan:
      1. Validate target against scope
      2. Block out-of-scope assets
      3. Enforce program restrictions
      4. Apply safe rate limits
      5. Disable dangerous modules if forbidden
    """

    def __init__(self):
        self._scope: Optional[ProgramScope] = None
        self._adapter: Optional[ProgramAdapter] = None

    async def load_scope(
        self, platform: str = "custom",
        program_id: str = "",
        raw_scope: Optional[Dict] = None,
    ) -> ProgramScope:
        """Load scope from a platform or raw data."""
        adapter_cls = ADAPTERS.get(platform, CustomProgramAdapter)
        self._adapter = adapter_cls()

        if raw_scope:
            self._scope = await self._adapter.parse_scope(raw_scope)
        else:
            self._scope = await self._adapter.fetch_program(program_id)

        logger.info(
            f"🎯 Scope loaded: {self._scope.program_name} "
            f"({self._scope.platform}) — "
            f"{len(self._scope.in_scope)} in-scope, "
            f"{len(self._scope.out_of_scope)} out-of-scope"
        )
        return self._scope

    def validate_target(self, target: str) -> Dict[str, Any]:
        """Validate a target against loaded scope."""
        if not self._scope:
            return {"allowed": True, "reason": "No scope loaded"}

        target_clean = target.lower().strip()
        for prefix in ["https://", "http://"]:
            if target_clean.startswith(prefix):
                target_clean = target_clean[len(prefix):]
        target_clean = target_clean.split("/")[0].split(":")[0]

        # Check out-of-scope first
        for oos in self._scope.out_of_scope:
            asset = oos.get("asset", "").lower()
            if self._domain_matches(target_clean, asset):
                return {
                    "allowed": False,
                    "reason": f"Out of scope: {asset}",
                    "target": target,
                }

        # Check in-scope
        if self._scope.in_scope:
            for ins in self._scope.in_scope:
                asset = ins.get("asset", "").lower()
                if self._domain_matches(target_clean, asset):
                    return {"allowed": True, "target": target}
            return {
                "allowed": False,
                "reason": "Not in scope",
                "target": target,
            }

        return {"allowed": True, "reason": "No scope restrictions"}

    @staticmethod
    def _domain_matches(target: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            base = pattern[2:]
            return target == base or target.endswith("." + base)
        return target == pattern

    def generate_execution_policy(self) -> Dict[str, Any]:
        """Generate execution policy from scope."""
        if not self._scope:
            return {"policy": "unrestricted"}

        policy = {
            "allowed_targets": [
                a["asset"] for a in self._scope.in_scope
            ],
            "blocked_targets": [
                a["asset"] for a in self._scope.out_of_scope
            ],
            "forbidden_testing": self._scope.forbidden_testing,
            "rate_limit": self._scope.rate_limit or 50,
            "allow_brute_force": "brute" not in " ".join(
                self._scope.forbidden_testing
            ).lower(),
            "program": self._scope.program_name,
            "platform": self._scope.platform,
        }
        return policy

    def generate_intelligence_report(self) -> ScopeIntelligenceReport:
        """Generate pre-scan scope intelligence report."""
        if not self._scope:
            return ScopeIntelligenceReport(
                program=ProgramScope(
                    program_name="unknown", platform="custom"
                )
            )

        scope = self._scope
        warnings = []

        # Build testing matrix
        matrix = {
            "subdomain_enum": True,
            "port_scanning": "port" not in " ".join(scope.forbidden_testing).lower(),
            "brute_force": "brute" not in " ".join(scope.forbidden_testing).lower(),
            "vulnerability_scanning": True,
            "fuzzing": "fuzz" not in " ".join(scope.forbidden_testing).lower(),
            "exploit_testing": "exploit" not in " ".join(scope.forbidden_testing).lower(),
        }

        # Warnings
        if not scope.in_scope:
            warnings.append("No explicit in-scope assets defined")
        if scope.forbidden_testing:
            warnings.append(
                f"Forbidden: {', '.join(scope.forbidden_testing)}"
            )

        # Target risk map
        risk_map = []
        for asset in scope.in_scope:
            risk_map.append({
                "asset": asset.get("asset", ""),
                "type": asset.get("type", "url"),
                "estimated_risk": "medium",
            })

        # Workflow recommendation
        if any(a.get("type") == "api" for a in scope.in_scope):
            workflow = "api_assessment"
        elif len(scope.in_scope) > 10:
            workflow = "full_assessment"
        else:
            workflow = "quick_scan"

        return ScopeIntelligenceReport(
            program=scope,
            allowed_testing_matrix=matrix,
            target_risk_map=risk_map,
            recommended_workflow=workflow,
            warnings=warnings,
        )


class ProgramMemory:
    """
    Store and recall program-specific intelligence.
    
    Remembers:
      - Previous scopes
      - Successful findings history
      - Target technology patterns
      - Preferred vulnerability classes
    """

    def __init__(self):
        self._programs: Dict[str, Dict[str, Any]] = {}

    def remember_program(self, scope: ProgramScope,
                         findings: Optional[List[Dict]] = None):
        key = f"{scope.platform}:{scope.program_name}"
        if key not in self._programs:
            self._programs[key] = {
                "scope": scope, "scans": [],
                "total_findings": 0,
                "successful_types": {},
            }
        entry = self._programs[key]
        entry["scope"] = scope
        entry["scans"].append({"timestamp": time.time()})
        if findings:
            entry["total_findings"] += len(findings)
            for f in findings:
                ftype = f.get("type", "unknown")
                entry["successful_types"][ftype] = (
                    entry["successful_types"].get(ftype, 0) + 1
                )

    def get_program_history(self, platform: str,
                            name: str) -> Optional[Dict]:
        key = f"{platform}:{name}"
        return self._programs.get(key)

    def get_recommended_focus(self, platform: str,
                               name: str) -> List[str]:
        """Get recommended vulnerability types based on history."""
        history = self.get_program_history(platform, name)
        if not history:
            return []
        types = history.get("successful_types", {})
        return sorted(types, key=types.get, reverse=True)[:5]
