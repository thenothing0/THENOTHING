"""
╔══════════════════════════════════════════════════════════════╗
║  Autonomous Bounty Hunter — Target Discovery & Selection     ║
║  Crawl platforms, score programs, auto-select targets,       ║
║  orchestrate full autonomous hunting campaigns               ║
║  NO COMPETITOR HAS THIS CAPABILITY                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import hashlib
import json
import logging
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.bounty_hunter")


# ──────────────────────────────────────────────
#  Data Structures
# ──────────────────────────────────────────────

class Platform(str, Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    SYNACK = "synack"
    CUSTOM = "custom"


class ProgramStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"
    NEW = "new"


class AssetType(str, Enum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    API = "api"
    MOBILE_APP = "mobile_app"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    OTHER = "other"


@dataclass
class ScopeAsset:
    """A single in-scope asset from a bug bounty program."""
    asset: str
    asset_type: AssetType = AssetType.DOMAIN
    eligible_for_bounty: bool = True
    max_severity: str = "critical"
    instruction: str = ""


@dataclass
class BountyProgram:
    """Represents a bug bounty program on any platform."""
    id: str = ""
    name: str = ""
    platform: Platform = Platform.HACKERONE
    url: str = ""
    status: ProgramStatus = ProgramStatus.ACTIVE

    # Payout info
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    avg_bounty: float = 0.0
    currency: str = "USD"

    # Response metrics
    avg_response_time_hours: float = 72.0
    avg_triage_time_hours: float = 24.0
    avg_resolution_time_hours: float = 168.0
    response_efficiency: float = 0.5  # 0-1

    # Scope
    in_scope: List[ScopeAsset] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    scope_size: int = 0

    # Program quality
    managed: bool = False
    offers_safe_harbor: bool = False
    reports_resolved: int = 0
    total_reports: int = 0
    hackers_thanked: int = 0

    # Competition
    active_hackers: int = 0
    competition_level: str = "medium"  # low, medium, high, extreme

    # Tech stack (detected or declared)
    tech_stack: List[str] = field(default_factory=list)
    industry: str = ""

    # Scoring
    composite_score: float = 0.0
    last_scored: float = 0.0
    last_crawled: float = 0.0


@dataclass
class HuntCampaign:
    """An autonomous hunting campaign on a selected target."""
    id: str = ""
    program: Optional[BountyProgram] = None
    target_assets: List[ScopeAsset] = field(default_factory=list)
    status: str = "pending"  # pending, active, paused, completed, abandoned
    started_at: float = 0.0
    completed_at: float = 0.0
    findings_count: int = 0
    reports_submitted: int = 0
    bounties_earned: float = 0.0
    researcher_profile: str = "balanced"
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


# ──────────────────────────────────────────────
#  Program Scorer
# ──────────────────────────────────────────────

class ProgramScorer:
    """
    Multi-factor program scoring engine.

    Evaluates programs across 5 dimensions:
      1. Payout potential (25%)
      2. Response quality (15%)
      3. Scope breadth (20%)
      4. Tech stack match (25%)
      5. Competition inverse (15%)

    Returns a composite 0-1 score used for target selection.
    """

    WEIGHTS = {
        "payout": 0.25,
        "response": 0.15,
        "scope": 0.20,
        "tech_match": 0.25,
        "competition": 0.15,
    }

    def __init__(self, known_strengths: Optional[List[str]] = None):
        self._known_strengths = known_strengths or [
            "wordpress", "react", "next.js", "node.js", "python",
            "django", "flask", "aws", "graphql", "jwt", "oauth",
            "php", "laravel", "spring", "angular", "vue",
        ]
        self._scoring_history: List[Dict[str, Any]] = []

    def score(self, program: BountyProgram) -> float:
        """Score a program using multi-factor analysis."""
        factors = {
            "payout": self._score_payout(program),
            "response": self._score_response(program),
            "scope": self._score_scope(program),
            "tech_match": self._score_tech_match(program),
            "competition": self._score_competition(program),
        }

        composite = sum(
            factors[k] * self.WEIGHTS[k] for k in factors
        )

        program.composite_score = round(composite, 4)
        program.last_scored = time.time()

        self._scoring_history.append({
            "program": program.name,
            "factors": factors,
            "composite": composite,
            "timestamp": time.time(),
        })

        return composite

    def _score_payout(self, p: BountyProgram) -> float:
        if p.max_bounty <= 0:
            return 0.1
        if p.max_bounty >= 50000:
            return 1.0
        if p.max_bounty >= 20000:
            return 0.85
        if p.max_bounty >= 10000:
            return 0.7
        if p.max_bounty >= 5000:
            return 0.55
        if p.max_bounty >= 1000:
            return 0.4
        return 0.2

    def _score_response(self, p: BountyProgram) -> float:
        if p.response_efficiency > 0:
            return min(p.response_efficiency, 1.0)
        if p.avg_response_time_hours <= 12:
            return 0.95
        if p.avg_response_time_hours <= 48:
            return 0.7
        if p.avg_response_time_hours <= 168:
            return 0.4
        return 0.2

    def _score_scope(self, p: BountyProgram) -> float:
        wildcard_count = sum(
            1 for a in p.in_scope if a.asset_type == AssetType.WILDCARD
        )
        domain_count = sum(
            1 for a in p.in_scope if a.asset_type == AssetType.DOMAIN
        )
        api_count = sum(
            1 for a in p.in_scope if a.asset_type == AssetType.API
        )

        score = 0.2
        if wildcard_count > 0:
            score += 0.4  # Wildcards = massive attack surface
        score += min(domain_count * 0.05, 0.3)
        score += min(api_count * 0.1, 0.2)
        return min(score, 1.0)

    def _score_tech_match(self, p: BountyProgram) -> float:
        if not p.tech_stack:
            return 0.5  # Unknown = neutral
        matches = sum(
            1 for tech in p.tech_stack
            if tech.lower() in [s.lower() for s in self._known_strengths]
        )
        if not p.tech_stack:
            return 0.5
        return min(matches / max(len(p.tech_stack), 1) + 0.2, 1.0)

    def _score_competition(self, p: BountyProgram) -> float:
        level_map = {
            "low": 0.9, "medium": 0.6,
            "high": 0.35, "extreme": 0.15,
        }
        return level_map.get(p.competition_level, 0.5)

    def update_strengths(self, new_strengths: List[str]):
        """Update known strengths from learning engine feedback."""
        for s in new_strengths:
            if s.lower() not in [x.lower() for x in self._known_strengths]:
                self._known_strengths.append(s)


# ──────────────────────────────────────────────
#  Target Selector
# ──────────────────────────────────────────────

class TargetSelector:
    """
    Autonomous target selection with portfolio optimization.

    Selects targets that maximize expected value while
    maintaining diversity across industries, tech stacks,
    and vulnerability classes.
    """

    def __init__(self, max_concurrent: int = 3):
        self._max_concurrent = max_concurrent
        self._active_campaigns: List[HuntCampaign] = []
        self._completed_campaigns: List[HuntCampaign] = []
        self._blacklist: set = set()

    def select(self, programs: List[BountyProgram],
               top_n: int = 5) -> List[BountyProgram]:
        """Select top-N programs for hunting."""
        # Filter out blacklisted / inactive
        eligible = [
            p for p in programs
            if p.status == ProgramStatus.ACTIVE
            and p.id not in self._blacklist
            and p.composite_score > 0
        ]

        # Sort by composite score
        eligible.sort(key=lambda p: p.composite_score, reverse=True)

        # Diversify by industry (don't pick 5 fintech programs)
        selected = []
        industries_seen = set()
        for p in eligible:
            if len(selected) >= top_n:
                break
            if p.industry and p.industry in industries_seen and len(selected) > 2:
                continue  # Skip duplicate industries after first 2
            selected.append(p)
            if p.industry:
                industries_seen.add(p.industry)

        logger.info(
            f"🎯 Selected {len(selected)} targets from "
            f"{len(eligible)} eligible programs"
        )
        for i, p in enumerate(selected):
            logger.info(
                f"  #{i+1}: {p.name} (score={p.composite_score:.3f}, "
                f"max_bounty=${p.max_bounty:,.0f}, "
                f"competition={p.competition_level})"
            )

        return selected

    def blacklist_program(self, program_id: str, reason: str = ""):
        """Blacklist a program from future selection."""
        self._blacklist.add(program_id)
        logger.info(f"Blacklisted program {program_id}: {reason}")

    def create_campaign(self, program: BountyProgram,
                        profile: str = "balanced") -> HuntCampaign:
        """Create a new hunt campaign for a selected program."""
        campaign = HuntCampaign(
            id=hashlib.sha256(
                f"{program.id}:{time.time()}".encode()
            ).hexdigest()[:16],
            program=program,
            target_assets=[
                a for a in program.in_scope if a.eligible_for_bounty
            ],
            status="pending",
            researcher_profile=profile,
        )
        self._active_campaigns.append(campaign)
        return campaign


# ──────────────────────────────────────────────
#  Platform Crawler (Abstract + HackerOne)
# ──────────────────────────────────────────────

class PlatformCrawler:
    """
    Abstract platform crawler.

    Subclasses implement platform-specific crawling logic.
    All crawlers return normalized BountyProgram objects.
    """

    def __init__(self, api_key: str = "", rate_limit: float = 1.0):
        self._api_key = api_key
        self._rate_limit = rate_limit
        self._last_request = 0.0
        self._programs_cache: Dict[str, BountyProgram] = {}

    async def _rate_limit_wait(self):
        elapsed = time.time() - self._last_request
        if elapsed < self._rate_limit:
            await asyncio.sleep(self._rate_limit - elapsed)
        self._last_request = time.time()

    async def crawl_programs(self) -> List[BountyProgram]:
        raise NotImplementedError

    async def crawl_program_detail(self, program_id: str) -> BountyProgram:
        raise NotImplementedError


class HackerOneCrawler(PlatformCrawler):
    """
    HackerOne platform crawler.

    Uses the HackerOne API to discover and analyze programs.
    Requires a valid API token for full access.
    Falls back to public directory scraping if no token.
    """

    BASE_URL = "https://api.hackerone.com/v1"

    async def crawl_programs(self) -> List[BountyProgram]:
        """Crawl HackerOne for active bounty programs."""
        programs = []

        if self._api_key:
            programs = await self._crawl_via_api()
        else:
            programs = await self._crawl_public_directory()

        for p in programs:
            self._programs_cache[p.id] = p

        logger.info(f"HackerOne: crawled {len(programs)} programs")
        return programs

    async def _crawl_via_api(self) -> List[BountyProgram]:
        """Crawl via authenticated HackerOne API."""
        programs = []
        try:
            import aiohttp
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            }
            async with aiohttp.ClientSession(headers=headers) as session:
                url = f"{self.BASE_URL}/hackers/programs"
                params = {"page[size]": 100, "filter[state][]": "started"}

                await self._rate_limit_wait()
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("data", []):
                            program = self._parse_program(item)
                            if program:
                                programs.append(program)
        except ImportError:
            logger.warning("aiohttp not available — using public directory")
            programs = await self._crawl_public_directory()
        except Exception as e:
            logger.warning(f"HackerOne API error: {e}")

        return programs

    async def _crawl_public_directory(self) -> List[BountyProgram]:
        """Crawl public HackerOne directory (no auth needed)."""
        programs = []
        try:
            import aiohttp
            url = "https://hackerone.com/sitemap.xml"
            async with aiohttp.ClientSession() as session:
                await self._rate_limit_wait()
                async with session.get(url) as resp:
                    if resp.status == 200:
                        # Parse sitemap for program URLs
                        text = await resp.text()
                        # Extract program slugs from sitemap
                        import re
                        slugs = re.findall(
                            r'hackerone\.com/([a-zA-Z0-9_-]+)</loc>', text
                        )
                        for slug in slugs[:100]:  # Limit to 100
                            programs.append(BountyProgram(
                                id=f"h1:{slug}",
                                name=slug,
                                platform=Platform.HACKERONE,
                                url=f"https://hackerone.com/{slug}",
                                status=ProgramStatus.ACTIVE,
                            ))
        except Exception as e:
            logger.warning(f"HackerOne public crawl error: {e}")

        return programs

    def _parse_program(self, data: Dict) -> Optional[BountyProgram]:
        """Parse a HackerOne API program response into BountyProgram."""
        try:
            attrs = data.get("attributes", {})
            rels = data.get("relationships", {})

            # Parse scope
            scope_assets = []
            for scope in rels.get("structured_scopes", {}).get("data", []):
                sa = scope.get("attributes", {})
                asset_type_map = {
                    "URL": AssetType.DOMAIN,
                    "WILDCARD": AssetType.WILDCARD,
                    "API": AssetType.API,
                    "APPLE_STORE_APP_ID": AssetType.MOBILE_APP,
                    "GOOGLE_PLAY_APP_ID": AssetType.MOBILE_APP,
                    "SOURCE_CODE": AssetType.SOURCE_CODE,
                }
                scope_assets.append(ScopeAsset(
                    asset=sa.get("asset_identifier", ""),
                    asset_type=asset_type_map.get(
                        sa.get("asset_type", ""), AssetType.OTHER
                    ),
                    eligible_for_bounty=sa.get(
                        "eligible_for_bounty", True
                    ),
                    max_severity=sa.get("max_severity", "critical"),
                ))

            return BountyProgram(
                id=f"h1:{data.get('id', '')}",
                name=attrs.get("name", data.get("id", "")),
                platform=Platform.HACKERONE,
                url=f"https://hackerone.com/{attrs.get('handle', '')}",
                status=ProgramStatus.ACTIVE if attrs.get(
                    "state") == "public_mode" else ProgramStatus.PAUSED,
                min_bounty=attrs.get("min_bounty", 0),
                max_bounty=attrs.get("max_bounty", 0),
                avg_bounty=attrs.get("average_bounty_lower_amount", 0),
                offers_safe_harbor=attrs.get(
                    "offers_bounties", False
                ),
                in_scope=scope_assets,
                scope_size=len(scope_assets),
            )
        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return None


class BugcrowdCrawler(PlatformCrawler):
    """Bugcrowd platform crawler."""

    async def crawl_programs(self) -> List[BountyProgram]:
        programs = []
        try:
            import aiohttp
            url = "https://bugcrowd.com/programs.json"
            async with aiohttp.ClientSession() as session:
                await self._rate_limit_wait()
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("programs", []):
                            programs.append(BountyProgram(
                                id=f"bc:{item.get('code', '')}",
                                name=item.get("name", ""),
                                platform=Platform.BUGCROWD,
                                url=f"https://bugcrowd.com/{item.get('code', '')}",
                                status=ProgramStatus.ACTIVE,
                                max_bounty=item.get(
                                    "max_reward", 0
                                ) or 0,
                            ))
        except Exception as e:
            logger.warning(f"Bugcrowd crawl error: {e}")

        logger.info(f"Bugcrowd: crawled {len(programs)} programs")
        return programs


# ──────────────────────────────────────────────
#  Bounty Hunter Orchestrator
# ──────────────────────────────────────────────

class BountyHunterEngine:
    """
    Autonomous Bounty Hunter — the brain behind target discovery.

    Lifecycle:
      1. DISCOVER — Crawl platforms for programs
      2. SCORE — Evaluate each program with multi-factor scoring
      3. SELECT — Pick high-value targets with portfolio diversity
      4. HUNT — Launch autonomous campaigns on selected targets
      5. MONITOR — Watch for scope changes, new programs
      6. LEARN — Update strengths from campaign outcomes

    This engine gives THENOTHING the ability to autonomously
    find its own targets — a capability NO competitor has.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self._scorer = ProgramScorer(
            known_strengths=config.get("known_strengths")
        )
        self._selector = TargetSelector(
            max_concurrent=config.get("max_concurrent_hunts", 3)
        )
        self._crawlers: Dict[Platform, PlatformCrawler] = {}
        self._all_programs: List[BountyProgram] = []
        self._campaigns: List[HuntCampaign] = []
        self._monitor_interval = config.get("monitor_interval", 3600)

        # Initialize crawlers
        h1_token = config.get("hackerone_token", "")
        self._crawlers[Platform.HACKERONE] = HackerOneCrawler(
            api_key=h1_token
        )
        self._crawlers[Platform.BUGCROWD] = BugcrowdCrawler()

    async def discover(self) -> List[BountyProgram]:
        """Phase 1: Discover programs across all platforms."""
        logger.info("🔍 Discovering bug bounty programs...")
        all_programs = []

        for platform, crawler in self._crawlers.items():
            try:
                programs = await crawler.crawl_programs()
                all_programs.extend(programs)
                logger.info(
                    f"  {platform.value}: {len(programs)} programs"
                )
            except Exception as e:
                logger.warning(f"  {platform.value}: crawl failed: {e}")

        self._all_programs = all_programs
        logger.info(
            f"📋 Total programs discovered: {len(all_programs)}"
        )
        return all_programs

    def score_all(self) -> List[BountyProgram]:
        """Phase 2: Score all discovered programs."""
        logger.info("📊 Scoring programs...")
        for program in self._all_programs:
            self._scorer.score(program)

        scored = sorted(
            self._all_programs,
            key=lambda p: p.composite_score, reverse=True,
        )

        top5 = scored[:5]
        for i, p in enumerate(top5):
            logger.info(
                f"  #{i+1}: {p.name} — score={p.composite_score:.3f}"
            )

        return scored

    def select_targets(self, top_n: int = 5) -> List[BountyProgram]:
        """Phase 3: Select high-value targets."""
        return self._selector.select(self._all_programs, top_n)

    def create_campaign(self, program: BountyProgram,
                        profile: str = "balanced") -> HuntCampaign:
        """Phase 4: Create a hunt campaign."""
        campaign = self._selector.create_campaign(program, profile)
        self._campaigns.append(campaign)
        logger.info(
            f"🎯 Campaign created: {program.name} "
            f"(profile={profile}, assets={len(campaign.target_assets)})"
        )
        return campaign

    def update_from_learning(self, outcomes: List[Dict[str, Any]]):
        """Phase 6: Update scoring from campaign outcomes."""
        new_strengths = []
        for outcome in outcomes:
            if outcome.get("status") == "confirmed":
                tech = outcome.get("tech_stack", [])
                new_strengths.extend(tech)

        if new_strengths:
            self._scorer.update_strengths(new_strengths)
            logger.info(
                f"📚 Updated strengths from {len(outcomes)} outcomes"
            )

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_programs": len(self._all_programs),
            "platforms_active": len(self._crawlers),
            "campaigns_active": len([
                c for c in self._campaigns if c.status == "active"
            ]),
            "campaigns_completed": len([
                c for c in self._campaigns if c.status == "completed"
            ]),
            "top_programs": [
                {"name": p.name, "score": p.composite_score}
                for p in sorted(
                    self._all_programs,
                    key=lambda x: x.composite_score, reverse=True
                )[:5]
            ],
        }
