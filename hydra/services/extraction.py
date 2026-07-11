"""Extraction Service — AI-enhanced deep field extraction from security reports.

Supplements the regex-based extraction in ReportIntelligencePipeline with
LLM-powered analysis for fields that require semantic understanding:
root cause analysis, exploitation flow, preconditions, detection opportunities.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.extraction")

# Precompiled regex patterns for fallback extraction
_CWE_RE = re.compile(r"CWE-\d+")
_STEP_RE = re.compile(r"(?:step\s*\d+|^\d+\.)\s*(.+)", re.MULTILINE | re.IGNORECASE)
_TACTIC_RE = re.compile(r"TA\d{4}")
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
_JSON_RE = re.compile(r"\{[\s\S]*\}")


@dataclass
class ExtractionResult:
    """Structured extraction output."""
    fields: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    model_used: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": self.fields,
            "confidence": self.confidence,
            "model_used": self.model_used,
            "error": self.error,
        }


# Extraction prompts keyed by field type
_PROMPTS: dict[str, str] = {
    "root_cause": (
        "Analyze this security report and extract the root cause of the vulnerability. "
        "Be specific about the code-level or architectural flaw. "
        "Return JSON: {\"root_cause\": \"...\", \"cwe\": \"CWE-XXX\", \"confidence\": 0.0-1.0}"
    ),
    "exploitation_flow": (
        "Extract the step-by-step exploitation flow from this security report. "
        "Return JSON: {\"steps\": [\"step1\", ...], \"preconditions\": [\"...\"], "
        "\"tools_used\": [\"...\"], \"confidence\": 0.0-1.0}"
    ),
    "impact_analysis": (
        "Analyze the security impact described in this report. "
        "Return JSON: {\"technical_impact\": \"...\", \"business_impact\": \"...\", "
        "\"affected_users\": \"...\", \"data_at_risk\": \"...\", \"confidence\": 0.0-1.0}"
    ),
    "detection": (
        "Extract detection opportunities from this vulnerability report. "
        "How could a defender detect exploitation of this vulnerability? "
        "Return JSON: {\"indicators\": [\"...\"], \"log_sources\": [\"...\"], "
        "\"detection_rules\": [\"...\"], \"confidence\": 0.0-1.0}"
    ),
    "remediation": (
        "Extract detailed remediation guidance from this security report. "
        "Return JSON: {\"immediate\": [\"...\"], \"short_term\": [\"...\"], "
        "\"long_term\": [\"...\"], \"confidence\": 0.0-1.0}"
    ),
    "ttp_extraction": (
        "Extract MITRE ATT&CK TTPs (Tactics, Techniques, Procedures) from this report. "
        "Return JSON: {\"tactics\": [\"TA00XX\"], \"techniques\": [\"T1XXX\"], "
        "\"procedures\": [\"...\"], \"confidence\": 0.0-1.0}"
    ),
}


class ExtractionService(BaseService):
    """AI-powered deep extraction from security content.

    Uses the AI router to send content to an LLM for structured extraction
    of fields that regex cannot reliably capture.
    """

    def extract_field(self, text: str, field_type: str,
                      model: str = "") -> ExtractionResult:
        """Extract a specific field type from text using AI."""
        if field_type not in _PROMPTS:
            return ExtractionResult(
                error=f"Unknown field type: {field_type}. "
                      f"Available: {', '.join(_PROMPTS)}"
            )
        try:
            prompt = _PROMPTS[field_type]
            response = self._call_llm(text, prompt, model=model)
            parsed = self._parse_json_response(response)
            confidence = parsed.pop("confidence", 0.5)
            return ExtractionResult(
                fields=parsed,
                confidence=confidence,
                model_used=model or "default",
            )
        except Exception as e:
            logger.error("extract_field(%s) failed: %s", field_type, e)
            return ExtractionResult(error=str(e))

    def extract_all(self, text: str, model: str = "") -> dict[str, ExtractionResult]:
        """Extract all supported field types from text."""
        results = {}
        for field_type in _PROMPTS:
            results[field_type] = self.extract_field(text, field_type, model=model)
        self._emit("extraction.completed", {
            "fields_extracted": len(results),
            "successful": sum(1 for r in results.values() if r.ok),
        })
        return results

    def extract_custom(self, text: str, prompt: str,
                       model: str = "") -> ExtractionResult:
        """Extract using a custom prompt."""
        try:
            response = self._call_llm(text, prompt, model=model)
            parsed = self._parse_json_response(response)
            confidence = parsed.pop("confidence", 0.5)
            return ExtractionResult(
                fields=parsed,
                confidence=confidence,
                model_used=model or "default",
            )
        except Exception as e:
            logger.error("extract_custom failed: %s", e)
            return ExtractionResult(error=str(e))

    def list_field_types(self) -> list[str]:
        """Return available extraction field types."""
        return list(_PROMPTS.keys())

    def _call_llm(self, content: str, system_prompt: str,
                  model: str = "") -> str:
        """Call the AI router for extraction."""
        try:
            from hydra.ai.router import AIRouter
            router = AIRouter()
            truncated = content[:12000]
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": truncated},
            ]
            return router.complete(messages, task_type="extraction",
                                   model=model or None)
        except ImportError:
            return self._fallback_extract(content, system_prompt)

    def _fallback_extract(self, content: str, prompt: str) -> str:
        """Regex-based fallback when no AI provider is available."""
        result: dict[str, Any] = {"confidence": 0.3}
        cwe_match = _CWE_RE.search(content)
        if cwe_match:
            result["cwe"] = cwe_match.group()
        if "root cause" in prompt.lower():
            for line in content.split("\n"):
                if any(kw in line.lower() for kw in ("root cause", "flaw", "vulnerability")):
                    result["root_cause"] = line.strip()[:200]
                    break
        if "step" in prompt.lower() or "flow" in prompt.lower():
            steps = _STEP_RE.findall(content)
            if steps:
                result["steps"] = [s.strip() for s in steps[:10]]
        if "impact" in prompt.lower():
            for line in content.split("\n"):
                if "impact" in line.lower():
                    result["technical_impact"] = line.strip()[:200]
                    break
        if "detection" in prompt.lower() or "indicator" in prompt.lower():
            indicators = []
            for line in content.split("\n"):
                if any(kw in line.lower() for kw in ("detect", "log", "monitor", "alert", "indicator")):
                    indicators.append(line.strip()[:100])
            if indicators:
                result["indicators"] = indicators[:5]
        if "remediat" in prompt.lower():
            fixes = []
            for line in content.split("\n"):
                if any(kw in line.lower() for kw in ("fix", "patch", "mitigat", "remediat", "upgrad")):
                    fixes.append(line.strip()[:100])
            if fixes:
                result["immediate"] = fixes[:3]
        if "att&ck" in prompt.lower() or "ttp" in prompt.lower():
            tactics = _TACTIC_RE.findall(content)
            techniques = _TECHNIQUE_RE.findall(content)
            if tactics:
                result["tactics"] = list(set(tactics))
            if techniques:
                result["techniques"] = list(set(techniques))
        return json.dumps(result)

    def _parse_json_response(self, response: str) -> dict:
        """Parse a JSON response from the LLM, handling common formatting."""
        cleaned = response.strip()
        json_match = _JSON_RE.search(cleaned)
        if json_match:
            cleaned = json_match.group()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {"raw_response": response[:500], "confidence": 0.2}
