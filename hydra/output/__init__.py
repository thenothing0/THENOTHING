"""
Persistent Artifact Output System — ALL outputs saved automatically.

Structure: output/<target>/recon|scans|reports|attack_graph|evidence|logs|memory/
Timestamps all files. Preserves reproducibility.
"""

import json, logging, time, hashlib
from typing import Any, Dict, Optional
from pathlib import Path

logger = logging.getLogger("hydra.output")

SUBDIRS = ["recon", "scans", "reports", "attack_graph", "evidence", "logs", "memory"]


class ArtifactStore:
    """
    Manages all scan output artifacts with structured directories.
    Every tool output, finding, evidence artifact is persisted automatically.
    """

    def __init__(self, base_dir: str = "output"):
        self.base_dir = Path(base_dir)
        self._target_dirs: Dict[str, Path] = {}

    def initialize_target(self, target: str, scan_id: str = "") -> Path:
        safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        target_dir = self.base_dir / safe_name
        if scan_id:
            target_dir = target_dir / scan_id
        for sub in SUBDIRS:
            (target_dir / sub).mkdir(parents=True, exist_ok=True)
        self._target_dirs[target] = target_dir
        logger.info(f"📁 Output dir initialized: {target_dir}")
        return target_dir

    def get_target_dir(self, target: str) -> Path:
        if target not in self._target_dirs:
            return self.initialize_target(target)
        return self._target_dirs[target]

    def _ts(self) -> str:
        return time.strftime("%Y%m%dT%H%M%S")

    def save_raw_output(self, target: str, category: str, tool_name: str,
                        content: str, ext: str = "txt") -> Path:
        d = self.get_target_dir(target) / category
        d.mkdir(parents=True, exist_ok=True)
        filename = f"{tool_name}_{self._ts()}.{ext}"
        path = d / filename
        path.write_text(content, encoding="utf-8")
        logger.debug(f"💾 Raw output saved: {path}")
        return path

    def save_parsed_output(self, target: str, category: str, tool_name: str,
                           data: Any) -> Path:
        d = self.get_target_dir(target) / category
        d.mkdir(parents=True, exist_ok=True)
        filename = f"{tool_name}_{self._ts()}_parsed.json"
        path = d / filename
        path.write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        return path

    def save_evidence(self, target: str, finding_id: str, evidence_type: str,
                      content: str, metadata: Optional[Dict] = None) -> Path:
        d = self.get_target_dir(target) / "evidence" / finding_id
        d.mkdir(parents=True, exist_ok=True)
        filename = f"{evidence_type}_{self._ts()}.json"
        path = d / filename
        artifact = {"type": evidence_type, "content": content,
                    "metadata": metadata or {}, "timestamp": time.time(),
                    "content_hash": hashlib.sha256(content.encode()).hexdigest()}
        path.write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
        return path

    def save_http_evidence(self, target: str, finding_id: str,
                           method: str, url: str, status: int,
                           request_headers: Dict = None, request_body: str = "",
                           response_headers: Dict = None, response_body: str = "") -> Path:
        d = self.get_target_dir(target) / "evidence" / finding_id
        d.mkdir(parents=True, exist_ok=True)
        filename = f"http_replay_{self._ts()}.json"
        path = d / filename
        artifact = {
            "type": "http_evidence", "timestamp": time.time(),
            "request": {"method": method, "url": url, "headers": request_headers or {}, "body": request_body},
            "response": {"status": status, "headers": response_headers or {},
                        "body": response_body[:10000]},
            "reproducible": True,
        }
        path.write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
        return path

    def save_screenshot(self, target: str, finding_id: str,
                        image_data: bytes, label: str = "screenshot") -> Path:
        d = self.get_target_dir(target) / "evidence" / finding_id
        d.mkdir(parents=True, exist_ok=True)
        filename = f"{label}_{self._ts()}.png"
        path = d / filename
        path.write_bytes(image_data)
        return path

    def save_attack_graph(self, target: str, graph_data: Dict, fmt: str = "json") -> Path:
        d = self.get_target_dir(target) / "attack_graph"
        d.mkdir(parents=True, exist_ok=True)
        filename = f"attack_graph_{self._ts()}.{fmt}"
        path = d / filename
        if fmt == "json":
            path.write_text(json.dumps(graph_data, indent=2, default=str), encoding="utf-8")
        else:
            path.write_text(str(graph_data), encoding="utf-8")
        return path

    def save_report(self, target: str, report_data: Any, fmt: str = "json",
                    name: str = "report") -> Path:
        d = self.get_target_dir(target) / "reports"
        d.mkdir(parents=True, exist_ok=True)
        filename = f"{name}_{self._ts()}.{fmt}"
        path = d / filename
        if fmt == "json":
            path.write_text(json.dumps(report_data, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        else:
            path.write_text(str(report_data), encoding="utf-8")
        return path

    def save_memory_snapshot(self, target: str, memory_data: Dict) -> Path:
        d = self.get_target_dir(target) / "memory"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"memory_{self._ts()}.json"
        path.write_text(json.dumps(memory_data, indent=2, default=str), encoding="utf-8")
        return path

    def save_log(self, target: str, log_content: str, label: str = "scan") -> Path:
        d = self.get_target_dir(target) / "logs"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{label}_{self._ts()}.log"
        path.write_text(log_content, encoding="utf-8")
        return path

    def list_artifacts(self, target: str, category: str = None) -> Dict[str, list]:
        td = self.get_target_dir(target)
        result = {}
        cats = [category] if category else SUBDIRS
        for cat in cats:
            cat_dir = td / cat
            if cat_dir.exists():
                result[cat] = sorted([str(f.name) for f in cat_dir.rglob("*") if f.is_file()])
        return result

    def get_evidence_for_finding(self, target: str, finding_id: str) -> list:
        d = self.get_target_dir(target) / "evidence" / finding_id
        if not d.exists(): return []
        artifacts = []
        for f in sorted(d.iterdir()):
            if f.is_file() and f.suffix == ".json":
                try:
                    artifacts.append(json.loads(f.read_text(encoding="utf-8")))
                except Exception:
                    artifacts.append({"file": str(f.name), "error": "parse_failed"})
        return artifacts
