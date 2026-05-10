"""
╔══════════════════════════════════════════════════════════════╗
║  Cloud Security Intelligence Agent — Multi-Cloud Exposure   ║
║  AWS, Azure, GCP, Kubernetes, Docker, IAM, S3, CI/CD        ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.cloud_security")


@dataclass
class CloudAsset:
    """A discovered cloud asset."""
    asset_type: str        # s3_bucket, azure_blob, gcp_storage, k8s_api, ecr_repo, lambda_func
    identifier: str
    provider: str          # aws, azure, gcp, k8s, docker
    region: str = ""
    public: bool = False
    url: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudVulnerability:
    """Cloud-specific vulnerability finding."""
    vuln_type: str         # public_bucket, metadata_ssrf, iam_escalation, k8s_unauth, ci_exposure
    title: str
    provider: str
    asset: str
    severity: str = "high"
    confidence: float = 0.5
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""


@dataclass
class CloudSecurityReport:
    """Complete cloud security analysis report."""
    target: str
    assets: List[CloudAsset] = field(default_factory=list)
    vulnerabilities: List[CloudVulnerability] = field(default_factory=list)
    providers_detected: List[str] = field(default_factory=list)
    iam_findings: List[Dict[str, Any]] = field(default_factory=list)


# ──────────────────────────────────────────────
#  Cloud Detection Patterns
# ──────────────────────────────────────────────

AWS_PATTERNS = {
    "s3_bucket": [
        re.compile(r'([a-z0-9][-a-z0-9]{1,61}[a-z0-9])\.s3[.-](?:us|eu|ap|sa|ca|me|af|cn|il)[-\w]*\.amazonaws\.com'),
        re.compile(r's3[.-](?:us|eu|ap|sa|ca|me|af|cn|il)[-\w]*\.amazonaws\.com/([a-z0-9][-a-z0-9]{1,61}[a-z0-9])'),
        re.compile(r'arn:aws:s3:::([a-z0-9][-a-z0-9]{1,61}[a-z0-9])'),
    ],
    "access_key": [re.compile(r'AKIA[0-9A-Z]{16}')],
    "account_id": [re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):')],
    "lambda": [re.compile(r'(?:lambda\.(?:us|eu|ap)[-\w]+\.amazonaws\.com|arn:aws:lambda:)')],
    "ec2_metadata": [re.compile(r'169\.254\.169\.254')],
    "cognito": [re.compile(r'[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com')],
    "cloudfront": [re.compile(r'[a-z0-9]+\.cloudfront\.net')],
    "elasticbeanstalk": [re.compile(r'[a-z0-9-]+\.[a-z0-9-]+\.elasticbeanstalk\.com')],
}

AZURE_PATTERNS = {
    "blob_storage": [re.compile(r'([a-z0-9]{3,24})\.blob\.core\.windows\.net')],
    "app_service": [re.compile(r'[a-z0-9-]+\.azurewebsites\.net')],
    "key_vault": [re.compile(r'[a-z0-9-]+\.vault\.azure\.net')],
    "cosmos_db": [re.compile(r'[a-z0-9-]+\.documents\.azure\.com')],
    "function_app": [re.compile(r'[a-z0-9-]+\.azurewebsites\.net/api/')],
}

GCP_PATTERNS = {
    "storage": [re.compile(r'storage\.googleapis\.com/([a-z0-9][-a-z0-9_.]{1,61}[a-z0-9])')],
    "app_engine": [re.compile(r'[a-z0-9-]+\.appspot\.com')],
    "firebase": [re.compile(r'[a-z0-9-]+\.firebaseio\.com')],
    "cloud_function": [re.compile(r'[a-z0-9-]+\.cloudfunctions\.net')],
    "cloud_run": [re.compile(r'[a-z0-9-]+-[a-z0-9]+\.a\.run\.app')],
}

K8S_PATTERNS = {
    "api_server": [re.compile(r'(?:https?://[^/]+)?/api/v[1-9](?:/|$)')],
    "dashboard": [re.compile(r'/api/v1/namespaces/kubernetes-dashboard')],
    "etcd": [re.compile(r':2379|:2380')],
    "kubelet": [re.compile(r':10250/|:10255/')],
}

CI_CD_PATTERNS = {
    "github_actions": [re.compile(r'\.github/workflows|GITHUB_TOKEN|github\.run_id')],
    "gitlab_ci": [re.compile(r'\.gitlab-ci\.yml|CI_COMMIT|GITLAB_')],
    "jenkins": [re.compile(r'jenkins[/.]|JENKINS_|/job/[^/]+/build')],
    "circleci": [re.compile(r'circleci\.com|CIRCLE_')],
    "terraform": [re.compile(r'\.tfstate|terraform\.io|TF_VAR_')],
}

DOCKER_PATTERNS = {
    "registry": [re.compile(r'(?:docker\.io|ghcr\.io|[a-z0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com)/[a-z0-9_/-]+')],
    "compose": [re.compile(r'docker-compose\.ya?ml')],
    "socket": [re.compile(r'/var/run/docker\.sock')],
}


class CloudSecurityEngine:
    """
    Cloud Security Intelligence Agent.

    Capabilities:
      - AWS exposure discovery (S3, Lambda, EC2 metadata, Cognito, CloudFront)
      - Azure asset correlation (Blob, App Service, Key Vault, Cosmos DB)
      - GCP enumeration (Storage, App Engine, Firebase, Cloud Functions)
      - Kubernetes exposure analysis (API server, dashboard, etcd, kubelet)
      - Docker intelligence (registry, socket exposure)
      - CI/CD exposure analysis (GitHub Actions, GitLab CI, Jenkins, Terraform)
      - IAM relationship mapping
      - SSRF-to-metadata attack path detection
    """

    def __init__(self):
        self._assets: List[CloudAsset] = []
        self._vulnerabilities: List[CloudVulnerability] = []
        self._providers: Set[str] = set()

    def analyze_content(self, content: str, source: str = "") -> CloudSecurityReport:
        """Analyze text content for cloud exposures."""
        self._scan_aws(content, source)
        self._scan_azure(content, source)
        self._scan_gcp(content, source)
        self._scan_k8s(content, source)
        self._scan_docker(content, source)
        self._scan_cicd(content, source)

        return CloudSecurityReport(
            target=source,
            assets=self._assets.copy(),
            vulnerabilities=self._vulnerabilities.copy(),
            providers_detected=list(self._providers),
        )

    def analyze_headers(self, headers: Dict[str, str], url: str = "") -> List[CloudAsset]:
        """Detect cloud providers from HTTP headers."""
        assets = []
        header_str = json.dumps(headers).lower() if headers else ""
        import json

        # AWS
        if any(h in header_str for h in ["x-amz-", "amazons3", "cloudfront", "x-amzn-"]):
            self._providers.add("aws")
            assets.append(CloudAsset("aws_service", url, "aws", url=url))

        # Azure
        if any(h in header_str for h in ["x-ms-", "x-azure-", "azure"]):
            self._providers.add("azure")
            assets.append(CloudAsset("azure_service", url, "azure", url=url))

        # GCP
        if any(h in header_str for h in ["x-goog-", "x-cloud-", "google"]):
            self._providers.add("gcp")
            assets.append(CloudAsset("gcp_service", url, "gcp", url=url))

        # Cloudflare
        if "cf-ray" in header_str or "cloudflare" in header_str:
            assets.append(CloudAsset("cdn", url, "cloudflare", url=url))

        self._assets.extend(assets)
        return assets

    def check_metadata_ssrf(self, target: str) -> List[Dict[str, Any]]:
        """Generate SSRF-to-cloud-metadata test payloads."""
        payloads = [
            # AWS IMDSv1
            {"url": "http://169.254.169.254/latest/meta-data/", "provider": "aws", "desc": "AWS IMDS v1"},
            {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
             "provider": "aws", "desc": "AWS IAM credentials via IMDS"},
            # AWS IMDSv2 (requires token)
            {"url": "http://169.254.169.254/latest/api/token",
             "provider": "aws", "desc": "AWS IMDS v2 token", "method": "PUT",
             "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}},
            # Azure
            {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
             "provider": "azure", "desc": "Azure IMDS",
             "headers": {"Metadata": "true"}},
            # GCP
            {"url": "http://metadata.google.internal/computeMetadata/v1/",
             "provider": "gcp", "desc": "GCP metadata",
             "headers": {"Metadata-Flavor": "Google"}},
            # DigitalOcean
            {"url": "http://169.254.169.254/metadata/v1/",
             "provider": "digitalocean", "desc": "DigitalOcean metadata"},
            # Kubernetes
            {"url": "https://kubernetes.default.svc/api/v1/namespaces",
             "provider": "k8s", "desc": "Kubernetes API from pod"},
        ]
        return payloads

    def check_s3_permissions(self, bucket_name: str) -> List[Dict[str, str]]:
        """Generate S3 permission check test cases."""
        return [
            {"test": "list", "url": f"https://{bucket_name}.s3.amazonaws.com/?list-type=2",
             "desc": "List objects (public read)"},
            {"test": "acl", "url": f"https://{bucket_name}.s3.amazonaws.com/?acl",
             "desc": "Read ACL"},
            {"test": "put", "method": "PUT",
             "url": f"https://{bucket_name}.s3.amazonaws.com/thenothing-test.txt",
             "desc": "Write test (public write)"},
            {"test": "policy", "url": f"https://{bucket_name}.s3.amazonaws.com/?policy",
             "desc": "Read bucket policy"},
        ]

    def _scan_aws(self, content: str, source: str):
        for asset_type, patterns in AWS_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.findall(content):
                    self._providers.add("aws")
                    identifier = match if isinstance(match, str) else match[0]
                    asset = CloudAsset(asset_type, identifier, "aws", url=source)
                    self._assets.append(asset)

                    if asset_type == "s3_bucket":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="public_bucket",
                            title=f"S3 bucket discovered: {identifier}",
                            provider="aws", asset=identifier,
                            severity="medium", confidence=0.5,
                            remediation="Check bucket ACL and policy for public access",
                        ))
                    elif asset_type == "access_key":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="credential_exposure",
                            title=f"AWS access key exposed: {identifier}",
                            provider="aws", asset=identifier,
                            severity="critical", confidence=0.9,
                            cwe="CWE-798",
                            remediation="Rotate the key immediately via IAM console",
                        ))
                    elif asset_type == "ec2_metadata":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="metadata_ssrf",
                            title="EC2 metadata endpoint reference found",
                            provider="aws", asset="169.254.169.254",
                            severity="high", confidence=0.6,
                            remediation="Ensure IMDSv2 is enforced; test for SSRF",
                        ))

    def _scan_azure(self, content: str, source: str):
        for asset_type, patterns in AZURE_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.findall(content):
                    self._providers.add("azure")
                    identifier = match if isinstance(match, str) else match[0]
                    self._assets.append(CloudAsset(asset_type, identifier, "azure", url=source))

    def _scan_gcp(self, content: str, source: str):
        for asset_type, patterns in GCP_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.findall(content):
                    self._providers.add("gcp")
                    identifier = match if isinstance(match, str) else match[0]
                    self._assets.append(CloudAsset(asset_type, identifier, "gcp", url=source))

                    if asset_type == "firebase":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="firebase_exposure",
                            title=f"Firebase database found: {identifier}",
                            provider="gcp", asset=identifier,
                            severity="medium", confidence=0.5,
                            remediation="Check Firebase security rules for unauthenticated access",
                        ))

    def _scan_k8s(self, content: str, source: str):
        for asset_type, patterns in K8S_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    self._providers.add("kubernetes")
                    self._assets.append(CloudAsset(asset_type, source, "kubernetes", url=source))

                    if asset_type == "dashboard":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="k8s_unauth",
                            title="Kubernetes dashboard endpoint detected",
                            provider="kubernetes", asset=source,
                            severity="critical", confidence=0.6,
                            remediation="Ensure dashboard requires authentication",
                        ))
                    elif asset_type == "etcd":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="k8s_etcd_exposed",
                            title="etcd port exposed",
                            provider="kubernetes", asset=source,
                            severity="critical", confidence=0.7,
                            remediation="Restrict etcd access to control plane nodes only",
                        ))

    def _scan_docker(self, content: str, source: str):
        for asset_type, patterns in DOCKER_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    self._providers.add("docker")
                    self._assets.append(CloudAsset(asset_type, source, "docker", url=source))

                    if asset_type == "socket":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="docker_socket",
                            title="Docker socket exposure detected",
                            provider="docker", asset="/var/run/docker.sock",
                            severity="critical", confidence=0.8,
                            remediation="Never expose Docker socket to containers or external access",
                        ))

    def _scan_cicd(self, content: str, source: str):
        for platform, patterns in CI_CD_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    self._assets.append(CloudAsset("cicd", platform, "cicd", url=source))

                    if platform == "terraform":
                        self._vulnerabilities.append(CloudVulnerability(
                            vuln_type="ci_exposure",
                            title="Terraform state reference found — may contain secrets",
                            provider="cicd", asset=platform,
                            severity="high", confidence=0.5,
                            remediation="Ensure .tfstate files are not publicly accessible",
                        ))

    def generate_report(self, target: str) -> CloudSecurityReport:
        return CloudSecurityReport(
            target=target,
            assets=self._assets,
            vulnerabilities=self._vulnerabilities,
            providers_detected=list(self._providers),
        )
