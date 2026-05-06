# ════════════════════════════════════════════════
#  HYDRA — Windows Setup Script (PowerShell)
#  Run: powershell -ExecutionPolicy Bypass -File setup.ps1
# ════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

function Write-Banner {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  HYDRA — AI Bug Bounty Operating System                  ║" -ForegroundColor Cyan
    Write-Host "║  Windows Setup                                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[✓] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[✗] $msg" -ForegroundColor Red }

# ── Check Python ─────────────────────────────
function Test-Python {
    Write-Step "Checking Python..."
    try {
        $ver = python --version 2>&1
        Write-Ok "Python found: $ver"
        return $true
    } catch {
        Write-Err "Python not found. Install Python 3.10+ from python.org"
        return $false
    }
}

# ── Check Go ─────────────────────────────────
function Test-Go {
    Write-Step "Checking Go..."
    try {
        $ver = go version 2>&1
        Write-Ok "Go found: $ver"
        return $true
    } catch {
        Write-Warn "Go not found. Install from https://go.dev/dl/"
        Write-Warn "Go is needed for: subfinder, httpx, nuclei, ffuf, katana, gau, amass"
        return $false
    }
}

# ── Install Python dependencies ──────────────
function Install-PythonDeps {
    Write-Step "Installing Python dependencies..."
    pip install -r requirements.txt --quiet 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Python dependencies installed"
    } else {
        Write-Warn "Some Python deps may have failed — check manually"
    }
}

# ── Install MCP SDK ──────────────────────────
function Install-MCP {
    Write-Step "Installing MCP SDK for Claude Code..."
    pip install "mcp[cli]" --quiet 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "MCP SDK installed"
    } else {
        Write-Warn "MCP install failed — run: pip install 'mcp[cli]'"
    }
}

# ── Install Go tools ────────────────────────
function Install-GoTools {
    if (-not (Test-Go)) {
        Write-Warn "Skipping Go tools (Go not installed)"
        return
    }

    $tools = @(
        @{Name="subfinder"; Pkg="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
        @{Name="httpx";     Pkg="github.com/projectdiscovery/httpx/cmd/httpx@latest"},
        @{Name="nuclei";    Pkg="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
        @{Name="katana";    Pkg="github.com/projectdiscovery/katana/cmd/katana@latest"},
        @{Name="ffuf";      Pkg="github.com/ffuf/ffuf/v2@latest"},
        @{Name="gau";       Pkg="github.com/lc/gau/v2/cmd/gau@latest"},
        @{Name="amass";     Pkg="github.com/owasp-amass/amass/v4/...@master"}
    )

    foreach ($tool in $tools) {
        $name = $tool.Name
        $existing = Get-Command $name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Ok "$name already installed"
        } else {
            Write-Step "Installing $name..."
            go install -v $tool.Pkg 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "$name installed"
            } else {
                Write-Warn "Failed to install $name"
            }
        }
    }

    # Update nuclei templates
    Write-Step "Updating Nuclei templates..."
    nuclei -update-templates 2>$null
    Write-Ok "Nuclei templates updated"
}

# ── Install pip-based security tools ─────────
function Install-PipTools {
    Write-Step "Installing pip-based security tools..."
    pip install wafw00f dirsearch --quiet 2>$null
    Write-Ok "pip security tools installed"
}

# ── Create directories ───────────────────────
function New-Directories {
    Write-Step "Creating data directories..."
    $dirs = @("data", "logs", "results", "reports", "wordlists")
    foreach ($d in $dirs) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
    Write-Ok "Directories created"
}

# ── Download wordlists ───────────────────────
function Get-Wordlists {
    $wl = "wordlists\common.txt"
    if (Test-Path $wl) {
        Write-Ok "Wordlists already present"
        return
    }
    Write-Step "Downloading wordlists..."
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" `
            -OutFile $wl -UseBasicParsing
        Write-Ok "Wordlists downloaded"
    } catch {
        Write-Warn "Wordlist download failed — add wordlists manually"
    }
}

# ── Setup .env ───────────────────────────────
function Set-EnvFile {
    if (-not (Test-Path ".env")) {
        if (Test-Path ".env.example") {
            Copy-Item ".env.example" ".env"
            Write-Ok ".env file created from template — edit it to add API keys"
        }
    } else {
        Write-Ok ".env already exists"
    }
}

# ── Verify tools ─────────────────────────────
function Test-Tools {
    Write-Host ""
    Write-Step "Verifying tool installation..."
    Write-Host "──────────────────────────────────────────"

    $tools = @("subfinder", "httpx", "nuclei", "ffuf", "amass", "katana", "gau", "nmap", "python")
    $ok = 0
    $fail = 0

    foreach ($tool in $tools) {
        $cmd = Get-Command $tool -ErrorAction SilentlyContinue
        if ($cmd) {
            Write-Ok "$tool — available ($($cmd.Source))"
            $ok++
        } else {
            Write-Err "$tool — NOT FOUND"
            $fail++
        }
    }

    Write-Host "──────────────────────────────────────────"
    Write-Ok "Results: $ok available, $fail missing"
}

# ── Main ─────────────────────────────────────
Write-Banner

if (-not (Test-Python)) {
    Write-Err "Python is required. Exiting."
    exit 1
}

Install-PythonDeps
Install-MCP
Install-GoTools
Install-PipTools
New-Directories
Get-Wordlists
Set-EnvFile
Test-Tools

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅ HYDRA setup complete!                                ║" -ForegroundColor Green
Write-Host "║                                                          ║" -ForegroundColor Green
Write-Host "║  Claude Code:  cd newpro && claude                       ║" -ForegroundColor Green
Write-Host "║  Standalone:   python -m hydra.main --target example.com ║" -ForegroundColor Green
Write-Host "║  Docker:       docker compose up                         ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
