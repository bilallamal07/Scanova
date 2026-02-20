from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from pathlib import Path
from typing import List, Literal, Optional
import asyncio
import base64
import json
import os
import tempfile

import httpx

from skill_scanner.scanner import scan_folder
from skill_scanner.models import ScanReport
from skill_scanner.browser_scanner import (
    BrowserTabScanner,
    BrowserFileAccessError,
    LocalDirectoryBrowser,
    DragDropFileHandler,
    FileUrlParser,
)

# Load .env file if present
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"
OLLAMA_BASE = os.environ.get("OLLAMA_BASE", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

app = FastAPI(title="Skill Scanner API")

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    path: str


class FileUrlScanRequest(BaseModel):
    url: str


class DirectoryListRequest(BaseModel):
    path: str
    pattern: str = "*"
    include_hidden: bool = False


class FileUploadRequest(BaseModel):
    files: List[dict]


class UrlScanRequest(BaseModel):
    url: str


@app.get("/")
async def root():
    return {"message": "Skill Scanner API is running"}


@app.post("/api/scan")
async def perform_scan(request: ScanRequest):
    """Scan a local directory path."""
    target_path = Path(request.path)

    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")

    if not target_path.is_dir():
        raise HTTPException(status_code=400, detail="Path must be a directory")

    try:
        report = scan_folder(target_path)
        return report.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/file-url")
async def scan_file_url(request: FileUrlScanRequest):
    """Scan a file:// URL or local path.

    Supports:
    - file:///path/to/file
    - file:///C:/path/to/file (Windows)
    - /absolute/path (Unix)
    - C:\\path\\to\\file (Windows)
    - ~/home/path
    - ./relative/path
    """
    scanner = BrowserTabScanner()

    try:
        report = scanner.scan_file_url(request.url)
        return report.model_dump()
    except BrowserFileAccessError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/parse-file-url")
async def parse_file_url(request: FileUrlScanRequest):
    """Parse and validate a file URL or local path without scanning.

    Returns information about the path without performing a scan.
    """
    parser = FileUrlParser()
    result = parser.parse_file_url(request.url)
    return result


@app.post("/api/directory/list")
async def list_directory(request: DirectoryListRequest):
    """List contents of a directory.

    Browse local file system from browser context.
    """
    browser = LocalDirectoryBrowser()

    try:
        items = browser.list_directory(
            path=request.path, pattern=request.pattern, include_hidden=request.include_hidden
        )
        return {"path": request.path, "items": items, "count": len(items)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/directory/tree")
async def get_directory_tree(request: DirectoryListRequest):
    """Get directory tree structure.

    Returns hierarchical tree for file browser UI.
    """
    browser = LocalDirectoryBrowser(request.path)

    try:
        tree = browser.get_directory_tree(max_depth=3)
        return tree
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/directory/find-skills")
async def find_skills(request: DirectoryListRequest):
    """Find potential skill files in a directory.

    Searches for SKILL.md, skill.yaml, and skills/ directories.
    """
    browser = LocalDirectoryBrowser(request.path)

    try:
        skills = browser.find_skill_files(max_depth=3)
        return {"path": request.path, "skills": skills, "count": len(skills)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scan/upload")
async def scan_uploaded_files(request: FileUploadRequest):
    """Scan files uploaded from browser.

    Accepts base64 encoded file content for drag-and-drop or file picker uploads.
    """
    handler = DragDropFileHandler()

    try:
        report = handler.scan_uploaded_files(request.files)
        return report.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        handler.cleanup()


@app.get("/api/browser/locations")
async def get_browser_locations():
    """Get common browser-accessible locations.

    Returns paths that browsers typically have access to.
    """
    locations = {
        "home": str(Path.home()),
        "cwd": str(Path.cwd()),
        "temp": str(Path(tempfile.gettempdir())),
    }

    # Add platform-specific locations
    if os.name == "posix":
        locations["downloads"] = str(Path.home() / "Downloads")
        locations["documents"] = str(Path.home() / "Documents")
    elif os.name == "nt":
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            ) as key:
                locations["downloads"] = winreg.QueryValueEx(
                    key, "{374DE290-123F-4565-9164-39C4925E467B}"
                )[0]
                locations["documents"] = winreg.QueryValueEx(key, "Personal")[0]
        except:
            pass

    return locations


@app.post("/api/scan/url")
async def scan_url_virustotal(request: UrlScanRequest):
    """Scan a URL using the VirusTotal API.

    Submits a URL for analysis and returns detection results from 70+ engines.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="VIRUSTOTAL_API_KEY environment variable is not set",
        )

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    target_url = request.url.strip()

    async with httpx.AsyncClient(timeout=60.0) as client:
        # Try to get cached report first
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        try:
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results = attrs.get("last_analysis_results", {})
                return _format_vt_response(target_url, stats, results, attrs)
        except httpx.HTTPError:
            pass

        # No cached result — submit for scanning
        resp = await client.post(
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": target_url},
        )
        if resp.status_code not in (200, 201):
            detail = resp.text
            try:
                detail = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                pass
            raise HTTPException(status_code=resp.status_code, detail=detail)

        analysis_id = resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            raise HTTPException(status_code=500, detail="No analysis ID returned")

        # Poll for results (max ~30s)
        for _ in range(15):
            await asyncio.sleep(2)
            resp = await client.get(
                f"{VT_BASE}/analyses/{analysis_id}", headers=headers
            )
            if resp.status_code != 200:
                continue
            analysis = resp.json().get("data", {}).get("attributes", {})
            if analysis.get("status") == "completed":
                stats = analysis.get("stats", {})
                results = analysis.get("results", {})
                return _format_vt_response(target_url, stats, results, analysis)

        raise HTTPException(
            status_code=504, detail="VirusTotal analysis timed out"
        )


def _format_vt_response(url: str, stats: dict, results: dict, attrs: dict) -> dict:
    """Normalize VirusTotal response into a frontend-friendly format."""
    engine_results = []
    for engine, info in sorted(results.items()):
        engine_results.append({
            "engine": engine,
            "category": info.get("category", "undetected"),
            "result": info.get("result") or info.get("category", "clean"),
        })

    total = sum(stats.values())
    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)

    return {
        "type": "virustotal",
        "url": url,
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
        },
        "total_engines": total,
        "positives": positives,
        "scan_date": attrs.get("date", attrs.get("last_analysis_date", "")),
        "results": engine_results,
    }


class AISummaryRequest(BaseModel):
    type: Literal["local", "virustotal"]
    data: dict

    @field_validator("data")
    @classmethod
    def data_must_not_be_empty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("data must not be empty")
        return v


def _build_local_prompt(data: dict) -> str:
    score = data.get("score", 0)
    verdict = data.get("verdict", "unknown")
    findings = data.get("findings", [])
    metadata = data.get("metadata", {})

    findings_text = ""
    for f in findings[:30]:  # cap to avoid huge prompts
        sev = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(
            f.get("severity", 0), "UNKNOWN"
        )
        findings_text += (
            f"- [{sev}] {f.get('rule_name', '?')} in {f.get('file_path', '?')}:"
            f"{f.get('line_number', '?')} (dimension: {f.get('dimension', '?')})\n"
        )

    return f"""You are a security analyst reviewing an agent skill scan report.

## Scan Summary
- Safety Score: {100 - score}/100
- Verdict: {verdict}
- Files Scanned: {metadata.get('files_scanned', '?')}
- Total Findings: {len(findings)}

## Findings
{findings_text if findings_text else "No findings detected."}

Provide a concise security analysis with:
1. **Overview**: Plain-language summary of what was found
2. **Risk Assessment**: Overall risk level and key concerns
3. **Top Priorities**: The most important issues to address first
4. **Remediation Steps**: Specific, actionable fixes for the top findings

Keep the response focused and under 500 words. Use markdown formatting."""


def _build_vt_prompt(data: dict) -> str:
    url = data.get("url", "unknown")
    stats = data.get("stats", {})
    positives = data.get("positives", 0)
    total = data.get("total_engines", 0)

    flagged = [
        r for r in data.get("results", []) if r.get("category") in ("malicious", "suspicious")
    ]
    flagged_text = ""
    for r in flagged[:20]:
        flagged_text += f"- {r.get('engine', '?')}: {r.get('result', '?')} ({r.get('category', '?')})\n"

    return f"""You are a security analyst reviewing a VirusTotal URL scan report.

## Scan Summary
- URL: {url}
- Engines Flagged: {positives} / {total}
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Harmless: {stats.get('harmless', 0)}
- Undetected: {stats.get('undetected', 0)}

## Flagged Engines
{flagged_text if flagged_text else "No engines flagged this URL."}

Provide a concise security analysis with:
1. **Overview**: Plain-language summary of the scan results
2. **Risk Assessment**: How dangerous is this URL and why
3. **Recommendations**: What the user should do next

Keep the response focused and under 400 words. Use markdown formatting."""


@app.post("/api/ai/summary")
async def generate_ai_summary(request: AISummaryRequest):
    """Generate an AI-powered summary of scan results using a local Ollama LLM."""
    if request.type == "local":
        prompt = _build_local_prompt(request.data)
    else:
        prompt = _build_vt_prompt(request.data)

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            if resp.status_code != 200:
                detail = resp.text[:500]
                raise HTTPException(
                    status_code=502,
                    detail=f"Ollama returned {resp.status_code}: {detail}",
                )
            body = resp.json()
            return {"summary": body.get("response", "")}
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail="Cannot connect to Ollama. Make sure Ollama is running on "
            f"{OLLAMA_BASE} with the '{OLLAMA_MODEL}' model pulled.",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Ollama request timed out. The model may be loading or the prompt too large.",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
