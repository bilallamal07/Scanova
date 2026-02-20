# Skill Scanner Web Interface - Design Plan

## Overview
Transform the current skill-scanner dashboard into a clean, marketing-style interface similar to Playbooks' skill-scanner tool.

---

## Current State Analysis

### Your Project Architecture
- **Backend**: FastAPI server (`dashboard/backend/server.py`)
  - Endpoint: `POST /api/scan` - scans local folder paths
  - Returns: `ScanReport` with findings, metadata, score, verdict
  
- **Frontend**: React + Vite (`dashboard/frontend/`)
  - Current: Dashboard-style interface with stats, table, radar chart
  - Dark theme with glassmorphism effects
  
- **Scanner Engine**: Python-based
  - 6 security dimensions defined
  - Rule-based pattern matching
  - Severity scoring system

### Playbooks Interface Analysis
- **Type**: Marketing landing page with embedded tool
- **Key Sections**:
  1. Navigation header with logo
  2. Breadcrumb navigation
  3. Hero section (H1 + subtitle + input + CTA)
  4. Demo buttons ("view bad/good skill")
  5. "What we check" - 6 numbered dimensions
  6. "How it works" - 3-step process
  7. Footer with branding

---

## Target Interface Design

### 1. Navigation Header
```
┌─────────────────────────────────────────────────────────┐
│  🛡️ SKILL-SCANNER    HOME • DOCS • GITHUB              │
└─────────────────────────────────────────────────────────┘
```
- Clean, minimal header
- Logo + brand name left
- Navigation links right
- Fixed position on scroll

### 2. Hero Section (Landing State)
```
┌─────────────────────────────────────────────────────────┐
│  home / tools / skill scanner                           │
│                                                         │
│  # Skill Security Scanner                               │
│  Check any skill for hidden security risks before you   │
│  install it. Instant audit, zero setup.                 │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ https://github.com/owner/repo/...     [SCAN]   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Paste a link to any skill folder or SKILL.md on        │
│  GitHub and we'll check it for security risks.          │
│                                                         │
│  [view a bad skill]  [view a good skill]                │
└─────────────────────────────────────────────────────────┘
```

### 3. "What We Check" Section
```
┌─────────────────────────────────────────────────────────┐
│  ## What we check                                       │
│  Every scan runs the skill files through six security   │
│  dimensions, looking for patterns that could indicate   │
│  malicious or risky behavior.                           │
│                                                         │
│  01  Remote execution     02  Data exfiltration        │
│      Download & execute        Send data externally     │
│      remote code                                              │
│                                                         │
│  03  Secret access        04  Persistence              │
│      API tokens &              Survive restarts         │
│      credentials                                        │
│                                                         │
│  05  Destructive ops      06  Obfuscation              │
│      Data loss risks           Hidden payloads          │
└─────────────────────────────────────────────────────────┘
```

### 4. "How It Works" Section
```
┌─────────────────────────────────────────────────────────┐
│  ## How it works                                        │
│  Paste any GitHub link and get a full security audit    │
│  in seconds.                                            │
│                                                         │
│  01 Fetch source    02 Run analysis    03 Get report   │
│     Pull files         Pattern scan       Score +       │
│                        against 6          findings      │
│                        dimensions                       │
└─────────────────────────────────────────────────────────┘
```

### 5. Results View (After Scan)
```
┌─────────────────────────────────────────────────────────┐
│  Scan Results                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Safety Score: 85%  │ Files: 12  │ Findings: 3   │   │
│  │ Verdict: WARNING   │ Duration: 245ms            │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  [Radar Chart - Dimension Analysis]                     │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Findings Table                                  │   │
│  │ Rule          Dimension    Severity   Location  │   │
│  │ ──────────────────────────────────────────────  │   │
│  │ Shell exec    remote_exec  HIGH       main.py:5 │   │
│  │ ...                                             │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  [Scan Another Skill]                                   │
└─────────────────────────────────────────────────────────┘
```

---

## Technical Implementation Plan

### Phase 1: Enhanced Backend API

#### New Endpoints Needed

1. **`POST /api/scan/github`**
   ```python
   class GitHubScanRequest(BaseModel):
       url: str  # GitHub URL to skill folder or SKILL.md
   
   # Returns same ScanReport structure
   ```
   - Parse GitHub URLs
   - Fetch raw files via GitHub API
   - Save to temp directory
   - Run existing scan logic
   - Cleanup temp files

2. **`GET /api/dimensions`**
   ```python
   # Returns dimension descriptions for frontend
   [
     {
       "id": "remote_execution",
       "number": "01",
       "title": "Remote execution",
       "description": "Detects patterns that download and execute remote code without verification."
     },
     ...
   ]
   ```

3. **`GET /api/demo/{type}`** 
   ```python
   # type: "bad" | "good"
   # Returns pre-scanned results for demo purposes
   ```

#### Implementation Details
```python
# New file: dashboard/backend/github_scanner.py
import re
import tempfile
import requests
from pathlib import Path

def parse_github_url(url: str) -> tuple[str, str, str, str]:
    """Extract owner, repo, branch, path from GitHub URL."""
    # Support formats:
    # - https://github.com/owner/repo/tree/branch/path
    # - https://github.com/owner/repo/blob/branch/path
    # - https://github.com/owner/repo/path (defaults to main/master)
    pass

def fetch_github_files(owner: str, repo: str, branch: str, path: str) -> Path:
    """Download files to temp directory."""
    # Use GitHub API or raw content URLs
    # Return temp directory path
    pass

def scan_github_url(url: str) -> ScanReport:
    """Main entry point for GitHub URL scanning."""
    owner, repo, branch, path = parse_github_url(url)
    temp_dir = fetch_github_files(owner, repo, branch, path)
    try:
        return scan_folder(temp_dir)
    finally:
        cleanup(temp_dir)
```

### Phase 2: Frontend Redesign

#### New Component Structure
```
dashboard/frontend/src/
├── components/
│   ├── Header.jsx           # Navigation header
│   ├── HeroSection.jsx      # Input area + CTA
│   ├── DimensionsSection.jsx # "What we check" grid
│   ├── HowItWorksSection.jsx # 3-step process
│   ├── ScanResults.jsx      # Results view (existing dashboard)
│   ├── Footer.jsx           # Footer with branding
│   └── ui/                  # Reusable UI components
│       ├── Button.jsx
│       ├── Input.jsx
│       ├── Card.jsx
│       └── SeverityBadge.jsx
├── pages/
│   ├── LandingPage.jsx      # Hero + dimensions + how it works
│   └── ResultsPage.jsx      # Full results view
├── hooks/
│   └── useScan.js           # Scan logic hook
├── services/
│   └── api.js               # API calls
└── App.jsx                  # Router + layout
```

#### Key Features

1. **Two-View Architecture**
   - **Landing View**: Marketing page with scanner input
   - **Results View**: Full dashboard with findings
   - Smooth transition between views

2. **Interactive Elements**
   - Input validation with visual feedback
   - Loading states during scan
   - Demo buttons with pre-configured URLs
   - Scroll animations for sections

3. **Responsive Design**
   - Mobile-first approach
   - Grid layouts for dimension cards
   - Collapsible sections on mobile

### Phase 3: Styling System

#### Color Palette (Light Theme like Playbooks)
```css
:root {
  /* Primary */
  --color-primary: #2563eb;
  --color-primary-hover: #1d4ed8;
  
  /* Background */
  --color-bg: #ffffff;
  --color-bg-secondary: #f8fafc;
  --color-bg-tertiary: #f1f5f9;
  
  /* Text */
  --color-text: #0f172a;
  --color-text-secondary: #64748b;
  --color-text-muted: #94a3b8;
  
  /* Severity Colors */
  --color-info: #3b82f6;
  --color-low: #22c55e;
  --color-medium: #eab308;
  --color-high: #f97316;
  --color-critical: #ef4444;
  
  /* Borders */
  --color-border: #e2e8f0;
  --color-border-light: #f1f5f9;
}
```

#### Typography
- **Headings**: Inter or system-ui, font-weight 700
- **Body**: Inter or system-ui, font-weight 400
- **Code**: JetBrains Mono or monospace

#### Spacing System
```css
--space-1: 0.25rem;   /* 4px */
--space-2: 0.5rem;    /* 8px */
--space-3: 0.75rem;   /* 12px */
--space-4: 1rem;      /* 16px */
--space-6: 1.5rem;    /* 24px */
--space-8: 2rem;      /* 32px */
--space-12: 3rem;     /* 48px */
--space-16: 4rem;     /* 64px */
--space-20: 5rem;     /* 80px */
--space-24: 6rem;     /* 96px */
```

### Phase 4: Animation & Interactions

#### Scroll Animations
```javascript
// Fade in sections on scroll
const sections = document.querySelectorAll('section');
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('animate-in');
    }
  });
}, { threshold: 0.1 });
```

#### Input Interactions
- Focus state: Border color change + subtle shadow
- Valid URL: Green checkmark indicator
- Invalid URL: Red error message
- Loading: Spinner in button

#### Results Transition
- Smooth page transition
- Staggered card animations
- Number counting animation for stats

---

## Implementation Phases

### Phase 1: Foundation (Week 1)
- [ ] Create `tasks/todo.md` with detailed tasks
- [ ] Set up new component structure
- [ ] Implement GitHub URL parsing
- [ ] Add new API endpoint `/api/scan/github`
- [ ] Create demo endpoints

### Phase 2: Landing Page (Week 1-2)
- [ ] Build Header component
- [ ] Build HeroSection with input
- [ ] Build DimensionsSection with 6 cards
- [ ] Build HowItWorksSection with 3 steps
- [ ] Build Footer component
- [ ] Implement light theme styling
- [ ] Add responsive layouts

### Phase 3: Results Integration (Week 2)
- [ ] Refactor existing Dashboard into ScanResults component
- [ ] Update styling to match new design system
- [ ] Add view routing (Landing → Results)
- [ ] Implement smooth transitions
- [ ] Add loading states

### Phase 4: Polish (Week 3)
- [ ] Add scroll animations
- [ ] Implement demo buttons
- [ ] Add input validation
- [ ] Mobile responsiveness testing
- [ ] Performance optimization
- [ ] Error handling improvements

---

## API Contract

### `POST /api/scan/github`
**Request:**
```json
{
  "url": "https://github.com/anthropics/claude-skills/tree/main/skills/web-search"
}
```

**Response:** (Same as current ScanReport)
```json
{
  "findings": [...],
  "metadata": {
    "scanned_path": "temp/github/...",
    "files_scanned": 12,
    "duration_ms": 245.5
  },
  "score": 15,
  "verdict": "LOW_RISK"
}
```

### `GET /api/dimensions`
**Response:**
```json
[
  {
    "id": "remote_execution",
    "number": "01",
    "title": "Remote execution",
    "short_description": "Download & execute remote code",
    "full_description": "Detects patterns that download and execute remote code without verification."
  },
  ...
]
```

### `GET /api/demo/{type}`
**Response:** Pre-computed ScanReport

---

## Demo URLs

### Bad Skill (High Risk)
Use existing malicious fixture or create synthetic scan results showing:
- Remote execution patterns
- Secret access attempts
- High severity findings

### Good Skill (Clean)
Use existing clean fixture showing:
- Zero findings
- CLEAN verdict
- 100% safety score

---

## Success Metrics

1. **Functionality**
   - Can scan GitHub URLs
   - Demo buttons work
   - Results display correctly
   - Mobile responsive

2. **Performance**
   - Page load < 2s
   - Scan results < 5s
   - Smooth animations (60fps)

3. **Design Match**
   - Matches Playbooks layout structure
   - Consistent spacing/typography
   - Professional appearance

---

## Notes

- Keep existing dark theme as optional toggle
- Maintain backward compatibility with local path scanning
- Consider rate limiting for GitHub API calls
- Add caching for repeated GitHub URL scans
- Document GitHub API token setup for higher rate limits
