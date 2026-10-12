import React, { useState, useEffect } from 'react';
import {
    Shield,
    Search,
    AlertTriangle,
    FileCode,
    Activity,
    ChevronLeft,
    ChevronDown,
    ChevronRight,
    FolderOpen,
    Upload,
    FileText,
    BarChart3,
    List,
    Globe,
    Sparkles,
    Download,
    Share2,
    Wifi,
    DatabaseZap,
    KeyRound,
    Timer,
    Trash2,
    EyeOff,
    Syringe,
    LayoutList
} from 'lucide-react';
import {
    Radar,
    RadarChart,
    PolarGrid,
    PolarAngleAxis,
    PolarRadiusAxis,
    PieChart,
    Pie,
    Cell,
    Tooltip,
    ResponsiveContainer,
} from 'recharts';
import FileBrowser from './components/FileBrowser';
import DragDropUploader from './components/DragDropUploader';
import { FileBrowserAPI, FileUtils } from './services/fileBrowser';

const API_BASE = "http://localhost:8000";

const SEVERITY_MAP = {
    0: "INFO",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL"
};

const DIMENSION_ICONS = {
    remote_execution: Wifi,
    exfiltration: DatabaseZap,
    secret_access: KeyRound,
    persistence: Timer,
    destructive_ops: Trash2,
    obfuscation: EyeOff,
    prompt_injection: Syringe,
};

const DIMENSIONS = [
    { key: 'remote_execution', title: 'Remote Execution', desc: 'Detects outbound calls, command execution, and code evaluation that could enable remote control.' },
    { key: 'exfiltration', title: 'Data Exfiltration', desc: 'Identifies patterns that could leak sensitive data through network requests or file operations.' },
    { key: 'secret_access', title: 'Secret Access', desc: 'Finds attempts to read credentials, API keys, tokens, and other sensitive configuration.' },
    { key: 'persistence', title: 'Persistence', desc: 'Detects modifications to startup files, cron jobs, and other mechanisms for maintaining access.' },
    { key: 'destructive_ops', title: 'Destructive Operations', desc: 'Flags file deletion, system modifications, and other potentially irreversible actions.' },
    { key: 'obfuscation', title: 'Obfuscation', desc: 'Identifies encoded payloads, dynamic code construction, and techniques to hide intent.' },
    { key: 'prompt_injection', title: 'Prompt Injection', desc: 'Detects instructions that try to override, hijack, or manipulate the agent\'s behavior.' },
];

const SEVERITY_COLORS = {
    CRITICAL: '#d9534f',
    HIGH: '#e88a1a',
    MEDIUM: '#f0ad4e',
    LOW: '#5cb85c',
    INFO: '#3498db',
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const DIMENSION_COLORS = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db', '#9b59b6', '#1abc9c'];

/* ── Pulsing Core Logo Component ── */
function ScanovaLogo({ size = 'large' }) {
    const isSmall = size === 'small';
    const iconSize = isSmall ? 32 : 120;
    const svgSize = isSmall ? 28 : 100;

    return (
        <div className={`scanova-logo scanova-logo--${size}`}>
            <div className="logo-icon-wrapper" style={{ width: iconSize, height: iconSize }}>
                {/* Nova Star (background pulse) */}
                <svg className="logo-nova-star" viewBox="0 0 100 100">
                    <path d="M50 0 L60 40 L100 50 L60 60 L50 100 L40 60 L0 50 L40 40 Z" />
                </svg>
                {/* Hexagon segments */}
                <svg className="logo-hex-svg" viewBox="0 0 100 115" style={{ width: svgSize, height: svgSize * 1.15 }}>
                    <line x1="25" y1="5" x2="5" y2="35" className="logo-hex-seg" />
                    <line x1="75" y1="5" x2="95" y2="35" className="logo-hex-seg" />
                    <line x1="95" y1="35" x2="95" y2="80" className="logo-hex-seg" />
                    <line x1="95" y1="80" x2="75" y2="110" className="logo-hex-seg" />
                    <line x1="25" y1="110" x2="5" y2="80" className="logo-hex-seg" />
                    <line x1="5" y1="80" x2="5" y2="35" className="logo-hex-seg" />
                </svg>
                {/* Scan line */}
                {!isSmall && <div className="logo-scan-line" />}
            </div>
            {!isSmall && (
                <div className="logo-wordmark">
                    <span className="logo-scan-part">SCAN</span>
                    <span className="logo-ova-part">OVA</span>
                </div>
            )}
        </div>
    );
}

export default function Dashboard() {
    const [path, setPath] = useState("");
    const [scanning, setScanning] = useState(false);
    const [report, setReport] = useState(null);
    const [error, setError] = useState(null);
    const [showFileBrowser, setShowFileBrowser] = useState(false);
    const [showDragDrop, setShowDragDrop] = useState(false);
    const [isFileUrl, setIsFileUrl] = useState(false);
    const [viewMode, setViewMode] = useState('simple');
    const [expandedDims, setExpandedDims] = useState({});
    const [urlInput, setUrlInput] = useState('');
    const [urlReport, setUrlReport] = useState(null);
    const [urlScanning, setUrlScanning] = useState(false);
    const [aiSummary, setAiSummary] = useState('');
    const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
    const [aiSummaryError, setAiSummaryError] = useState(null);
    const [showDocs, setShowDocs] = useState(false);
    const [activeDimension, setActiveDimension] = useState(null);
    const [expandedFindings, setExpandedFindings] = useState({});


    useEffect(() => {
        setIsFileUrl(FileUtils.isFileUrl(path));
    }, [path]);

    const handleScan = async () => {
        setScanning(true);
        setError(null);
        setViewMode('simple');
        try {
            let data;
            if (isFileUrl || path.startsWith('file://')) {
                data = await FileBrowserAPI.scanFileUrl(path);
            } else {
                const res = await fetch(`${API_BASE}/api/scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path })
                });
                if (!res.ok) throw new Error(await res.text());
                data = await res.json();
            }
            setReport(data);
            // Auto-expand dimensions that have findings
            const expanded = {};
            DIMENSIONS.forEach(d => {
                const count = data.findings.filter(f => f.dimension === d.key).length;
                if (count > 0) expanded[d.key] = true;
            });
            setExpandedDims(expanded);
        } catch (err) {
            setError(err.message);
        } finally {
            setScanning(false);
        }
    };

    const handleFileBrowserSelect = (selectedPath) => {
        setPath(selectedPath);
        setShowFileBrowser(false);
    };

    const handleFileBrowserScan = async (selectedPath) => {
        setPath(selectedPath);
        setShowFileBrowser(false);
    };

    const handleDragDropComplete = (scanReport) => {
        setReport(scanReport);
        setShowDragDrop(false);
    };

    const handleBack = () => {
        setReport(null);
        setUrlReport(null);
        setError(null);
        setAiSummary('');
        setAiSummaryError(null);
        setActiveDimension(null);
        setExpandedFindings({});
    };

    const handleUrlScan = async () => {
        if (!urlInput.trim()) return;
        setUrlScanning(true);
        setError(null);
        setUrlReport(null);
        setViewMode('simple');
        try {
            const res = await fetch(`${API_BASE}/api/scan/url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlInput.trim() })
            });
            if (!res.ok) {
                const errText = await res.text();
                let msg = errText;
                try { msg = JSON.parse(errText).detail || errText; } catch {}
                throw new Error(msg);
            }
            const data = await res.json();
            setUrlReport(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setUrlScanning(false);
        }
    };

    const handleGenerateAISummary = async (type, data) => {
        setAiSummaryLoading(true);
        setAiSummaryError(null);
        setAiSummary('');
        try {
            const res = await fetch(`${API_BASE}/api/ai/summary`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type, data })
            });
            if (!res.ok) {
                const errText = await res.text();
                let msg = errText;
                try { msg = JSON.parse(errText).detail || errText; } catch {}
                throw new Error(msg);
            }
            const result = await res.json();
            setAiSummary(result.summary);
        } catch (err) {
            setAiSummaryError(err.message);
        } finally {
            setAiSummaryLoading(false);
        }
    };

    const toggleDimension = (key) => {
        setExpandedDims(prev => ({ ...prev, [key]: !prev[key] }));
    };

    const toggleFinding = (findingKey) => {
        setExpandedFindings(prev => ({ ...prev, [findingKey]: !prev[findingKey] }));
    };

    const getFindingKey = (f, i) => `${f.dimension}-${f.rule_name}-${f.file_path}-${f.line_number}-${i}`;

    const getSeverityBlock = (severity) => {
        const sev = SEVERITY_MAP[severity];
        const colors = {
            CRITICAL: '#d9534f', HIGH: '#e88a1a', MEDIUM: '#f0ad4e', LOW: '#5cb85c', INFO: '#3498db'
        };
        return { label: sev, color: colors[sev] || '#555' };
    };

    const getRadarData = () => {
        if (!report) return [];
        const dims = {
            remote_execution: 0,
            exfiltration: 0,
            secret_access: 0,
            persistence: 0,
            destructive_ops: 0,
            obfuscation: 0,
            prompt_injection: 0
        };
        report.findings.forEach(f => {
            dims[f.dimension] += f.severity + 1;
        });
        return Object.keys(dims).map(key => ({
            subject: key.replace(/_/g, ' '),
            A: dims[key],
            fullMark: 10
        }));
    };

    const getGroupedFindings = () => {
        if (!report) return {};
        const grouped = {};
        DIMENSIONS.forEach(d => {
            grouped[d.key] = report.findings.filter(f => f.dimension === d.key);
        });
        return grouped;
    };

    const getSeverityCounts = () => {
        if (!report) return {};
        const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        report.findings.forEach(f => {
            const sev = SEVERITY_MAP[f.severity];
            if (sev in counts) counts[sev]++;
        });
        return counts;
    };

    const getSeverityChartData = () => {
        const counts = getSeverityCounts();
        return SEVERITY_ORDER
            .filter(s => counts[s] > 0)
            .map(s => ({ name: s, value: counts[s], color: SEVERITY_COLORS[s] }));
    };

    const getDimensionChartData = () => {
        if (!report) return [];
        const counts = {};
        DIMENSIONS.forEach(d => { counts[d.key] = 0; });
        report.findings.forEach(f => { counts[f.dimension]++; });
        return DIMENSIONS
            .filter((d, i) => counts[d.key] > 0)
            .map((d, i) => ({ name: d.title, value: counts[d.key], color: DIMENSION_COLORS[DIMENSIONS.indexOf(d)] }));
    };

    const getSafetyScoreData = () => {
        const score = report ? 100 - report.score : 100;
        return [
            { name: 'Safe', value: score, color: '#5cb85c' },
            { name: 'Risk', value: 100 - score, color: '#d9534f' },
        ];
    };

    const getTopFindings = () => {
        if (!report) return [];
        const map = {};
        report.findings.forEach(f => {
            const key = f.rule_name;
            if (!map[key]) {
                map[key] = { rule_name: f.rule_name, severity: f.severity, count: 0 };
            }
            map[key].count++;
            if (f.severity > map[key].severity) map[key].severity = f.severity;
        });
        return Object.values(map)
            .sort((a, b) => b.severity - a.severity || b.count - a.count)
            .slice(0, 10);
    };

    const safetyScore = report ? 100 - report.score : 0;

    const scanTimestamp = new Date().toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: 'numeric', minute: '2-digit', hour12: true
    });

    const projectName = path ? path.split('/').filter(Boolean).pop() || 'Scan' : 'Scan';

    const getAgentEnv = () => {
        if (!report || !report.metadata) return null;
        const m = report.metadata;
        const parts = [];
        if (m.language) parts.push(m.language);
        if (m.framework) parts.push(m.framework);
        return parts.length > 0 ? parts.join(' / ') : null;
    };

    // ==================== MODALS ====================
    const modals = (
        <>
            {showDocs && (
                <div className="modal-overlay" onClick={() => setShowDocs(false)}>
                    <div className="modal-content docs-modal" onClick={e => e.stopPropagation()}>
                        <div className="docs-header">
                            <span className="docs-title">Scanova Docs</span>
                            <span className="docs-close" onClick={() => setShowDocs(false)}>&times;</span>
                        </div>
                        <div className="docs-body">
                            <p className="docs-intro">
                                Scanova is an open-source security analysis platform for agentic architectures.
                                It performs structured seven-dimensional risk assessment across all agents and external
                                dependencies, detecting remote code execution paths, data exfiltration vectors,
                                credential exposure, privilege abuse, and integration vulnerabilities before deployment.
                            </p>

                            <h3>Getting Started</h3>
                            <div className="docs-steps">
                                <div className="docs-step">
                                    <span className="docs-step-num">1</span>
                                    <div>
                                        <strong>Local Scan</strong>
                                        <p>Enter a directory path and click <strong>Scan</strong>. Scanova analyzes all skill files in the folder.</p>
                                    </div>
                                </div>
                                <div className="docs-step">
                                    <span className="docs-step-num">2</span>
                                    <div>
                                        <strong>URL Scan</strong>
                                        <p>Paste a URL in the VirusTotal section and click <strong>Scan URL</strong>. Results come from 70+ security engines.</p>
                                    </div>
                                </div>
                                <div className="docs-step">
                                    <span className="docs-step-num">3</span>
                                    <div>
                                        <strong>Review Results</strong>
                                        <p>Findings are grouped by dimension with severity ratings. Switch between Simple and Detailed views.</p>
                                    </div>
                                </div>
                                <div className="docs-step">
                                    <span className="docs-step-num">4</span>
                                    <div>
                                        <strong>AI Summary</strong>
                                        <p>Click <strong>Generate AI Summary</strong> for a plain-language risk assessment and prioritized remediation steps. Requires Ollama running locally.</p>
                                    </div>
                                </div>
                            </div>

                            <h3>Seven Dimensions</h3>
                            <div className="docs-dimensions">
                                {DIMENSIONS.map((d, i) => (
                                    <div key={d.key} className="docs-dim-item">
                                        <span className="docs-dim-num">{String(i + 1).padStart(2, '0')}</span>
                                        <strong>{d.title}</strong> &mdash; {d.desc}
                                    </div>
                                ))}
                            </div>

                            <h3>Severity Levels</h3>
                            <div className="docs-severity-list">
                                <span className="severity-pill severity-critical">CRITICAL</span>
                                <span className="severity-pill severity-high">HIGH</span>
                                <span className="severity-pill severity-medium">MEDIUM</span>
                                <span className="severity-pill severity-low">LOW</span>
                                <span className="severity-pill severity-info">INFO</span>
                            </div>
                            <p>Findings range from informational patterns to critical vulnerabilities requiring immediate attention.</p>
                        </div>
                    </div>
                </div>
            )}
            {showFileBrowser && (
                <div className="modal-overlay" onClick={() => setShowFileBrowser(false)}>
                    <div className="modal-content" onClick={e => e.stopPropagation()}>
                        <FileBrowser
                            initialPath={path || "/"}
                            onSelect={(item) => handleFileBrowserSelect(item.path)}
                            onScan={handleFileBrowserScan}
                            onClose={() => setShowFileBrowser(false)}
                        />
                    </div>
                </div>
            )}
            {showDragDrop && (
                <div className="modal-overlay" onClick={() => setShowDragDrop(false)}>
                    <div className="modal-content" onClick={e => e.stopPropagation()}>
                        <DragDropUploader
                            onScanComplete={handleDragDropComplete}
                            onClose={() => setShowDragDrop(false)}
                        />
                    </div>
                </div>
            )}
        </>
    );

    // ==================== VIRUSTOTAL RESULTS VIEW ====================
    if (urlReport) {
        const vt = urlReport;
        const vtCategories = [
            { key: 'malicious', label: 'CRITICAL', cls: 'sev-critical' },
            { key: 'suspicious', label: 'HIGH', cls: 'sev-high' },
            { key: 'harmless', label: 'MEDIUM', cls: 'sev-medium' },
            { key: 'undetected', label: 'LOW', cls: 'sev-low' },
            { key: 'timeout', label: 'INFO', cls: 'sev-info' },
        ];

        return (
            <div className="app-container wide">
                {modals}

                <div className="global-header">
                    <div className="global-breadcrumbs">
                        <span className="breadcrumb-link" onClick={handleBack}>Projects</span>
                        <span className="bc-sep">/</span>
                        <span className="breadcrumb-link" onClick={handleBack}>VirusTotal</span>
                        <span className="bc-sep">/</span>
                        <span className="breadcrumb-current">URL-Scan-Results</span>
                    </div>
                    <div className="global-meta-bar">
                        <div className="meta-left">
                            <span className="meta-item">{scanTimestamp}</span>
                            <span className="meta-item meta-status">
                                <span className="status-dot" />
                                Scan Complete
                            </span>
                        </div>
                        <div className="meta-right">
                            <button className="meta-action-btn" title="Export PDF">
                                <Download size={13} /> Export PDF
                            </button>
                            <button className="meta-action-btn" title="Share Link">
                                <Share2 size={13} /> Share Link
                            </button>
                            <div className="view-toggle-inline">
                                <button
                                    className={`vtog-btn ${viewMode === 'simple' ? 'active' : ''}`}
                                    onClick={() => setViewMode('simple')}
                                >
                                    Simple
                                </button>
                                <button
                                    className={`vtog-btn ${viewMode === 'detailed' ? 'active' : ''}`}
                                    onClick={() => setViewMode('detailed')}
                                >
                                    Detailed
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Summary Bar */}
                <div className="summary-bar">
                    <div className="summary-item">
                        <div className="summary-label">Safety Score</div>
                        <div className={`summary-value ${vt.positives === 0 ? 'score-safe' : 'score-danger'}`}>
                            {vt.total_engines > 0 ? Math.round(((vt.total_engines - vt.positives) / vt.total_engines) * 100) : 100}%
                        </div>
                    </div>
                    <div className="summary-item">
                        <div className="summary-label">Verdict</div>
                        <div className="summary-value">
                            {vt.positives === 0 ? 'CLEAN' : vt.positives <= 3 ? 'SUSPICIOUS' : 'MALICIOUS'}
                        </div>
                    </div>
                    <div className="summary-item">
                        <div className="summary-label">Engines Scanned</div>
                        <div className="summary-value">{vt.total_engines}</div>
                    </div>
                    <div className="summary-item">
                        <div className="summary-label">Flagged</div>
                        <div className="summary-value">{vt.positives}</div>
                    </div>
                </div>

                {/* Severity Cards */}
                <div className="severity-cards-row">
                    {vtCategories.map(cat => (
                        <div key={cat.key} className={`severity-card ${cat.cls}`}>
                            <div className="severity-card-count">{vt.stats[cat.key]}</div>
                            <div className="severity-card-label">{cat.label}</div>
                            <div className="severity-card-bar" />
                        </div>
                    ))}
                </div>

                {/* AI Summary */}
                <div className="ai-summary-section">
                    {!aiSummary && !aiSummaryLoading && (
                        <button
                            className="btn-ai-summary"
                            onClick={() => handleGenerateAISummary('virustotal', vt)}
                        >
                            <Sparkles size={16} />
                            Generate AI Summary
                        </button>
                    )}
                    {aiSummaryLoading && (
                        <div className="ai-summary-card">
                            <div className="ai-summary-header">
                                <Sparkles size={14} />
                                AI Summary
                            </div>
                            <div className="ai-summary-loading">
                                <Activity className="animate-spin" size={16} />
                                <span>Generating analysis...</span>
                            </div>
                        </div>
                    )}
                    {aiSummaryError && (
                        <div className="ai-summary-error">
                            <AlertTriangle size={14} />
                            <span>{aiSummaryError}</span>
                        </div>
                    )}
                    {aiSummary && (
                        <div className="ai-summary-card">
                            <div className="ai-summary-header">
                                <Sparkles size={14} />
                                AI Summary
                            </div>
                            <div className="ai-summary-body" dangerouslySetInnerHTML={{
                                __html: aiSummary
                                    .replace(/^### (.*$)/gm, '<h3>$1</h3>')
                                    .replace(/^## (.*$)/gm, '<h2>$1</h2>')
                                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                                    .replace(/\*(.*?)\*/g, '<em>$1</em>')
                                    .replace(/^- (.*$)/gm, '<li>$1</li>')
                                    .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
                                    .replace(/\n{2,}/g, '<br/><br/>')
                                    .replace(/\n/g, '<br/>')
                            }} />
                        </div>
                    )}
                </div>

                {/* Engine Results Feed */}
                {(() => {
                    const vtSevMap = { malicious: 'CRITICAL', suspicious: 'HIGH', harmless: 'MEDIUM', undetected: 'LOW', timeout: 'INFO' };
                    const vtSevColors = { CRITICAL: '#d9534f', HIGH: '#e88a1a', MEDIUM: '#f0ad4e', LOW: '#5cb85c', INFO: '#3498db' };
                    const vtGroups = [
                        { key: 'malicious', label: 'Malicious', icon: Wifi },
                        { key: 'suspicious', label: 'Suspicious', icon: AlertTriangle },
                        { key: 'undetected', label: 'Undetected', icon: EyeOff },
                        { key: 'harmless', label: 'Harmless', icon: Shield },
                        { key: 'timeout', label: 'Timeout', icon: Timer },
                    ];
                    const vtGrouped = {};
                    vtGroups.forEach(g => { vtGrouped[g.key] = []; });
                    vt.results.forEach(r => {
                        if (vtGrouped[r.category]) vtGrouped[r.category].push(r);
                    });
                    const [activeVtCat, setActiveVtCat] = [activeDimension, setActiveDimension];
                    const vtGroupColors = { malicious: '#e74c3c', suspicious: '#e67e22', undetected: '#9b59b6', harmless: '#2ecc71', timeout: '#3498db' };

                    // --- DETAILED VIEW: Charts + Top Engines ---
                    if (viewMode === 'detailed') {
                        const vtCatChartData = vtGroups
                            .filter(g => vtGrouped[g.key].length > 0)
                            .map(g => ({ name: g.label, value: vtGrouped[g.key].length, color: vtGroupColors[g.key] }));

                        const vtSevChartData = Object.entries(vtSevMap).reduce((acc, [cat, sev]) => {
                            const count = vtGrouped[cat]?.length || 0;
                            if (count > 0) {
                                const existing = acc.find(d => d.name === sev);
                                if (existing) existing.value += count;
                                else acc.push({ name: sev, value: count, color: vtSevColors[sev] });
                            }
                            return acc;
                        }, []);

                        const vtScore = vt.total_engines > 0 ? Math.round(((vt.total_engines - vt.positives) / vt.total_engines) * 100) : 100;
                        const vtScoreData = [
                            { value: vtScore, color: vtScore > 70 ? '#5cb85c' : '#d9534f' },
                            { value: 100 - vtScore, color: '#1a1a1a' },
                        ];
                        const vtVerdict = vt.positives === 0 ? 'CLEAN' : vt.positives <= 3 ? 'SUSPICIOUS' : 'MALICIOUS';

                        const vtRadarData = vtGroups.map(g => ({
                            subject: g.label,
                            A: Math.min(vtGrouped[g.key].length, 10),
                        }));

                        // Top engines: group by engine result, count occurrences
                        const engineCounts = {};
                        vt.results.forEach(r => {
                            const key = `${r.category}:${r.result || 'N/A'}`;
                            if (!engineCounts[key]) engineCounts[key] = { category: r.category, result: r.result || 'N/A', count: 0 };
                            engineCounts[key].count++;
                        });
                        const topEngines = Object.values(engineCounts).sort((a, b) => b.count - a.count).slice(0, 7);

                        return (
                            <>
                                {/* Severity Cards */}
                                <div className="severity-cards-row">
                                    {vtCategories.map(cat => (
                                        <div key={cat.key} className={`severity-card ${cat.cls}`}>
                                            <div className="severity-card-count">{vt.stats[cat.key]}</div>
                                            <div className="severity-card-label">{cat.label}</div>
                                            <div className="severity-card-bar" />
                                        </div>
                                    ))}
                                </div>

                                {/* Charts Row */}
                                <div className="charts-row">
                                    <div className="chart-card">
                                        <div className="chart-card-label">Findings by Category</div>
                                        <div className="chart-card-body">
                                            <ResponsiveContainer width={140} height={140}>
                                                <PieChart>
                                                    <Pie data={vtCatChartData.length > 0 ? vtCatChartData : [{ name: 'None', value: 1, color: '#333' }]} cx="50%" cy="50%" innerRadius={35} outerRadius={60} dataKey="value" stroke="none">
                                                        {(vtCatChartData.length > 0 ? vtCatChartData : [{ color: '#333' }]).map((entry, i) => <Cell key={i} fill={entry.color} />)}
                                                    </Pie>
                                                    <Tooltip />
                                                </PieChart>
                                            </ResponsiveContainer>
                                            <div className="chart-legend">
                                                {vtCatChartData.map((d, i) => (
                                                    <div key={i} className="legend-item">
                                                        <span className="legend-dot" style={{ background: d.color }} />
                                                        <span className="legend-label">{d.name}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="chart-card">
                                        <div className="chart-card-label">Severity Breakdown</div>
                                        <div className="chart-card-body">
                                            <ResponsiveContainer width={140} height={140}>
                                                <PieChart>
                                                    <Pie data={vtSevChartData.length > 0 ? vtSevChartData : [{ name: 'None', value: 1, color: '#333' }]} cx="50%" cy="50%" innerRadius={35} outerRadius={60} dataKey="value" stroke="none">
                                                        {(vtSevChartData.length > 0 ? vtSevChartData : [{ color: '#333' }]).map((entry, i) => <Cell key={i} fill={entry.color} />)}
                                                    </Pie>
                                                    <Tooltip />
                                                </PieChart>
                                            </ResponsiveContainer>
                                            <div className="chart-legend">
                                                {vtSevChartData.map((d, i) => (
                                                    <div key={i} className="legend-item">
                                                        <span className="legend-dot" style={{ background: d.color }} />
                                                        <span className="legend-label">{d.name}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="chart-card">
                                        <div className="chart-card-label">Safety Score</div>
                                        <div className="chart-card-body">
                                            <ResponsiveContainer width={140} height={140}>
                                                <PieChart>
                                                    <Pie data={vtScoreData} cx="50%" cy="50%" innerRadius={35} outerRadius={60} dataKey="value" stroke="none" startAngle={90} endAngle={-270}>
                                                        {vtScoreData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                                                    </Pie>
                                                </PieChart>
                                            </ResponsiveContainer>
                                            <div className="chart-legend">
                                                <div style={{ fontSize: '1.75rem', fontWeight: 700, color: vtScore > 70 ? '#5cb85c' : '#d9534f' }}>{vtScore}%</div>
                                                <div className="legend-label">{vtVerdict}</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Radar + Top Engines */}
                                <div className="bottom-row">
                                    <div className="chart-card">
                                        <div className="chart-card-label">Category Analysis</div>
                                        <div style={{ height: '300px', width: '100%' }}>
                                            <ResponsiveContainer width="100%" height="100%">
                                                <RadarChart cx="50%" cy="50%" outerRadius="80%" data={vtRadarData}>
                                                    <PolarGrid stroke="var(--border)" />
                                                    <PolarAngleAxis dataKey="subject" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
                                                    <PolarRadiusAxis angle={30} domain={[0, 10]} tick={false} axisLine={false} />
                                                    <Radar name="Engines" dataKey="A" stroke="var(--accent-color)" fill="var(--accent-color)" fillOpacity={0.3} />
                                                </RadarChart>
                                            </ResponsiveContainer>
                                        </div>
                                    </div>

                                    <div className="top-findings-card">
                                        <div className="top-findings-label">Top Results</div>
                                        <div className="top-findings-list">
                                            {topEngines.map((e, i) => (
                                                <div key={i} className="top-finding-item">
                                                    <span className={`severity-pill severity-${(vtSevMap[e.category] || 'info').toLowerCase()}`}>
                                                        {vtSevMap[e.category] || 'INFO'}
                                                    </span>
                                                    <span className="top-finding-name">{e.result}</span>
                                                    <span className="top-finding-count">{e.count}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </>
                        );
                    }

                    return (
                        <div className="results-layout">
                            <aside className="dim-sidebar">
                                <div className="dim-sidebar-label">Categories</div>
                                <div
                                    className={`dim-sidebar-item ${activeVtCat === null ? 'active' : ''}`}
                                    onClick={() => setActiveVtCat(null)}
                                >
                                    <LayoutList size={15} className="dim-sidebar-icon" />
                                    <span className="dim-sidebar-name">All Engines</span>
                                    <span className="dim-sidebar-badge">{vt.results.length}</span>
                                </div>
                                {vtGroups.map((g) => {
                                    const count = vtGrouped[g.key].length;
                                    const GIcon = g.icon;
                                    return (
                                        <div
                                            key={g.key}
                                            className={`dim-sidebar-item ${activeVtCat === g.key ? 'active' : ''} ${count === 0 ? 'empty' : ''}`}
                                            onClick={() => count > 0 && setActiveVtCat(activeVtCat === g.key ? null : g.key)}
                                        >
                                            <GIcon size={15} className="dim-sidebar-icon" style={{ color: vtGroupColors[g.key] }} />
                                            <span className="dim-sidebar-name">{g.label}</span>
                                            {count > 0 ? (
                                                <span className="dim-sidebar-badge" style={{ background: vtGroupColors[g.key] + '33', color: vtGroupColors[g.key] }}>{count}</span>
                                            ) : (
                                                <span className="dim-sidebar-badge dim-badge-zero">0</span>
                                            )}
                                        </div>
                                    );
                                })}
                            </aside>
                            <div className="results-main">
                                {(activeVtCat ? vtGroups.filter(g => g.key === activeVtCat) : vtGroups).map(g => {
                                    const engines = vtGrouped[g.key];
                                    if (engines.length === 0) return null;
                                    const isExp = expandedDims[g.key] !== false;
                                    const GIcon = g.icon;
                                    return (
                                        <div key={g.key} className="dimension-group">
                                            <div className="dimension-header" onClick={() => setExpandedDims(prev => ({ ...prev, [g.key]: !isExp }))}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                                    {isExp ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                                    <GIcon size={14} style={{ color: vtGroupColors[g.key], opacity: 0.8 }} />
                                                    <span className="dimension-name">{g.label}</span>
                                                </div>
                                                <div className="dimension-meta">
                                                    <span className="dimension-count">{engines.length} engine{engines.length !== 1 ? 's' : ''}</span>
                                                </div>
                                            </div>
                                            {isExp && (
                                                <div className="dimension-findings">
                                                    {engines.map((r, i) => {
                                                        const sevLabel = vtSevMap[r.category] || 'INFO';
                                                        const fKey = `vt-${g.key}-${i}`;
                                                        const fExpanded = expandedFindings[fKey];
                                                        return (
                                                            <div key={i} className={`forensic-card ${fExpanded ? 'expanded' : ''}`}>
                                                                <div className="forensic-collapsed" onClick={() => toggleFinding(fKey)}>
                                                                    <div className="forensic-sev-block" style={{ background: vtSevColors[sevLabel] }}>
                                                                        {sevLabel}
                                                                    </div>
                                                                    <div className="forensic-summary">
                                                                        <span className="forensic-threat">{r.engine}</span>
                                                                        <span className="forensic-location">{r.result || 'clean'}</span>
                                                                    </div>
                                                                    <div className="forensic-chevron">
                                                                        {fExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                                                    </div>
                                                                </div>
                                                                {fExpanded && (
                                                                    <div className="forensic-expanded">
                                                                        <div className="forensic-vector-section">
                                                                            <div className="forensic-section-label">Engine Details</div>
                                                                            <p className="forensic-vector-text">
                                                                                <strong>{r.engine}</strong> classified this URL as <strong>{r.category}</strong> with verdict: <strong>{r.result || 'N/A'}</strong>.
                                                                            </p>
                                                                        </div>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        );
                                                    })}
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    );
                })()}
            </div>
        );
    }

    // ==================== RESULTS VIEW ====================
    if (report) {
        const grouped = getGroupedFindings();

        return (
            <div className="app-container wide">
                {modals}

                {/* Global Header */}
                <div className="global-header">
                    <div className="global-breadcrumbs">
                        <span className="breadcrumb-link" onClick={handleBack}>Projects</span>
                        <span className="bc-sep">/</span>
                        <span className="breadcrumb-link" onClick={handleBack}>{projectName}</span>
                        <span className="bc-sep">/</span>
                        <span className="breadcrumb-current">Scan-Results</span>
                    </div>
                    <div className="global-meta-bar">
                        <div className="meta-left">
                            <span className="meta-item">{scanTimestamp}</span>
                            {getAgentEnv() && (
                                <span className="meta-item">{getAgentEnv()}</span>
                            )}
                            <span className="meta-item meta-status">
                                <span className="status-dot" />
                                Scan Complete
                            </span>
                        </div>
                        <div className="meta-right">
                            <button className="meta-action-btn" title="Export PDF">
                                <Download size={13} /> Export PDF
                            </button>
                            <button className="meta-action-btn" title="Share Link">
                                <Share2 size={13} /> Share Link
                            </button>
                            <div className="view-toggle-inline">
                                <button
                                    className={`vtog-btn ${viewMode === 'simple' ? 'active' : ''}`}
                                    onClick={() => setViewMode('simple')}
                                >
                                    Simple
                                </button>
                                <button
                                    className={`vtog-btn ${viewMode === 'detailed' ? 'active' : ''}`}
                                    onClick={() => setViewMode('detailed')}
                                >
                                    Detailed
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Summary Bar */}
                <div className="summary-bar">
                    <div className="summary-item">
                        <div className="summary-label">Safety Score</div>
                        <div className={`summary-value ${safetyScore > 70 ? 'score-safe' : 'score-danger'}`}>
                            {safetyScore}%
                        </div>
                    </div>
                    <div className="summary-item">
                        <div className="summary-label">Verdict</div>
                        <div className="summary-value" style={{ fontSize: '1rem' }}>
                            {report.verdict}
                        </div>
                    </div>
                    <div className="summary-item">
                        <div className="summary-label">Files Scanned</div>
                        <div className="summary-value">{report.metadata.files_scanned}</div>
                    </div>
                    <div className="summary-item">
                        <div className="summary-label">Findings</div>
                        <div className="summary-value">{report.findings.length}</div>
                    </div>
                </div>

                {/* Severity Bento Cards */}
                <div className="severity-cards-row">
                    {SEVERITY_ORDER.map(sev => {
                        const counts = getSeverityCounts();
                        return (
                            <div key={sev} className={`severity-card sev-${sev.toLowerCase()}`}>
                                <div className="severity-card-count">{counts[sev]}</div>
                                <div className="severity-card-label">{sev}</div>
                                <div className="severity-card-bar" />
                            </div>
                        );
                    })}
                </div>

                {/* AI Summary */}
                <div className="ai-summary-section">
                    {!aiSummary && !aiSummaryLoading && (
                        <button
                            className="btn-ai-summary"
                            onClick={() => handleGenerateAISummary('local', report)}
                        >
                            <Sparkles size={16} />
                            Generate AI Summary
                        </button>
                    )}
                    {aiSummaryLoading && (
                        <div className="ai-summary-card">
                            <div className="ai-summary-header">
                                <Sparkles size={14} />
                                AI Summary
                            </div>
                            <div className="ai-summary-loading">
                                <Activity className="animate-spin" size={16} />
                                <span>Generating analysis...</span>
                            </div>
                        </div>
                    )}
                    {aiSummaryError && (
                        <div className="ai-summary-error">
                            <AlertTriangle size={14} />
                            <span>{aiSummaryError}</span>
                        </div>
                    )}
                    {aiSummary && (
                        <div className="ai-summary-card">
                            <div className="ai-summary-header">
                                <Sparkles size={14} />
                                AI Summary
                            </div>
                            <div className="ai-summary-body" dangerouslySetInnerHTML={{
                                __html: aiSummary
                                    .replace(/^### (.*$)/gm, '<h3>$1</h3>')
                                    .replace(/^## (.*$)/gm, '<h2>$1</h2>')
                                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                                    .replace(/\*(.*?)\*/g, '<em>$1</em>')
                                    .replace(/^- (.*$)/gm, '<li>$1</li>')
                                    .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
                                    .replace(/\n{2,}/g, '<br/><br/>')
                                    .replace(/\n/g, '<br/>')
                            }} />
                        </div>
                    )}
                </div>

                {/* Simple View with Sidebar */}
                {viewMode === 'simple' && (
                    <div className="results-layout">
                        {/* Sidebar */}
                        <aside className="dim-sidebar">
                            <div className="dim-sidebar-label">Dimensions</div>
                            <div
                                className={`dim-sidebar-item ${activeDimension === null ? 'active' : ''}`}
                                onClick={() => setActiveDimension(null)}
                            >
                                <LayoutList size={15} className="dim-sidebar-icon" />
                                <span className="dim-sidebar-name">All Findings</span>
                                <span className="dim-sidebar-badge">{report.findings.length}</span>
                            </div>
                            {DIMENSIONS.map((dim, i) => {
                                const count = (grouped[dim.key] || []).length;
                                const Icon = DIMENSION_ICONS[dim.key];
                                return (
                                    <div
                                        key={dim.key}
                                        className={`dim-sidebar-item ${activeDimension === dim.key ? 'active' : ''} ${count === 0 ? 'empty' : ''}`}
                                        onClick={() => count > 0 && setActiveDimension(activeDimension === dim.key ? null : dim.key)}
                                    >
                                        <Icon size={15} className="dim-sidebar-icon" style={{ color: DIMENSION_COLORS[i] }} />
                                        <span className="dim-sidebar-name">{dim.title}</span>
                                        {count > 0 && (
                                            <span className="dim-sidebar-badge" style={{
                                                background: `${DIMENSION_COLORS[i]}20`,
                                                color: DIMENSION_COLORS[i]
                                            }}>{count}</span>
                                        )}
                                        {count === 0 && (
                                            <span className="dim-sidebar-badge dim-badge-zero">0</span>
                                        )}
                                    </div>
                                );
                            })}
                        </aside>

                        {/* Main Feed */}
                        <div className="results-main">
                            {(activeDimension ? [DIMENSIONS.find(d => d.key === activeDimension)] : DIMENSIONS).map(dim => {
                                if (!dim) return null;
                                const findings = grouped[dim.key] || [];
                                if (findings.length === 0) return null;
                                const isExpanded = expandedDims[dim.key];
                                const Icon = DIMENSION_ICONS[dim.key];
                                const dimIdx = DIMENSIONS.indexOf(dim);

                                return (
                                    <div key={dim.key} className="dimension-group">
                                        <div
                                            className="dimension-header"
                                            onClick={() => toggleDimension(dim.key)}
                                        >
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                                <Icon size={14} style={{ color: DIMENSION_COLORS[dimIdx], opacity: 0.8 }} />
                                                <span className="dimension-name">
                                                    {dim.title}
                                                </span>
                                            </div>
                                            <div className="dimension-meta">
                                                <span className="dimension-count">
                                                    {findings.length} finding{findings.length !== 1 ? 's' : ''}
                                                </span>
                                            </div>
                                        </div>
                                        {isExpanded && (
                                            <div className="dimension-findings">
                                                {findings.map((f, i) => {
                                                    const fKey = getFindingKey(f, i);
                                                    const fExpanded = expandedFindings[fKey];
                                                    const sevBlock = getSeverityBlock(f.severity);
                                                    const fileName = f.file_path.split('/').pop();

                                                    return (
                                                        <div key={i} className={`forensic-card ${fExpanded ? 'expanded' : ''}`}>
                                                            <div className="forensic-collapsed" onClick={() => toggleFinding(fKey)}>
                                                                <div className="forensic-sev-block" style={{ background: sevBlock.color }}>
                                                                    {sevBlock.label}
                                                                </div>
                                                                <div className="forensic-summary">
                                                                    <span className="forensic-threat">{f.description || f.rule_name}</span>
                                                                    <span className="forensic-location">{fileName}:{f.line_number}</span>
                                                                </div>
                                                                <div className="forensic-chevron">
                                                                    {fExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                                                </div>
                                                            </div>
                                                            {fExpanded && (
                                                                <div className="forensic-expanded">
                                                                    {f.matched_text && (
                                                                        <div className="forensic-code-section">
                                                                            <div className="forensic-section-label">Code Snippet</div>
                                                                            <div className="forensic-code-block">
                                                                                <span className="forensic-line-num">{f.line_number}</span>
                                                                                <code className="forensic-code-text">{f.matched_text}</code>
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                    <div className="forensic-vector-section">
                                                                        <div className="forensic-section-label">Attack Vector</div>
                                                                        <p className="forensic-vector-text">
                                                                            {f.description || `The pattern "${f.rule_name}" was detected in ${fileName} at line ${f.line_number}. This could be exploited by an attacker to ${
                                                                                dim.key === 'remote_execution' ? 'execute arbitrary commands on the host system' :
                                                                                dim.key === 'exfiltration' ? 'exfiltrate sensitive data to external servers' :
                                                                                dim.key === 'secret_access' ? 'access credentials and API keys stored on the system' :
                                                                                dim.key === 'persistence' ? 'maintain persistent access across system restarts' :
                                                                                dim.key === 'destructive_ops' ? 'destroy data or corrupt system state irreversibly' :
                                                                                dim.key === 'prompt_injection' ? 'override the agent\'s instructions and hijack its behavior' :
                                                                                'hide malicious intent through code obfuscation'
                                                                            }.`}
                                                                        </p>
                                                                    </div>
                                                                    <div className="forensic-fix-section">
                                                                        <div className="forensic-fix-header">
                                                                            <Sparkles size={13} />
                                                                            AI Fix Suggestion
                                                                        </div>
                                                                        <div className="forensic-fix-body">
                                                                            <div className="forensic-fix-before">
                                                                                <div className="forensic-fix-label">Before</div>
                                                                                <code>{f.matched_text || f.rule_name}</code>
                                                                            </div>
                                                                            <div className="forensic-fix-after">
                                                                                <div className="forensic-fix-label">After</div>
                                                                                <code>
                                                                                    {dim.key === 'remote_execution' ? '# Use subprocess with restricted args, no shell=True' :
                                                                                     dim.key === 'exfiltration' ? '# Validate destination URLs against allowlist' :
                                                                                     dim.key === 'secret_access' ? '# Use a secrets manager (e.g., vault) instead' :
                                                                                     dim.key === 'persistence' ? '# Remove auto-start hooks; use managed schedulers' :
                                                                                     dim.key === 'destructive_ops' ? '# Add confirmation + backup before destructive ops' :
                                                                                     dim.key === 'prompt_injection' ? '# Remove instruction-override text; keep skill content declarative' :
                                                                                     '# Replace obfuscated code with readable equivalent'}
                                                                                </code>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}

                            {report.findings.length === 0 && (
                                <div style={{ textAlign: 'center', padding: '3rem 0', color: 'var(--text-secondary)' }}>
                                    No security findings detected.
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* Detailed Dashboard View */}
                {viewMode === 'detailed' && (() => {
                    const sevCounts = getSeverityCounts();
                    const sevChartData = getSeverityChartData();
                    const dimChartData = getDimensionChartData();
                    const scoreData = getSafetyScoreData();
                    const topFindings = getTopFindings();

                    return (
                        <>
                            {/* Row 1: Severity Cards */}
                            <div className="severity-cards-row">
                                {SEVERITY_ORDER.map(sev => (
                                    <div key={sev} className={`severity-card sev-${sev.toLowerCase()}`}>
                                        <div className="severity-card-count">{sevCounts[sev]}</div>
                                        <div className="severity-card-label">{sev}</div>
                                        <div className="severity-card-bar" />
                                    </div>
                                ))}
                            </div>

                            {/* Row 2: Three Donut Charts */}
                            <div className="charts-row">
                                {/* By Dimension */}
                                <div className="chart-card">
                                    <div className="chart-card-label">Findings by Dimension</div>
                                    <div className="chart-card-body">
                                        <ResponsiveContainer width={140} height={140}>
                                            <PieChart>
                                                <Pie
                                                    data={dimChartData.length > 0 ? dimChartData : [{ name: 'None', value: 1, color: '#333' }]}
                                                    cx="50%" cy="50%"
                                                    innerRadius={35} outerRadius={60}
                                                    dataKey="value"
                                                    stroke="none"
                                                >
                                                    {(dimChartData.length > 0 ? dimChartData : [{ color: '#333' }]).map((entry, i) => (
                                                        <Cell key={i} fill={entry.color} />
                                                    ))}
                                                </Pie>
                                                <Tooltip />
                                            </PieChart>
                                        </ResponsiveContainer>
                                        <div className="chart-legend">
                                            {dimChartData.map((d, i) => (
                                                <div key={i} className="legend-item">
                                                    <span className="legend-dot" style={{ background: d.color }} />
                                                    <span className="legend-label">{d.name}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>

                                {/* By Severity */}
                                <div className="chart-card">
                                    <div className="chart-card-label">Vulnerabilities</div>
                                    <div className="chart-card-body">
                                        <ResponsiveContainer width={140} height={140}>
                                            <PieChart>
                                                <Pie
                                                    data={sevChartData.length > 0 ? sevChartData : [{ name: 'None', value: 1, color: '#333' }]}
                                                    cx="50%" cy="50%"
                                                    innerRadius={35} outerRadius={60}
                                                    dataKey="value"
                                                    stroke="none"
                                                >
                                                    {(sevChartData.length > 0 ? sevChartData : [{ color: '#333' }]).map((entry, i) => (
                                                        <Cell key={i} fill={entry.color} />
                                                    ))}
                                                </Pie>
                                                <Tooltip />
                                            </PieChart>
                                        </ResponsiveContainer>
                                        <div className="chart-legend">
                                            {sevChartData.map((d, i) => (
                                                <div key={i} className="legend-item">
                                                    <span className="legend-dot" style={{ background: d.color }} />
                                                    <span className="legend-label">{d.name}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>

                                {/* Safety Score Gauge */}
                                <div className="chart-card">
                                    <div className="chart-card-label">Safety Score</div>
                                    <div className="chart-card-body">
                                        <ResponsiveContainer width={140} height={140}>
                                            <PieChart>
                                                <Pie
                                                    data={scoreData}
                                                    cx="50%" cy="50%"
                                                    innerRadius={35} outerRadius={60}
                                                    dataKey="value"
                                                    stroke="none"
                                                    startAngle={90} endAngle={-270}
                                                >
                                                    {scoreData.map((entry, i) => (
                                                        <Cell key={i} fill={entry.color} />
                                                    ))}
                                                </Pie>
                                            </PieChart>
                                        </ResponsiveContainer>
                                        <div className="chart-legend">
                                            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: safetyScore > 70 ? '#5cb85c' : '#d9534f' }}>
                                                {safetyScore}%
                                            </div>
                                            <div className="legend-label">{report.verdict}</div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Row 3: Radar + Top Findings */}
                            <div className="bottom-row">
                                <div className="chart-card">
                                    <div className="chart-card-label">Dimension Analysis</div>
                                    <div style={{ height: '300px', width: '100%' }}>
                                        <ResponsiveContainer width="100%" height="100%">
                                            <RadarChart cx="50%" cy="50%" outerRadius="80%" data={getRadarData()}>
                                                <PolarGrid stroke="var(--border)" />
                                                <PolarAngleAxis dataKey="subject" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
                                                <PolarRadiusAxis angle={30} domain={[0, 10]} tick={false} axisLine={false} />
                                                <Radar
                                                    name="Findings"
                                                    dataKey="A"
                                                    stroke="var(--accent-color)"
                                                    fill="var(--accent-color)"
                                                    fillOpacity={0.3}
                                                />
                                            </RadarChart>
                                        </ResponsiveContainer>
                                    </div>
                                </div>

                                <div className="top-findings-card">
                                    <div className="top-findings-label">Top Vulnerabilities</div>
                                    <div className="top-findings-list">
                                        {topFindings.length > 0 ? topFindings.map((f, i) => (
                                            <div key={i} className="top-finding-item">
                                                <span className={`severity-pill severity-${SEVERITY_MAP[f.severity].toLowerCase()}`}>
                                                    {SEVERITY_MAP[f.severity]}
                                                </span>
                                                <span className="top-finding-name" title={f.rule_name}>
                                                    {f.rule_name}
                                                </span>
                                                <span className="top-finding-count">{f.count}</span>
                                            </div>
                                        )) : (
                                            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                                                No findings.
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </>
                    );
                })()}
            </div>
        );
    }

    // ==================== LANDING VIEW ====================
    return (
        <div className="app-container">
            {modals}

            {/* Nav */}
            <nav className="nav">
                <div className="nav-brand">
                    <ScanovaLogo size="small" />
                    <span>Scanova</span>
                </div>
                <div className="nav-links">
                    <span className="nav-link" onClick={() => setShowDocs(true)}>Docs</span>
                </div>
            </nav>

            {/* Hero */}
            <section className="hero">
                <ScanovaLogo size="large" />
                <p className="hero-subtitle">
                    Comprehensive open-source security platform for agentic architectures.
                    Delivers seven-dimensional risk analysis across all agents and external
                    dependencies to proactively detect execution threats, data exfiltration,
                    credential misuse, and systemic vulnerabilities.
                </p>
            </section>

            {/* Scan Input */}
            <section className="scan-section">
                <div className="scan-input-group">
                    <input
                        className="scan-input"
                        value={path}
                        onChange={(e) => setPath(e.target.value)}
                        placeholder="Enter path to scan..."
                        autoComplete="off"
                        onKeyDown={(e) => e.key === 'Enter' && !scanning && handleScan()}
                    />
                    <button
                        className="btn-icon"
                        onClick={() => setShowFileBrowser(true)}
                        title="Browse files"
                    >
                        <FolderOpen size={18} />
                    </button>
                    <button
                        className="btn-icon"
                        onClick={() => setShowDragDrop(true)}
                        title="Upload files"
                    >
                        <Upload size={18} />
                    </button>
                    <button className="btn-scan" onClick={handleScan} disabled={scanning}>
                        {scanning ? (
                            <>
                                <Activity className="animate-spin" size={16} />
                                Scanning...
                            </>
                        ) : (
                            <>
                                <Search size={16} />
                                Scan
                            </>
                        )}
                    </button>
                </div>
                <div className="scan-hint">
                    Supports local paths, file:// URLs, or drag & drop upload
                </div>
            </section>

            {/* Error */}
            {error && (
                <div className="error-banner">
                    <AlertTriangle size={16} />
                    <span>{error}</span>
                </div>
            )}

            {/* URL Scan */}
            <section className="url-scan-section">
                <div className="section-label">Scan a URL (VirusTotal)</div>
                <div className="scan-input-group">
                    <input
                        className="scan-input"
                        value={urlInput}
                        onChange={(e) => setUrlInput(e.target.value)}
                        placeholder="https://example.com"
                        autoComplete="off"
                        onKeyDown={(e) => e.key === 'Enter' && !urlScanning && handleUrlScan()}
                    />
                    <button className="btn-scan" onClick={handleUrlScan} disabled={urlScanning}>
                        {urlScanning ? (
                            <>
                                <Activity className="animate-spin" size={16} />
                                Scanning...
                            </>
                        ) : (
                            <>
                                <Globe size={16} />
                                Scan URL
                            </>
                        )}
                    </button>
                </div>
                <div className="scan-hint">
                    Scans URLs against 70+ security engines via VirusTotal
                </div>
            </section>

            {/* What We Check */}
            <section className="features-section">
                <div className="section-label">What We Check</div>
                <div className="features-grid">
                    {DIMENSIONS.map((dim, i) => (
                        <div key={dim.key} className="feature-item">
                            <div className="feature-number">{String(i + 1).padStart(2, '0')}</div>
                            <div className="feature-title">{dim.title}</div>
                            <div className="feature-desc">{dim.desc}</div>
                        </div>
                    ))}
                </div>
            </section>

            {/* How It Works */}
            <section className="how-section">
                <div className="section-label">How It Works</div>
                <div className="how-steps">
                    <div className="how-step">
                        <div className="step-number">01</div>
                        <div className="step-title">Enter Path</div>
                        <div className="step-desc">
                            Point to a local directory, file, or upload skill files directly.
                        </div>
                    </div>
                    <div className="how-step">
                        <div className="step-number">02</div>
                        <div className="step-title">Analyze</div>
                        <div className="step-desc">
                            The scanner runs pattern-based analysis across all 7 security dimensions.
                        </div>
                    </div>
                    <div className="how-step">
                        <div className="step-number">03</div>
                        <div className="step-title">Review</div>
                        <div className="step-desc">
                            Get a detailed report with findings, severity ratings, and a safety score.
                        </div>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="footer">
                Scanova - Security Intelligence
            </footer>
        </div>
    );
}
