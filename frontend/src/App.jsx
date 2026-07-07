import React, { useState, useEffect, useRef } from 'react';
import StatusCard from './components/StatusCard';
import './index.css';

const API_BASE = 'http://localhost:3001/api/network';

const NAV_ITEMS = [
  { id: 'overview', icon: '⊞', label: 'Overview', desc: 'Network snapshot' },
  { id: 'wifi-analyzer', icon: '📶', label: 'Wi-Fi Analyzer', desc: 'Signal & channels' },
  { id: 'isp-detector', icon: '⌖', label: 'ISP Truth', desc: 'Routing analysis' },
  { id: 'speed-stability', icon: '🚀', label: 'Speed & Stability', desc: 'Phases & bufferbloat' },
  { id: 'route-trace', icon: '🗺', label: 'Route Trace', desc: 'Hop-by-hop path' },
  { id: 'health', icon: '❤', label: 'Health & Tips', desc: 'Scores & advice' },
  { id: 'security', icon: '⛨', label: 'Security', desc: 'Threat scanner' },
  { id: 'devices', icon: '⊟', label: 'Devices', desc: 'Connected devices' },
  { id: 'trends', icon: '📈', label: 'Trends', desc: 'History & graphs' },
  { id: 'diagnostics', icon: '⚙', label: 'Diagnostics', desc: 'Deep inspect' },
  { id: 'wsl-tools', icon: '🐧', label: 'WSL Tools', desc: 'mtr · dig (Linux)', wslOnly: true },
  { id: 'guide', icon: '?', label: 'How to Use', desc: 'Metric guide' },
];

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const [basicStats, setBasicStats] = useState(null);
  const [gatewayPing, setGatewayPing] = useState(null);
  const [externalPing, setExternalPing] = useState(null);
  const [publicIp, setPublicIp] = useState(null);
  const [dnsTime, setDnsTime] = useState(null);
  const [throughput, setThroughput] = useState(null);
  const [loadingBasic, setLoadingBasic] = useState(true);
  const [toolbarVisible, setToolbarVisible] = useState(true);
  const [toolbarPinned, setToolbarPinned] = useState(true);
  const [toolbarOpacity, setToolbarOpacity] = useState(100);
  const [arpCount, setArpCount] = useState(null);
  const [globalPing, setGlobalPing] = useState(null);
  const [cdnSpeedTest, setCdnSpeedTest] = useState(null);
  const [cdnTestLoading, setCdnTestLoading] = useState(false);
  const [dnsHijack, setDnsHijack] = useState(null);
  const [showEvidenceReport, setShowEvidenceReport] = useState(false);
  const [securityScan, setSecurityScan] = useState(null);
  const [portScan, setPortScan] = useState(null);
  const [portScanLoading, setPortScanLoading] = useState(false);

  // New advanced security state
  const [devices, setDevices] = useState(null);
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [arpSpoof, setArpSpoof] = useState(null);
  const [dnsLeak, setDnsLeak] = useState(null);
  const [wifiAudit, setWifiAudit] = useState(null);
  const [mitmCheck, setMitmCheck] = useState(null);

  // v1.1.0 advanced diagnostics state
  const [activeInterface, setActiveInterface] = useState(null);
  const [gatewayHealth, setGatewayHealth] = useState(null);
  const [wifiAnalysis, setWifiAnalysis] = useState(null);
  const [wifiScan, setWifiScan] = useState(null);
  const [wifiScanLoading, setWifiScanLoading] = useState(false);
  const [wifiCapabilities, setWifiCapabilities] = useState(null);

  // Router admin
  const [routerAdminIp, setRouterAdminIp] = useState('');
  const [routerAdminUser, setRouterAdminUser] = useState(() => { try { return localStorage.getItem('nd_router_user') || ''; } catch { return ''; } });
  const [routerAdminPass, setRouterAdminPass] = useState(() => { try { return localStorage.getItem('nd_router_pass') || ''; } catch { return ''; } });
  const [routerDevices, setRouterDevices] = useState(null);
  const [routerDevicesLoading, setRouterDevicesLoading] = useState(false);
  const [dnsBenchmark, setDnsBenchmark] = useState(null);
  const [dnsBenchLoading, setDnsBenchLoading] = useState(false);
  const [deviceHealth, setDeviceHealth] = useState(null);
  const [healthBreakdown, setHealthBreakdown] = useState(null);
  const [healthLoading, setHealthLoading] = useState(false);

  // v1.2.0 - speed phases, route trace, stability, trends, WSL
  const [speedDiag, setSpeedDiag] = useState(null);
  const [speedDiagLoading, setSpeedDiagLoading] = useState(false);
  const [routeTrace, setRouteTrace] = useState(null);
  const [routeTraceLoading, setRouteTraceLoading] = useState(false);
  const [routeTarget, setRouteTarget] = useState('8.8.8.8');
  const [stabilityRunning, setStabilityRunning] = useState(false);
  const [stabilityProgress, setStabilityProgress] = useState(0);
  const [stabilitySamples, setStabilitySamples] = useState([]);
  const [stabilityResult, setStabilityResult] = useState(null);
  const [trends, setTrends] = useState([]);
  const [wslStatus, setWslStatus] = useState(null);
  const [wslMtrData, setWslMtrData] = useState(null);
  const [wslMtrLoading, setWslMtrLoading] = useState(false);
  const [wslMtrTarget, setWslMtrTarget] = useState('8.8.8.8');
  const [wslDigData, setWslDigData] = useState(null);
  const [wslDigLoading, setWslDigLoading] = useState(false);
  const [wslDigDomain, setWslDigDomain] = useState('cloudflare.com');
  const [wslInstallCopied, setWslInstallCopied] = useState(false);
  const [wslToolsLoading, setWslToolsLoading] = useState(false);
  // New WSL tool states
  const [wslTracerouteData, setWslTracerouteData] = useState(null);
  const [wslTracerouteLoading, setWslTracerouteLoading] = useState(false);
  const [wslTracerouteTarget, setWslTracerouteTarget] = useState('8.8.8.8');
  const [wslNmapData, setWslNmapData] = useState(null);
  const [wslNmapLoading, setWslNmapLoading] = useState(false);
  const [wslNmapSubnet, setWslNmapSubnet] = useState('');
  const [wslIpv6Data, setWslIpv6Data] = useState(null);
  const [wslIpv6Loading, setWslIpv6Loading] = useState(false);
  const [wslHttpData, setWslHttpData] = useState(null);
  const [wslHttpLoading, setWslHttpLoading] = useState(false);
  const [wslHttpUrl, setWslHttpUrl] = useState('https://cloudflare.com');

  const stabilityTimer = useRef(null);
  const opacityTimer = useRef(null);

  // Refs mirroring live state for the trends recorder (avoids stale closures)
  const throughputRef = useRef(null);
  const externalPingRef = useRef(null);
  const basicStatsRef = useRef(null);
  useEffect(() => { throughputRef.current = throughput; }, [throughput]);
  useEffect(() => { externalPingRef.current = externalPing; }, [externalPing]);
  useEffect(() => { basicStatsRef.current = basicStats; }, [basicStats]);

  const fetchToolbarStatus = () => {
    fetch('http://localhost:3001/api/toolbar/status')
      .then(r => r.json())
      .then(s => { setToolbarVisible(s.visible); setToolbarPinned(s.pinned); setToolbarOpacity(s.opacity ?? 100); })
      .catch(() => {});
  };

  const toggleToolbar = () => {
    fetch('http://localhost:3001/api/toolbar/toggle', { method: 'POST' })
      .then(() => fetchToolbarStatus())
      .catch(() => {});
  };

  const togglePin = () => {
    fetch('http://localhost:3001/api/toolbar/pin-toggle', { method: 'POST' })
      .then(r => r.json())
      .then(s => setToolbarPinned(s.pinned))
      .catch(() => {});
  };

  const handleOpacityChange = (pct) => {
    setToolbarOpacity(pct);
    clearTimeout(opacityTimer.current);
    opacityTimer.current = setTimeout(() => {
      fetch('http://localhost:3001/api/toolbar/opacity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ opacity: pct / 100 }),
      }).catch(() => {});
    }, 80);
  };

  // ── Fetchers ──────────────────────────────────────────────────────────────
  const fetchArpCount = () => {
    fetch(`${API_BASE}/arp-count`).then(r => r.json()).then(d => setArpCount(d.count)).catch(() => {});
  };
  const fetchGlobalPing = () => {
    fetch(`${API_BASE}/ping-global`).then(r => r.json()).then(setGlobalPing).catch(console.error);
  };
  const fetchDnsHijack = () => {
    fetch(`${API_BASE}/dns-hijacking`).then(r => r.json()).then(setDnsHijack).catch(console.error);
  };
  const fetchSecurityScan = () => {
    fetch(`${API_BASE}/security-scan`).then(r => r.json()).then(setSecurityScan).catch(console.error);
  };
  const fetchArpSpoof = () => {
    fetch(`${API_BASE}/arp-spoof-check`).then(r => r.json()).then(setArpSpoof).catch(console.error);
  };
  const fetchDnsLeak = () => {
    fetch(`${API_BASE}/dns-leak`).then(r => r.json()).then(setDnsLeak).catch(console.error);
  };
  const fetchWifiAudit = () => {
    fetch(`${API_BASE}/wifi-audit`).then(r => r.json()).then(setWifiAudit).catch(console.error);
  };
  const fetchMitmCheck = () => {
    fetch(`${API_BASE}/mitm-check`).then(r => r.json()).then(setMitmCheck).catch(console.error);
  };

  // v1.1.0 fetchers
  const fetchActiveInterface = () => {
    fetch(`${API_BASE}/active-interface`).then(r => r.json()).then(setActiveInterface).catch(console.error);
  };
  const fetchGatewayHealth = () => {
    fetch(`${API_BASE}/gateway-health`).then(r => r.json()).then(setGatewayHealth).catch(console.error);
  };
  const fetchWifiAnalysis = () => {
    fetch(`${API_BASE}/wifi-analysis`).then(r => r.json()).then(setWifiAnalysis).catch(console.error);
  };
  const fetchDeviceHealth = () => {
    fetch(`${API_BASE}/device-health`).then(r => r.json()).then(setDeviceHealth).catch(console.error);
  };
  const runWifiScan = () => {
    setWifiScanLoading(true);
    fetch(`${API_BASE}/wifi-scan`).then(r => r.json())
      .then(d => { setWifiScan(d); setWifiScanLoading(false); })
      .catch(err => { console.error(err); setWifiScanLoading(false); });
  };

  const fetchWifiCapabilities = () => {
    fetch(`${API_BASE}/wifi-capabilities`).then(r => r.json()).then(setWifiCapabilities).catch(() => {});
  };

  const fetchRouterDevices = () => {
    const ip = routerAdminIp || basicStats?.ip?.defaultGateway || '';
    if (!ip) return;
    setRouterDevicesLoading(true);
    setRouterDevices(null);
    // Save credentials to localStorage (local app only)
    try { localStorage.setItem('nd_router_user', routerAdminUser); localStorage.setItem('nd_router_pass', routerAdminPass); } catch {}
    fetch(`${API_BASE}/router-devices`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, user: routerAdminUser, pass: routerAdminPass }) })
      .then(r => r.json())
      .then(d => { setRouterDevices(d); setRouterDevicesLoading(false); })
      .catch(() => setRouterDevicesLoading(false));
  };

  const openRouterAdmin = () => {
    const ip = routerAdminIp || basicStats?.ip?.defaultGateway || '';
    if (!ip) return;
    fetch(`${API_BASE}/open-browser`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: `http://${ip}` }) }).catch(() => {});
  };
  const runDnsBenchmark = () => {
    setDnsBenchLoading(true);
    fetch(`${API_BASE}/dns-benchmark`).then(r => r.json())
      .then(d => { setDnsBenchmark(d); setDnsBenchLoading(false); })
      .catch(err => { console.error(err); setDnsBenchLoading(false); });
  };
  const runHealthBreakdown = () => {
    setHealthLoading(true);
    fetch(`${API_BASE}/health-breakdown`).then(r => r.json())
      .then(d => { setHealthBreakdown(d); setHealthLoading(false); })
      .catch(err => { console.error(err); setHealthLoading(false); });
  };

  // ── v1.2.0 fetchers ──────────────────────────────────────────────────────
  const runSpeedDiagnostics = () => {
    setSpeedDiagLoading(true);
    fetch(`${API_BASE}/speed-diagnostics`).then(r => r.json())
      .then(d => { setSpeedDiag(d); setSpeedDiagLoading(false); })
      .catch(err => { console.error(err); setSpeedDiagLoading(false); });
  };

  const runRouteTrace = () => {
    setRouteTraceLoading(true);
    setRouteTrace(null);
    const t = encodeURIComponent(routeTarget || '8.8.8.8');
    fetch(`${API_BASE}/route-analysis?target=${t}`).then(r => r.json())
      .then(d => { setRouteTrace(d); setRouteTraceLoading(false); })
      .catch(err => { console.error(err); setRouteTraceLoading(false); });
  };

  const stopStabilityTest = () => {
    clearInterval(stabilityTimer.current);
    stabilityTimer.current = null;
    setStabilityRunning(false);
  };

  const startStabilityTest = () => {
    if (stabilityRunning) { stopStabilityTest(); return; }
    setStabilityRunning(true);
    setStabilityProgress(0);
    setStabilitySamples([]);
    setStabilityResult(null);
    const total = 60;
    const samples = [];
    let count = 0;
    let finished = false;

    const record = (s) => {
      if (finished) return;
      samples.push(s);
      count++;
      setStabilitySamples([...samples]);
      setStabilityProgress(Math.round((count / total) * 100));
      if (count >= total) { finished = true; finishStabilityTest(samples); }
    };

    // TCP-based ping returns in ~50ms so setInterval(1s) never piles up.
    // This ensures the test always completes in exactly 60 seconds.
    const tick = () => {
      if (finished) return;
      fetch(`${API_BASE}/ping-once?target=8.8.8.8`).then(r => r.json())
        .then(d => record({ alive: !!d.alive, latency: d.latency }))
        .catch(() => record({ alive: false, latency: null }));
    };

    tick(); // fire first ping immediately (t=0)
    stabilityTimer.current = setInterval(tick, 1000); // remaining 59 at t=1..59s
  };

  const finishStabilityTest = (samples) => {
    clearInterval(stabilityTimer.current);
    stabilityTimer.current = null;
    setStabilityRunning(false);
    const drops = samples.filter(s => !s.alive).length;
    let reconnects = 0;
    for (let k = 1; k < samples.length; k++) {
      if (!samples[k - 1].alive && samples[k].alive) reconnects += 1;
    }
    const live = samples.filter(s => s.alive && s.latency != null).map(s => s.latency);
    const avg = live.length ? live.reduce((a, b) => a + b, 0) / live.length : 0;
    const max = live.length ? Math.max(...live) : 0;
    const min = live.length ? Math.min(...live) : 0;
    const jitter = live.length > 1
      ? (live.slice(1).reduce((a, b, idx) => a + Math.abs(b - live[idx]), 0) / (live.length - 1))
      : 0;
    const lossPct = (drops / samples.length) * 100;
    let label, cls;
    if (drops === 0 && jitter < 15) { label = 'Excellent: rock solid'; cls = 'success'; }
    else if (lossPct <= 2 && jitter < 30) { label = 'Good: stable'; cls = 'highlight'; }
    else if (drops === 0 && lossPct < 1) { label = 'Fair: high jitter (no drops)'; cls = ''; }
    else if (lossPct <= 8) { label = 'Poor: occasional drops'; cls = ''; }
    else { label = 'Unstable: frequent drops'; cls = 'error'; }
    setStabilityResult({
      total: samples.length, drops, reconnects,
      avg: avg.toFixed(0), min, max, jitter: jitter.toFixed(1),
      lossPct: lossPct.toFixed(1), label, cls
    });
  };

  const fetchWslStatus = () => {
    fetch(`${API_BASE}/wsl-status`).then(r => r.json()).then(setWslStatus).catch(() => {});
  };

  // Boots the WSL distro to check installed Linux tools - only on explicit click.
  const checkWslTools = (force = false) => {
    setWslToolsLoading(true);
    fetch(`${API_BASE}/wsl-tools${force ? '?force=true' : ''}`).then(r => r.json())
      .then(d => { setWslStatus(d); setWslToolsLoading(false); })
      .catch(() => setWslToolsLoading(false));
  };

  const runWslMtr = () => {
    setWslMtrLoading(true);
    setWslMtrData(null);
    const t = encodeURIComponent(wslMtrTarget || '8.8.8.8');
    fetch(`${API_BASE}/wsl-mtr?target=${t}`).then(r => r.json())
      .then(d => { setWslMtrData(d); setWslMtrLoading(false); })
      .catch(err => { console.error(err); setWslMtrLoading(false); });
  };

  const runWslDig = () => {
    setWslDigLoading(true);
    setWslDigData(null);
    const dmn = encodeURIComponent(wslDigDomain || 'cloudflare.com');
    fetch(`${API_BASE}/wsl-dig?domain=${dmn}`).then(r => r.json())
      .then(d => { setWslDigData(d); setWslDigLoading(false); })
      .catch(err => { console.error(err); setWslDigLoading(false); });
  };

  const runWslTraceroute = () => {
    setWslTracerouteLoading(true); setWslTracerouteData(null);
    const t = encodeURIComponent(wslTracerouteTarget || '8.8.8.8');
    fetch(`${API_BASE}/wsl-traceroute?target=${t}`).then(r => r.json())
      .then(d => { setWslTracerouteData(d); setWslTracerouteLoading(false); })
      .catch(() => setWslTracerouteLoading(false));
  };

  const runWslNmap = () => {
    setWslNmapLoading(true); setWslNmapData(null);
    const sub = encodeURIComponent(wslNmapSubnet || '');
    fetch(`${API_BASE}/wsl-nmap-lan${sub ? `?subnet=${sub}` : ''}`).then(r => r.json())
      .then(d => { setWslNmapData(d); setWslNmapLoading(false); })
      .catch(() => setWslNmapLoading(false));
  };

  const runWslIpv6 = () => {
    setWslIpv6Loading(true); setWslIpv6Data(null);
    fetch(`${API_BASE}/wsl-ipv6`).then(r => r.json())
      .then(d => { setWslIpv6Data(d); setWslIpv6Loading(false); })
      .catch(() => setWslIpv6Loading(false));
  };

  const runWslHttp = () => {
    setWslHttpLoading(true); setWslHttpData(null);
    const u = encodeURIComponent(wslHttpUrl || 'https://cloudflare.com');
    fetch(`${API_BASE}/wsl-http-inspect?url=${u}`).then(r => r.json())
      .then(d => { setWslHttpData(d); setWslHttpLoading(false); })
      .catch(() => setWslHttpLoading(false));
  };

  const copyWslInstall = () => {
    const cmd = wslStatus?.installCommand || 'sudo apt update && sudo apt install -y mtr-tiny dnsutils traceroute nmap';
    navigator.clipboard.writeText(cmd).then(() => {
      setWslInstallCopied(true);
      setTimeout(() => setWslInstallCopied(false), 2500);
    });
  };

  const fetchDevices = () => {
    setDevicesLoading(true);
    fetch(`${API_BASE}/connected-devices`)
      .then(r => r.json())
      .then(d => { setDevices(d); setDevicesLoading(false); })
      .catch(err => { console.error(err); setDevicesLoading(false); });
  };

  const runPortScan = () => {
    setPortScanLoading(true);
    fetch(`${API_BASE}/port-scan`, { method: 'POST' })
      .then(r => r.json())
      .then(data => { setPortScan(data); setPortScanLoading(false); })
      .catch(err => { console.error(err); setPortScanLoading(false); });
  };

  const runCdnSpeedTest = () => {
    setCdnTestLoading(true);
    fetch(`${API_BASE}/speedtest-cdn`, { method: 'POST' })
      .then(r => r.json())
      .then(data => { setCdnSpeedTest(data); setCdnTestLoading(false); })
      .catch(err => { console.error(err); setCdnTestLoading(false); });
  };

  const copyEvidenceReport = () => {
    const report = generateEvidenceReport();
    navigator.clipboard.writeText(report).then(() => {
      setShowEvidenceReport(true);
      setTimeout(() => setShowEvidenceReport(false), 3000);
    });
  };

  const downloadFile = (content, filename, mime) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const buildSnapshot = () => ({
    generatedAt: new Date().toISOString(),
    connection: {
      activeInterface: activeInterface || null,
      connectionType: activeInterface?.type || basicStats?.wifi?.connectionType || null,
      publicIp: publicIp?.ip || null,
      isp: publicIp?.org || null,
      location: publicIp?.city && publicIp?.country ? `${publicIp.city}, ${publicIp.country}` : null,
    },
    wifi: wifiAnalysis || null,
    localHealth: gatewayHealth || gatewayPing || null,
    routing: globalPing || null,
    speedTest: cdnSpeedTest || null,
    dnsBenchmark: dnsBenchmark || null,
    deviceHealth: deviceHealth || null,
    healthBreakdown: healthBreakdown || null,
    security: { mitm: mitmCheck || null, arpSpoof: arpSpoof || null, wifiAudit: wifiAudit || null, dnsLeak: dnsLeak || null },
    devices: devices?.devices || null,
  });

  const exportJson = () => {
    downloadFile(JSON.stringify(buildSnapshot(), null, 2), `network-report-${Date.now()}.json`, 'application/json');
  };

  const exportMarkdown = () => {
    const s = buildSnapshot();
    const stab = computeStability();
    let md = `# Network Detector Report\n\n_Generated: ${new Date().toLocaleString()}_\n\n`;
    md += `## Connection\n`;
    md += `- **Type:** ${s.connection.connectionType || 'N/A'}\n`;
    md += `- **Adapter:** ${activeInterface?.name || 'N/A'} (${activeInterface?.description || ''})\n`;
    md += `- **Public IP:** ${s.connection.publicIp || 'N/A'}\n`;
    md += `- **ISP:** ${s.connection.isp || 'N/A'}\n`;
    md += `- **Location:** ${s.connection.location || 'N/A'}\n\n`;
    if (wifiAnalysis?.connected) {
      md += `## Wi-Fi\n`;
      md += `- **SSID:** ${wifiAnalysis.ssid}\n- **Band:** ${wifiAnalysis.band}\n- **Channel:** ${wifiAnalysis.channel}\n`;
      md += `- **Signal:** ${wifiAnalysis.signalPercent} (${wifiAnalysis.rssi})\n- **Standard:** ${wifiAnalysis.standard}\n`;
      md += `- **Rx/Tx:** ${wifiAnalysis.rxRate} / ${wifiAnalysis.txRate}\n\n`;
    }
    if (gatewayHealth) {
      md += `## Local Network Health (Gateway ${gatewayHealth.gateway})\n`;
      md += `- **Avg:** ${gatewayHealth.avg} ms · **Min:** ${gatewayHealth.min} · **Max:** ${gatewayHealth.max} · **p95:** ${gatewayHealth.p95}\n`;
      md += `- **Jitter:** ${gatewayHealth.jitter} ms · **Loss:** ${gatewayHealth.loss}\n- **Verdict:** ${gatewayHealth.verdict}\n\n`;
    }
    if (healthBreakdown?.categories) {
      md += `## Health Scores\n`;
      Object.entries(healthBreakdown.categories).forEach(([k, v]) => { md += `- **${k}:** ${v}/100\n`; });
      md += `- **Overall:** ${healthBreakdown.overall}/100\n\n`;
      if (healthBreakdown.recommendations?.length) {
        md += `## Recommendations\n`;
        healthBreakdown.recommendations.forEach(r => { md += `- ${r.text}\n`; });
        md += `\n`;
      }
    } else if (stab) {
      md += `## Health Score\n- **Overall:** ${stab.score}/100 (${stab.label})\n\n`;
    }
    downloadFile(md, `network-report-${Date.now()}.md`, 'text/markdown');
  };

  const generateEvidenceReport = () => {
    const timestamp = new Date().toLocaleString();
    let report = `═══════════════════════════════════════════════════════\n`;
    report += `        NETWORK DETECTOR - EVIDENCE REPORT\n`;
    report += `═══════════════════════════════════════════════════════\n\n`;
    report += `Generated: ${timestamp}\n\n`;

    report += `── CONNECTION OVERVIEW ────────────────────────────────\n`;
    report += `Public IP:           ${publicIp?.ip || 'N/A'}\n`;
    report += `ISP / ASN:           ${publicIp?.org || 'N/A'}\n`;
    report += `Location:            ${publicIp?.city && publicIp?.country ? `${publicIp.city}, ${publicIp.country}` : 'N/A'}\n`;
    report += `Wi-Fi Link Speed:    ${basicStats?.wifi?.linkSpeed || 'N/A'}\n`;
    report += `Signal Quality:      ${basicStats?.wifi?.signalQuality || 'N/A'}\n\n`;

    if (wifiAnalysis?.connected || activeInterface) {
      report += `── INTERFACE & WI-FI DETAILS ──────────────────────────\n`;
      if (activeInterface) {
        report += `Active Adapter:      ${activeInterface.name || 'N/A'}\n`;
        report += `Type:                ${activeInterface.type || 'N/A'}\n`;
        report += `Local IP:            ${basicStats?.ip?.ipv4 || 'N/A'}\n`;
        report += `MAC:                 ${activeInterface.mac || 'N/A'}\n`;
      }
      if (wifiAnalysis?.connected) {
        report += `SSID:                ${wifiAnalysis.ssid || 'N/A'}\n`;
        report += `Band / Channel:      ${wifiAnalysis.band || 'N/A'} / ${wifiAnalysis.channel || 'N/A'}\n`;
        if (wifiCapabilities?.isDualBand) {
          report += `Adapter Capability:  Dual-band (${wifiCapabilities.supportedBands.join(' + ')}) - ${wifiAnalysis.band === '2.4 GHz' ? '⚠ Currently on slower 2.4 GHz band' : '✓ On fast 5 GHz band'}\n`;
        }
        report += `RSSI:                ${wifiAnalysis.rssi || 'N/A'} (${wifiAnalysis.signalPercent || 'N/A'})\n`;
        report += `Standard:            ${wifiAnalysis.standard || 'N/A'}\n`;
        report += `Rx / Tx Rate:        ${wifiAnalysis.rxRate || 'N/A'} / ${wifiAnalysis.txRate || 'N/A'}\n`;
        report += `Security:            ${wifiAnalysis.auth || 'N/A'} (${wifiAnalysis.cipher || 'N/A'})\n`;
      }
      // Channel congestion: signal quality labels
      if (wifiAnalysis?.connected) {
        const sig = parseInt(wifiAnalysis.signalPercent);
        if (!isNaN(sig)) {
          const rssiNum = parseInt((wifiAnalysis.rssi || '').replace(/[^-\d]/g, ''));
          let sigLabel = '';
          if (rssiNum >= -50) sigLabel = 'Excellent';
          else if (rssiNum >= -60) sigLabel = 'Very Good';
          else if (rssiNum >= -67) sigLabel = 'Good';
          else if (rssiNum >= -70) sigLabel = 'Fair';
          else sigLabel = 'Poor: move closer to router';
          report += `Signal Strength:     ${sigLabel} (${wifiAnalysis.rssi})\n`;
        }
        if (wifiAnalysis.band === '2.4 GHz') {
          const ch = parseInt(wifiAnalysis.channel);
          const nonOverlap = [1, 6, 11];
          if (!nonOverlap.includes(ch)) {
            report += `Channel Note:        ⚠ Channel ${ch} overlaps with neighbouring channels. Channels 1, 6, or 11 are non-overlapping. Consider changing in router settings.\n`;
          }
        }
      }
      report += `\n`;
    }

    if (throughput || externalPing || dnsTime) {
      report += `── LIVE PERFORMANCE ───────────────────────────────────\n`;
      if (throughput) report += `Throughput:          ↓ ${throughput.downloadMbps ?? 'N/A'} Mbps / ↑ ${throughput.uploadMbps ?? 'N/A'} Mbps\n`;
      report += `  (This is the current NIC transfer rate, not a speed test. Run Speed & Stability for true throughput.)\n`;
      if (externalPing) report += `Internet Latency:    ${externalPing.latency || 'N/A'} (${externalPing.loss || 'N/A'})\n`;
      if (dnsTime) report += `DNS Resolution:      ${dnsTime.time || dnsTime.latency || 'N/A'}\n`;
      report += `\n`;
    }

    if (deviceHealth && !deviceHealth.error) {
      report += `── SYSTEM RESOURCES ───────────────────────────────────\n`;
      report += `CPU Load:            ${deviceHealth.cpuLoad ?? 'N/A'}%\n`;
      report += `Memory:              ${deviceHealth.memUsedGB ?? 'N/A'} / ${deviceHealth.memTotalGB ?? 'N/A'} GB (${deviceHealth.memUsedPercent ?? 'N/A'}%)\n`;
      if (deviceHealth.hasBattery) {
        report += `Battery:             ${deviceHealth.batteryPercent ?? 'N/A'}% ${deviceHealth.onBattery ? '(on battery)' : '(plugged in)'}\n`;
      }
      report += `\n`;
    }

    report += `── LOCAL NETWORK HEALTH ───────────────────────────────\n`;
    const gw = gatewayHealth || gatewayPing;
    if (gatewayHealth) {
      report += `Gateway:             ${gatewayHealth.gateway || 'N/A'}\n`;
      report += `Avg Latency:         ${gatewayHealth.avg ?? gatewayHealth.latency ?? 'N/A'} ms\n`;
      report += `Min / Max:           ${gatewayHealth.min ?? 'N/A'} / ${gatewayHealth.max ?? 'N/A'} ms\n`;
      report += `Jitter:              ${gatewayHealth.jitter ?? 'N/A'}\n`;
      report += `Packet Loss:         ${gatewayHealth.loss ?? 'N/A'}\n`;
      report += `Verdict:             ${gatewayHealth.verdict || 'N/A'}\n\n`;
    } else {
      report += `Gateway Latency:     ${gw?.latency || 'N/A'}\n`;
      report += `Gateway Loss:        ${gw?.loss || 'N/A'}\n`;
      report += `Gateway Jitter:      ${gw?.jitter || 'N/A'}\n\n`;
    }

    if (speedDiag?.phases) {
      const p = speedDiag.phases;
      report += `── CONNECTION SPEED & PHASES ──────────────────────────\n`;
      report += `DNS Lookup:          ${p.dnsLookupMs ?? 'N/A'} ms\n`;
      report += `TCP Connect:         ${p.tcpConnectMs ?? 'N/A'} ms\n`;
      report += `TLS Handshake:       ${p.tlsHandshakeMs ?? 'N/A'} ms\n`;
      report += `Time To First Byte:  ${p.ttfbMs ?? 'N/A'} ms\n`;
      report += `Total:               ${p.totalMs ?? 'N/A'} ms\n`;
      report += `Single-stream:       ${p.downloadMbps ?? 'N/A'} Mbps  (one connection - lower than line speed; see CDN Speed Test below)\n`;
      if (speedDiag.bufferbloat) {
        report += `Bufferbloat Grade:   ${speedDiag.bufferbloat.grade}: ${speedDiag.bufferbloat.verdict}\n`;
        report += `  Idle Latency:      ${speedDiag.bufferbloat.idleLatency} ms\n`;
        report += `  Loaded Latency:    ${speedDiag.bufferbloat.loadedLatency} ms (+${speedDiag.bufferbloat.increase} ms)\n`;
      }
      report += `\n`;
    }

    if (routeTrace?.hops?.length) {
      report += `── ROUTE TRACE (${routeTrace.target}) ───────────────────────\n`;
      routeTrace.hops.forEach(h => {
        const loc = [h.city, h.country].filter(Boolean).join(', ');
        report += `  ${String(h.hop).padStart(2)}. ${(h.ip || '*').padEnd(16)} ${h.timeout ? 'timeout' : (h.avg + ' ms').padStart(8)}  ${h.isp || ''}${loc ? ' (' + loc + ')' : ''}\n`;
      });
      if (routeTrace.analysis) report += `Analysis:            ${routeTrace.analysis}\n`;
      report += `\n`;
    }

    if (stabilityResult) {
      report += `── CONNECTION STABILITY ───────────────────────────────\n`;
      report += `Rating:              ${stabilityResult.label}\n`;
      report += `Samples:             ${stabilityResult.total ?? 'N/A'}\n`;
      report += `Drops / Reconnects:  ${stabilityResult.drops ?? 'N/A'} / ${stabilityResult.reconnects ?? 'N/A'}\n`;
      report += `Avg / Min / Max:     ${stabilityResult.avg ?? 'N/A'} / ${stabilityResult.min ?? 'N/A'} / ${stabilityResult.max ?? 'N/A'} ms\n`;
      report += `Jitter:              ${stabilityResult.jitter ?? 'N/A'} ms\n`;
      report += `Packet Loss:         ${stabilityResult.lossPct ?? 'N/A'}%\n\n`;
    }

    if (globalPing) {
      report += `── MULTI-REGION LATENCY ───────────────────────────────\n`;
      if (globalPing.localExchange?.target) {
        report += `Local Exchange:      ${globalPing.localExchange.latency} (${globalPing.localExchange.target})\n`;
      }
      report += `Singapore:           ${globalPing.singapore?.latency || 'N/A'}\n`;
      report += `US East:             ${globalPing.usEast?.latency || 'N/A'}\n`;
      report += `US West:             ${globalPing.usWest?.latency || 'N/A'}\n\n`;
    }

    if (cdnSpeedTest) {
      report += `── CDN SPEED TEST (multi-stream) ──────────────────────\n`;
      report += `Download Speed:      ${cdnSpeedTest.speedMbps} Mbps  (${cdnSpeedTest.connections || 6} parallel streams, sustained)\n`;
      if (cdnSpeedTest.peakMbps) report += `Peak:                ${cdnSpeedTest.peakMbps} Mbps\n`;
      report += `Data Downloaded:     ${(cdnSpeedTest.bytesDownloaded / 1000000).toFixed(1)} MB\n`;
      report += `Duration:            ${cdnSpeedTest.duration}s\n\n`;
    }

    if (mitmCheck) {
      report += `── SECURITY POSTURE ───────────────────────────────────\n`;
      report += `MITM Risk:           ${mitmCheck.risk}\n`;
      report += `Analysis:            ${mitmCheck.analysis}\n\n`;
    }

    const dnsBench = dnsBenchmark || healthBreakdown?.dnsBenchmark;
    if (dnsBench?.results?.length) {
      report += `── DNS RESOLVER BENCHMARK ─────────────────────────────\n`;
      dnsBench.results.forEach(r => {
        let t = r.status === 'ok' && r.time != null ? `${r.time} ms` : 'timeout';
        // Values over 200 ms from a parallel test are likely first-run cache misses
        // or resolver slowness - annotate so the reader isn't misled
        if (r.status === 'ok' && r.time > 200) t += ' ⚠ slow (possible cache miss or resolver congestion)';
        report += `  ${(r.name || '').padEnd(12)} ${(r.ip || '').padEnd(16)} ${t.padStart(10)}\n`;
      });
      if (dnsBench.fastest) {
        report += `Fastest:             ${dnsBench.fastest.name} (${dnsBench.fastest.ip}) - ${dnsBench.fastest.time} ms\n`;
      }
      report += `\n`;
    }

    if (portScan?.openPorts?.length) {
      report += `── OPEN LISTENING PORTS (local) ───────────────────────\n`;
      report += `${portScan.openPorts.join(', ')}\n\n`;
    }

    if (devices?.devices?.length || arpCount) {
      report += `── LAN DEVICES ────────────────────────────────────────\n`;
      report += `Devices on network:  ${devices?.devices?.length ?? arpCount ?? 'N/A'}\n`;
      if (devices?.devices?.length) {
        devices.devices.slice(0, 20).forEach(d => {
          report += `  ${(d.ip || '').padEnd(16)} ${(d.mac || '').padEnd(18)} ${d.vendor || ''}\n`;
        });
      }
      report += `\n`;
    }

    if (dnsHijack || dnsLeak || arpSpoof) {
      report += `── THREAT CHECKS ──────────────────────────────────────\n`;
      if (dnsHijack) report += `DNS Hijacking:       ${dnsHijack.status || dnsHijack.risk || 'N/A'}\n`;
      if (dnsLeak) report += `DNS Leak:            ${dnsLeak.status || dnsLeak.risk || 'N/A'}\n`;
      if (arpSpoof) report += `ARP Spoofing:        ${arpSpoof.status || arpSpoof.risk || 'N/A'}\n`;
      report += `\n`;
    }

    if (healthBreakdown?.categories) {
      const c = healthBreakdown.categories;
      const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
      report += `── HEALTH SCORES ──────────────────────────────────────\n`;
      report += `Overall:             ${healthBreakdown.overall}/100\n`;
      Object.entries(c).forEach(([k, v]) => {
        report += `  ${cap(k).padEnd(16)} ${v}/100\n`;
      });
      if (healthBreakdown.recommendations?.length) {
        report += `\nRecommendations:\n`;
        healthBreakdown.recommendations.forEach(r => { report += `  • ${r.text}\n`; });
      }
      report += `\n`;
    } else {
      const stability = computeStability();
      if (stability) {
        report += `── HEALTH SCORES ──────────────────────────────────────\n`;
        report += `Overall:             ${stability.score}/100 (${stability.label})\n`;
        report += `Local Link:          ${stability.localScore}/100\n`;
        report += `ISP Routing:         ${stability.ispScore}/100\n`;
        report += `(Run the Health Check tab for the full category breakdown.)\n\n`;
      }
    }

    report += `═══════════════════════════════════════════════════════\n`;
    return report;
  };

  const fetchBasicStats = () => {
    fetch(`${API_BASE}/basic`)
      .then(res => res.json())
      .then(data => { setBasicStats(data); setLoadingBasic(false); })
      .catch(err => { console.error(err); setLoadingBasic(false); });
  };

  const fetchThroughput = () => {
    fetch(`${API_BASE}/throughput`).then(res => res.json()).then(setThroughput).catch(console.error);
  };

  const fetchPings = () => {
    fetch(`${API_BASE}/ping-gateway`).then(r => r.json()).then(setGatewayPing).catch(console.error);
    fetch(`${API_BASE}/ping-external`).then(r => r.json()).then(setExternalPing).catch(console.error);
    fetch(`${API_BASE}/dns-time`).then(r => r.json()).then(setDnsTime).catch(console.error);
  };

  const fetchPublicIp = () => {
    fetch(`${API_BASE}/public-ip`).then(r => r.json()).then(setPublicIp).catch(console.error);
  };

  useEffect(() => {
    // Phase 1 - instant, zero-subprocess calls only (basic stats + public IP + toolbar)
    fetchBasicStats();
    fetchPublicIp();
    fetchThroughput();
    fetchToolbarStatus();
    fetchWslStatus();
    fetchWifiCapabilities();

    // Phase 2 - first ping wave + active interface (light subprocess usage)
    const t1 = setTimeout(() => {
      fetchPings();          // gateway + external ping + DNS time
      fetchActiveInterface();
      fetchWifiAnalysis();
      fetchDeviceHealth();
    }, 800);

    // Phase 3 - medium scans
    const t2 = setTimeout(() => {
      fetchArpCount();
      fetchGatewayHealth();
      fetchGlobalPing();
      fetchDnsHijack();
      fetchMitmCheck();
      fetchDevices();
    }, 2500);

    // Phase 4 - heavy security scans last so the UI is already responsive
    const t3 = setTimeout(() => {
      fetchSecurityScan();
      fetchArpSpoof();
      fetchDnsLeak();
      fetchWifiAudit();
    }, 5000);

    const throughputInterval = setInterval(fetchThroughput, 1000);
    const basicInterval = setInterval(fetchBasicStats, 5000);
    const pingInterval = setInterval(fetchPings, 8000);
    const ipInterval = setInterval(fetchPublicIp, 120000);
    const arpInterval = setInterval(fetchArpCount, 60000);
    const globalPingInterval = setInterval(fetchGlobalPing, 45000);
    const dnsHijackInterval = setInterval(fetchDnsHijack, 60000);
    const securityInterval = setInterval(fetchSecurityScan, 120000);
    const arpSpoofInterval = setInterval(fetchArpSpoof, 60000);
    const mitmInterval = setInterval(fetchMitmCheck, 120000);
    const ifaceInterval = setInterval(fetchActiveInterface, 60000);
    const gwHealthInterval = setInterval(fetchGatewayHealth, 60000);
    const wifiAnalysisInterval = setInterval(fetchWifiAnalysis, 20000);
    const deviceHealthInterval = setInterval(fetchDeviceHealth, 20000);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearInterval(throughputInterval);
      clearInterval(basicInterval);
      clearInterval(pingInterval);
      clearInterval(ipInterval);
      clearInterval(arpInterval);
      clearInterval(globalPingInterval);
      clearInterval(dnsHijackInterval);
      clearInterval(securityInterval);
      clearInterval(arpSpoofInterval);
      clearInterval(mitmInterval);
      clearInterval(ifaceInterval);
      clearInterval(gwHealthInterval);
      clearInterval(wifiAnalysisInterval);
      clearInterval(deviceHealthInterval);
      clearTimeout(opacityTimer.current);
    };
  }, []);

  // ── Auto-populate router admin IP from gateway ──────────────────────────
  useEffect(() => {
    const gw = basicStats?.ip?.defaultGateway;
    if (gw && !routerAdminIp) setRouterAdminIp(gw);
  }, [basicStats?.ip?.defaultGateway]);

  // ── Trends: load history + record a snapshot every 30s ────────────────────
  useEffect(() => {
    try {
      const raw = localStorage.getItem('nd_trends');
      if (raw) setTrends(JSON.parse(raw));
    } catch { /* ignore */ }

    const recordTrend = () => {
      const dl = parseFloat(throughputRef.current?.downloadMbps);
      const ul = parseFloat(throughputRef.current?.uploadMbps);
      const lat = parseInt((externalPingRef.current?.latency || '').match(/(\d+)/)?.[1]);
      const lossM = (externalPingRef.current?.loss || '').match(/(\d+)%/);
      const sig = parseInt(basicStatsRef.current?.wifi?.signalQuality);
      const point = {
        t: Date.now(),
        dl: isNaN(dl) ? null : dl,
        ul: isNaN(ul) ? null : ul,
        lat: isNaN(lat) ? null : lat,
        loss: lossM ? parseInt(lossM[1]) : null,
        sig: isNaN(sig) ? null : sig,
      };
      setTrends(prev => {
        const next = [...prev, point].slice(-200);
        try { localStorage.setItem('nd_trends', JSON.stringify(next)); } catch { /* ignore */ }
        return next;
      });
    };

    const trendInterval = setInterval(recordTrend, 30000);
    return () => clearInterval(trendInterval);
  }, []);

  const getSignalIndicator = (percentString) => {
    if (!percentString || percentString === 'N/A') return 'indicator-red';
    const val = parseInt(percentString);
    if (val >= 70) return 'indicator-green';
    if (val >= 40) return 'indicator-yellow';
    return 'indicator-red';
  };

  const getThroughputIndicator = (mbps) => {
    if (!mbps || mbps === '0.00' || mbps === 'Error') return 'indicator-yellow';
    return 'indicator-green';
  };

  const computeStability = () => {
    if (!externalPing || !basicStats || !gatewayPing) return null;
    let localScore = 100, ispScore = 100;

    const sig = parseInt(basicStats.wifi?.signalQuality) || 100;
    if (sig < 40) localScore -= 30; else if (sig < 60) localScore -= 15; else if (sig < 70) localScore -= 5;

    const gwMatch = (gatewayPing?.latency || '').match(/^(\d+)/);
    const gwMs = gwMatch ? parseInt(gwMatch[1]) : 0;
    if (gwMs > 10) localScore -= 10; else if (gwMs > 5) localScore -= 5;

    const lossMatch = (externalPing.loss || '').match(/(\d+)%/);
    ispScore -= (lossMatch ? parseInt(lossMatch[1]) : 0) * 4;

    const jitterMatch = (externalPing.jitter || '').match(/^([\d.]+)/);
    const jitter = jitterMatch ? parseFloat(jitterMatch[1]) : 0;
    if (jitter > 50) ispScore -= 25; else if (jitter > 30) ispScore -= 15; else if (jitter > 15) ispScore -= 8;

    const pingMatch = (externalPing.latency || '').match(/^(\d+)/);
    const ping = pingMatch ? parseInt(pingMatch[1]) : 0;
    if (ping > 200) ispScore -= 20; else if (ping > 100) ispScore -= 10; else if (ping > 70) ispScore -= 5;

    localScore = Math.max(0, Math.min(100, localScore));
    ispScore = Math.max(0, Math.min(100, ispScore));
    const score = Math.round((localScore * 0.3) + (ispScore * 0.7));

    let label, cls;
    if (score >= 90) { label = 'Excellent'; cls = 'success'; }
    else if (score >= 70) { label = 'Good'; cls = 'highlight'; }
    else if (score >= 50) { label = 'Fair'; cls = ''; }
    else { label = 'Poor'; cls = 'error'; }

    return { score, label, cls, localScore, ispScore };
  };

  const stability = computeStability();
  const navItems = NAV_ITEMS.filter(n => !n.wslOnly || wslStatus?.installed);
  const activeNavItem = NAV_ITEMS.find(n => n.id === activeTab);

  return (
    <div className={`app-shell ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      {/* ═════════════ SIDEBAR ═════════════ */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">⏚</div>
          {!sidebarCollapsed && (
            <div className="brand-text">
              <div className="brand-title">Network</div>
              <div className="brand-subtitle">Detector</div>
            </div>
          )}
        </div>

        <nav className="sidebar-nav">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              title={item.label}
            >
              <span className="nav-icon">{item.icon}</span>
              {!sidebarCollapsed && (
                <span className="nav-text">
                  <span className="nav-label">{item.label}</span>
                  <span className="nav-desc">{item.desc}</span>
                </span>
              )}
              {activeTab === item.id && <span className="nav-indicator"></span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <button className="sidebar-collapse-btn" onClick={() => setSidebarCollapsed(!sidebarCollapsed)} title={sidebarCollapsed ? 'Expand' : 'Collapse'}>
            {sidebarCollapsed ? '›' : '‹'}
          </button>
          {!sidebarCollapsed && (
            <div className="sidebar-status">
              <span className={`status-dot ${basicStats?.wifi?.status === 'Operational' ? 'online' : 'offline'}`}></span>
              <span className="status-label">{basicStats?.wifi?.status === 'Operational' ? 'Connected' : 'Offline'}</span>
            </div>
          )}
        </div>
      </aside>

      {/* ═════════════ MAIN ═════════════ */}
      <main className="main-area">
        <header className="main-header">
          <div className="header-left">
            <h1 className="page-title">
              <span className="page-icon">{activeNavItem?.icon}</span>
              {activeNavItem?.label}
            </h1>
            <p className="page-subtitle">{activeNavItem?.desc}</p>
          </div>
          <div className="header-right">
            <button className="action-btn evidence-btn" onClick={copyEvidenceReport} title="Copy Evidence Report">
              ⎘ Copy Report
            </button>
            <button className="action-btn export-btn" onClick={exportJson} title="Export as JSON">
              ⤓ JSON
            </button>
            <button className="action-btn export-btn" onClick={exportMarkdown} title="Export as Markdown">
              ⤓ MD
            </button>
            {showEvidenceReport && <div className="copy-notification">✓ Copied!</div>}
            <div className="toolbar-controls">
              <div className="opacity-control">
                <span className="ctrl-label">Opacity</span>
                <input
                  type="range" min="20" max="100" step="5" value={toolbarOpacity}
                  className="opacity-slider"
                  onChange={(e) => handleOpacityChange(parseInt(e.target.value))}
                />
                <span className="ctrl-label">{toolbarOpacity}%</span>
              </div>
              <button className={`toolbar-ctrl-btn ${toolbarVisible ? 'ctrl-on' : ''}`} onClick={toggleToolbar}>
                {toolbarVisible ? 'Toolbar ON' : 'Toolbar OFF'}
              </button>
              <button className={`toolbar-ctrl-btn ${toolbarPinned ? 'ctrl-on' : ''}`} onClick={togglePin}>
                {toolbarPinned ? 'TOP ON' : 'TOP OFF'}
              </button>
            </div>
          </div>
        </header>

        {loadingBasic ? (
          <div className="loader-container"><div className="loader"></div></div>
        ) : (
          <div className="tab-content">
            {/* ─── OVERVIEW ─── */}
            {activeTab === 'overview' && (
              <div className="dashboard">
                <StatusCard title="Connection Overview" className="stagger-1"
                  data={[
                    { label: 'Connection Type', value: activeInterface?.type || basicStats?.wifi?.connectionType || 'Detecting...', className: 'highlight' },
                    { label: 'Active Adapter', value: activeInterface?.name || basicStats?.wifi?.interfaceName || 'N/A' },
                    { label: 'Adapter Detail', value: activeInterface?.description || basicStats?.wifi?.description || 'N/A' },
                    { label: 'Status', value: activeInterface?.status || basicStats?.wifi?.status || 'N/A', className: (activeInterface?.status === 'Up' || basicStats?.wifi?.status === 'Operational') ? 'success' : '' },
                    { label: 'Link Speed', value: activeInterface?.linkSpeed || basicStats?.wifi?.linkSpeed || 'N/A' },
                    { label: 'MAC Address', value: activeInterface?.mac || basicStats?.wifi?.macAddress || 'N/A' },
                    { label: 'VPN Active', value: activeInterface?.isVpn ? '✓ Yes' : '✗ No', className: activeInterface?.isVpn ? 'highlight' : '' },
                  ]}
                />
                <StatusCard title="Wi-Fi Info" className="stagger-2"
                  data={[
                    { label: 'SSID', value: basicStats.wifi?.ssid || 'N/A', className: 'highlight' },
                    { label: 'BSSID', value: basicStats.wifi?.bssid || 'N/A' },
                    { label: 'Protocol', value: basicStats.wifi?.protocol || 'N/A' },
                    { label: 'Band / Channel', value: basicStats.wifi?.radioBand || 'N/A' },
                    { label: 'Signal Quality', value: <><span className={`indicator-dot ${getSignalIndicator(basicStats.wifi?.signalQuality)}`}></span>{basicStats.wifi?.signalQuality || 'N/A'}</> },
                    { label: 'Link Speed', value: basicStats.wifi?.linkSpeed || 'N/A' },
                    { label: 'Authentication', value: basicStats.wifi?.authentication || 'N/A' },
                  ]}
                />
                <StatusCard title="Live Bandwidth" className="stagger-3"
                  data={[
                    { label: 'Download Speed', value: throughput ? <><span className={`indicator-dot ${getThroughputIndicator(throughput.downloadMbps)}`}></span>{throughput.downloadMbps} Mbps</> : 'Loading...', className: 'highlight' },
                    { label: 'Upload Speed', value: throughput ? <><span className={`indicator-dot ${getThroughputIndicator(throughput.uploadMbps)}`}></span>{throughput.uploadMbps} Mbps</> : 'Loading...', className: 'highlight' },
                  ]}
                />
                <StatusCard title="IP & DHCP" className="stagger-4"
                  data={[
                    { label: 'IPv4 Address', value: basicStats.ip?.ipv4 || 'N/A', className: 'highlight' },
                    { label: 'Subnet Mask', value: basicStats.ip?.subnetMask || 'N/A' },
                    { label: 'Default Gateway', value: basicStats.ip?.defaultGateway || 'N/A' },
                    { label: 'DHCP Server', value: basicStats.ip?.dhcpServer || 'N/A' },
                    { label: 'DNS Servers', value: basicStats.ip?.dnsServers || 'N/A' },
                  ]}
                />
                <StatusCard title="Latency & Ping" className="stagger-5"
                  data={[
                    { label: 'Gateway Latency', value: gatewayPing ? `${gatewayPing.latency} (Loss: ${gatewayPing.loss})` : 'Loading...' },
                    { label: 'External (8.8.8.8)', value: externalPing ? `${externalPing.latency} (Loss: ${externalPing.loss})` : 'Loading...' },
                    { label: 'DNS Resolution', value: dnsTime ? dnsTime.time : 'Resolving...' },
                    { label: 'Gateway Jitter', value: gatewayPing?.jitter || 'Loading...' },
                    { label: 'External Jitter', value: externalPing?.jitter || 'Loading...' },
                  ]}
                />
                <StatusCard title="Public Details" className="stagger-6"
                  data={[
                    { label: 'Public IPv4', value: publicIp ? publicIp.ip : 'Loading...', className: 'highlight' },
                    { label: 'ISP / ASN', value: publicIp?.org || 'Loading...' },
                    { label: 'Location', value: publicIp?.city && publicIp?.country ? `${publicIp.city}, ${publicIp.country}` : (publicIp ? 'N/A' : 'Loading...') },
                    { label: 'Timezone', value: publicIp?.timezone || (publicIp ? 'N/A' : 'Loading...') },
                  ]}
                />
                <StatusCard title="Connection Health" className="stagger-7"
                  data={[
                    { label: 'Overall Score', value: stability ? `${stability.score}/100 · ${stability.label}` : 'Calculating...', className: stability?.cls || '' },
                    { label: '├─ Local Link', value: stability ? `${stability.localScore}/100` : 'N/A', className: stability?.localScore >= 80 ? 'success' : '' },
                    { label: '└─ ISP Routing', value: stability ? `${stability.ispScore}/100` : 'N/A', className: stability?.ispScore >= 80 ? 'success' : (stability?.ispScore < 50 ? 'error' : '') },
                    { label: 'LAN Devices', value: arpCount !== null ? `${arpCount} on network` : 'Scanning...' },
                    { label: 'Connection Type', value: basicStats?.wifi?.connectionType || 'N/A' },
                  ]}
                />
                <StatusCard title="Device Health" className="stagger-8"
                  data={
                    deviceHealth ? [
                      { label: 'CPU Load', value: `${deviceHealth.cpuLoad}%`, className: deviceHealth.cpuLoad > 85 ? 'error' : 'success' },
                      { label: 'Memory Used', value: `${deviceHealth.memUsedGB} / ${deviceHealth.memTotalGB} GB (${deviceHealth.memUsedPercent}%)`, className: deviceHealth.memUsedPercent > 90 ? 'error' : '' },
                      { label: 'Power Source', value: deviceHealth.hasBattery ? (deviceHealth.onBattery ? `🔋 Battery ${deviceHealth.batteryPercent}%` : '🔌 Plugged In') : '🔌 Desktop' , className: deviceHealth.onBattery ? 'error' : 'success' },
                      ...(deviceHealth.recommendations?.slice(0, 2).map((r, i) => ({ label: i === 0 ? 'Note' : ' ', value: r })) || []),
                    ] : [{ label: 'Status', value: 'Reading system...' }]
                  }
                />
              </div>
            )}

            {/* ─── WI-FI ANALYZER ─── */}
            {activeTab === 'wifi-analyzer' && (
              <div className="dashboard">
                <StatusCard title="Wi-Fi Signal Analysis" className="stagger-1"
                  data={
                    wifiAnalysis ? (wifiAnalysis.connected ? [
                      { label: 'SSID', value: wifiAnalysis.ssid || 'N/A', className: 'highlight' },
                      { label: 'BSSID', value: wifiAnalysis.bssid || 'N/A' },
                      { label: 'Active Band', value: wifiAnalysis.band || 'N/A', className: wifiAnalysis.band === '2.4 GHz' ? '' : 'success' },
                      { label: 'Adapter Supports', value: wifiCapabilities?.supportedBands?.join(' + ') || '…', className: wifiCapabilities?.isDualBand ? 'success' : '' },
                      { label: 'Channel', value: wifiAnalysis.channel || 'N/A' },
                      { label: 'Signal', value: wifiAnalysis.signalPercent || 'N/A', className: parseInt(wifiAnalysis.signalPercent) >= 70 ? 'success' : (parseInt(wifiAnalysis.signalPercent) < 40 ? 'error' : '') },
                      { label: 'RSSI', value: wifiAnalysis.rssi || 'N/A' },
                      { label: 'Standard', value: wifiAnalysis.standard || 'N/A' },
                    ] : [{ label: 'Status', value: 'Not connected to Wi-Fi (Ethernet/VPN active)' }]) : [{ label: 'Status', value: 'Analyzing...' }]
                  }
                />
                <StatusCard title="Link Rates & Security" className="stagger-2"
                  data={
                    wifiAnalysis && wifiAnalysis.connected ? [
                      { label: 'Receive Rate', value: wifiAnalysis.rxRate || 'N/A', className: 'highlight' },
                      { label: 'Transmit Rate', value: wifiAnalysis.txRate || 'N/A', className: 'highlight' },
                      { label: 'Authentication', value: wifiAnalysis.auth || 'N/A' },
                      { label: 'Cipher', value: wifiAnalysis.cipher || 'N/A' },
                      { label: 'RSSI Guide', value: '> -50 Excellent · -60 Good · -70 Fair · < -80 Poor' },
                    ] : [{ label: 'Status', value: wifiAnalysis ? 'No active Wi-Fi link' : 'Analyzing...' }]
                  }
                />
                <StatusCard title="Channel Interference Scan" className="stagger-3"
                  data={
                    wifiScan ? [
                      { label: 'Nearby Networks', value: wifiScan.totalNetworks, className: 'highlight' },
                      { label: 'Recommendation', value: wifiScan.recommendation, className: 'success' },
                      ...Object.entries(wifiScan.channelUsage || {}).sort((a, b) => b[1] - a[1]).slice(0, 5)
                        .map(([ch, cnt]) => ({ label: `Channel ${ch}`, value: `${cnt} network${cnt > 1 ? 's' : ''}`, className: cnt >= 4 ? 'error' : (cnt >= 2 ? '' : 'success') })),
                      { label: '', value: (<button className="cdn-test-btn" onClick={runWifiScan} disabled={wifiScanLoading}>{wifiScanLoading ? 'Scanning...' : '↻ Rescan Networks'}</button>) },
                    ] : [
                      { label: 'Status', value: 'Scan nearby Wi-Fi to find the clearest channel' },
                      { label: '', value: (<button className="cdn-test-btn" onClick={runWifiScan} disabled={wifiScanLoading}>{wifiScanLoading ? 'Scanning...' : 'Scan Nearby Networks'}</button>) },
                    ]
                  }
                />
                {/* Nearby Networks - placed before the full-width notice so it fills the grid gap */}
                {wifiScan && wifiScan.networks?.length > 0 && (
                  <StatusCard title={`Nearby Networks (Top ${Math.min(8, wifiScan.networks.length)})`} className="stagger-4"
                    data={wifiScan.networks.slice(0, 8).map(n => ({
                      label: n.ssid || '(hidden)',
                      value: `Ch ${n.channel ?? '?'} · ${n.band || '?'} · ${n.signal ?? '?'}%`,
                      className: (n.signal || 0) >= 70 ? 'success' : ''
                    }))}
                  />
                )}
                {/* Dual-band capability notice (full width, rendered last) */}
                {wifiCapabilities?.isDualBand && wifiAnalysis?.connected && wifiAnalysis?.band === '2.4 GHz' && (
                  <div className="full-width-card stagger-5" style={{ borderLeft: '3px solid #f59e0b' }}>
                    <h3 className="diag-title" style={{ color: '#f59e0b' }}>⚠ You can connect at 5 GHz</h3>
                    <p className="diag-sub">Your <strong>{wifiCapabilities.driver || 'Wi-Fi adapter'}</strong> supports {wifiCapabilities.supportedBands.join(' + ')}, but you're currently on <strong>2.4 GHz</strong>. 5 GHz offers higher throughput and far less interference. Open your router admin page, enable the 5 GHz SSID, and connect to it on this device.</p>
                    <button className="export-btn" style={{ marginTop: '10px' }} onClick={openRouterAdmin}>Open Router Admin ({routerAdminIp || basicStats?.ip?.defaultGateway || '…'})</button>
                  </div>
                )}
              </div>
            )}

            {/* ─── HEALTH & TIPS ─── */}
            {activeTab === 'health' && (
              <div className="health-view">
                <div className="health-actions">
                  <button className="cdn-test-btn" onClick={runHealthBreakdown} disabled={healthLoading}>
                    {healthLoading ? 'Analyzing Network...' : (healthBreakdown ? '↻ Re-run Full Analysis' : '▶ Run Full Health Analysis')}
                  </button>
                  <button className="cdn-test-btn" onClick={runDnsBenchmark} disabled={dnsBenchLoading}>
                    {dnsBenchLoading ? 'Benchmarking DNS...' : '⚡ Benchmark DNS'}
                  </button>
                </div>

                {healthBreakdown?.categories && (
                  <div className="score-grid">
                    {Object.entries({
                      overall: healthBreakdown.overall,
                      ...healthBreakdown.categories
                    }).map(([k, v]) => (
                      <div key={k} className={`score-tile ${v >= 85 ? 'good' : v >= 60 ? 'warn' : 'bad'} ${k === 'overall' ? 'score-overall' : ''}`}>
                        <div className="score-num">{v}</div>
                        <div className="score-label">{k.charAt(0).toUpperCase() + k.slice(1)}</div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="dashboard">
                  {healthBreakdown?.recommendations && (
                    <StatusCard title="Intelligent Recommendations" className="stagger-1"
                      data={healthBreakdown.recommendations.map((r, i) => ({
                        label: r.type === 'good' ? '✓' : (r.type === 'bad' ? '✗' : '⚠'),
                        value: r.text,
                        className: r.type === 'good' ? 'success' : (r.type === 'bad' ? 'error' : '')
                      }))}
                    />
                  )}

                  <StatusCard title="DNS Provider Benchmark" className="stagger-2"
                    data={
                      dnsBenchmark ? [
                        ...dnsBenchmark.results.map(r => ({
                          label: `${r.name} (${r.ip})`,
                          value: r.status === 'ok' ? `${r.time} ms` : '✗ Unreachable',
                          className: dnsBenchmark.fastest && r.ip === dnsBenchmark.fastest.ip ? 'success' : (r.status === 'fail' ? 'error' : '')
                        })),
                        { label: 'Recommendation', value: dnsBenchmark.recommendation, className: 'highlight' },
                      ] : [{ label: 'Status', value: 'Click "Benchmark DNS" to compare resolvers' }]
                    }
                  />

                  <StatusCard title="Local Network Health (Detailed)" className="stagger-3"
                    data={
                      gatewayHealth && gatewayHealth.avg !== 'N/A' ? [
                        { label: 'Gateway', value: gatewayHealth.gateway || 'N/A', className: 'highlight' },
                        { label: 'Average', value: `${gatewayHealth.avg} ms`, className: gatewayHealth.cls === 'good' ? 'success' : (gatewayHealth.cls === 'bad' ? 'error' : '') },
                        { label: 'Min / Max', value: `${gatewayHealth.min} ms / ${gatewayHealth.max} ms` },
                        { label: 'Median / p95', value: `${gatewayHealth.median} ms / ${gatewayHealth.p95} ms` },
                        { label: 'Jitter', value: `${gatewayHealth.jitter} ms` },
                        { label: 'Packet Loss', value: gatewayHealth.loss, className: parseInt(gatewayHealth.loss) > 0 ? 'error' : 'success' },
                        { label: 'Verdict', value: gatewayHealth.verdict, className: gatewayHealth.cls === 'good' ? 'success' : (gatewayHealth.cls === 'bad' ? 'error' : '') },
                      ] : [{ label: 'Status', value: 'Measuring gateway (20 pings)...' }]
                    }
                  />

                  <StatusCard title="Device Health" className="stagger-4"
                    data={
                      deviceHealth ? [
                        { label: 'CPU Load', value: `${deviceHealth.cpuLoad}%`, className: deviceHealth.cpuLoad > 85 ? 'error' : 'success' },
                        { label: 'Memory', value: `${deviceHealth.memUsedGB} / ${deviceHealth.memTotalGB} GB (${deviceHealth.memUsedPercent}%)`, className: deviceHealth.memUsedPercent > 90 ? 'error' : '' },
                        { label: 'Power', value: deviceHealth.hasBattery ? (deviceHealth.onBattery ? `🔋 Battery ${deviceHealth.batteryPercent}%` : '🔌 Plugged In') : '🔌 Desktop', className: deviceHealth.onBattery ? 'error' : 'success' },
                        ...(deviceHealth.recommendations?.map((r, i) => ({ label: `Tip ${i + 1}`, value: r })) || []),
                      ] : [{ label: 'Status', value: 'Reading system...' }]
                    }
                  />
                </div>
              </div>
            )}

            {/* ─── ISP TRUTH ─── */}
            {activeTab === 'isp-detector' && (
              <div className="dashboard">
                <StatusCard title="Multi-Region Latency Matrix" className="stagger-1"
                  data={
                    globalPing ? [
                      globalPing.localExchange?.target && { label: 'Local Exchange', value: `${globalPing.localExchange.latency} (${globalPing.localExchange.target})`, className: 'highlight' },
                      globalPing.localExchange?.target && { label: '  ↳ Loss / Jitter', value: `${globalPing.localExchange.loss} / ${globalPing.localExchange.jitter}` },
                      { label: 'Singapore (Cloudflare)', value: globalPing.singapore?.latency || 'N/A' },
                      { label: '  ↳ Loss / Jitter', value: `${globalPing.singapore?.loss || 'N/A'} / ${globalPing.singapore?.jitter || 'N/A'}` },
                      { label: 'US East (Google)', value: globalPing.usEast?.latency || 'N/A' },
                      { label: '  ↳ Loss / Jitter', value: `${globalPing.usEast?.loss || 'N/A'} / ${globalPing.usEast?.jitter || 'N/A'}` },
                      { label: 'US West (OpenDNS)', value: globalPing.usWest?.latency || 'N/A' },
                      { label: '  ↳ Loss / Jitter', value: `${globalPing.usWest?.loss || 'N/A'} / ${globalPing.usWest?.jitter || 'N/A'}` },
                    ].filter(Boolean) : [{ label: 'Status', value: 'Loading matrix...' }]
                  }
                />
                <StatusCard title="True CDN Speed Test" className="stagger-2"
                  data={[
                    cdnSpeedTest ? { label: 'Download Speed', value: `${cdnSpeedTest.speedMbps} Mbps`, className: 'highlight' } : null,
                    cdnSpeedTest && cdnSpeedTest.peakMbps ? { label: 'Peak', value: `${cdnSpeedTest.peakMbps} Mbps`, className: 'success' } : null,
                    cdnSpeedTest ? { label: 'Test Server', value: cdnSpeedTest.testServer } : null,
                    cdnSpeedTest ? { label: 'Duration', value: `${cdnSpeedTest.duration}s` } : null,
                    cdnSpeedTest ? { label: 'Data Downloaded', value: `${(cdnSpeedTest.bytesDownloaded / 1000000).toFixed(1)} MB` } : null,
                    cdnSpeedTest ? { label: 'Status', value: cdnSpeedTest.success ? '✓ Success' : `✗ ${cdnSpeedTest.error}`, className: cdnSpeedTest.success ? 'success' : 'error' } : null,
                    { label: 'Note', value: 'Uses 6 parallel streams (sustained trimmed mean). Speeds vary with Wi-Fi band, distance, and server load.' },
                    { label: '', value: (<button className="cdn-test-btn" onClick={runCdnSpeedTest} disabled={cdnTestLoading}>{cdnTestLoading ? 'Testing...' : (cdnSpeedTest ? 'Run Again' : 'Run CDN Speed Test')}</button>) },
                  ].filter(Boolean)}
                />
                <StatusCard title="DNS Hijacking Detector" className="stagger-3"
                  data={
                    dnsHijack ? [
                      { label: 'Analysis', value: dnsHijack.analysis, className: dnsHijack.hijackDetected ? 'error' : 'success' },
                      { label: 'System DNS IP', value: dnsHijack.systemDns.ip || dnsHijack.systemDns.error },
                      { label: 'System DNS Time', value: `${dnsHijack.systemDns.time}ms` },
                      { label: 'DoH IP', value: dnsHijack.doh.ip || dnsHijack.doh.error },
                      { label: 'DoH Time', value: `${dnsHijack.doh.time}ms` },
                    ] : [{ label: 'Status', value: 'Checking...' }]
                  }
                />
                <StatusCard title="ISP Performance Analysis" className="stagger-4"
                  data={[
                    { label: 'Overall Score', value: stability ? `${stability.score}/100` : 'Calculating...', className: stability?.cls || '' },
                    { label: 'ISP Routing Health', value: stability ? `${stability.ispScore}/100` : 'N/A', className: stability?.ispScore >= 80 ? 'success' : (stability?.ispScore < 50 ? 'error' : '') },
                    { label: 'External Latency', value: externalPing?.latency || 'N/A' },
                    { label: 'Packet Loss', value: externalPing?.loss || 'N/A' },
                    { label: 'Jitter', value: externalPing?.jitter || 'N/A' },
                  ]}
                />
              </div>
            )}

            {/* ─── SECURITY ─── */}
            {activeTab === 'security' && (
              <div className="dashboard">
                <StatusCard title="MITM Attack Check" className="stagger-1"
                  data={
                    mitmCheck ? [
                      { label: 'Status', value: mitmCheck.analysis, className: mitmCheck.mitmDetected ? 'error' : 'success' },
                      { label: 'Risk Level', value: mitmCheck.risk, className: mitmCheck.risk === 'Critical' || mitmCheck.risk === 'High' ? 'error' : 'success' },
                      { label: 'ARP Spoofing', value: mitmCheck.details?.arpSpoofing ? '⚠️ Detected' : '✓ Clean', className: mitmCheck.details?.arpSpoofing ? 'error' : 'success' },
                      { label: 'DNS Hijacking', value: mitmCheck.details?.dnsHijacking ? '⚠️ Detected' : '✓ Clean', className: mitmCheck.details?.dnsHijacking ? 'error' : 'success' },
                      { label: 'Certificate Issues', value: mitmCheck.details?.certificateMismatch ? '⚠️ Found' : '✓ Valid', className: mitmCheck.details?.certificateMismatch ? 'error' : 'success' },
                    ] : [{ label: 'Status', value: 'Running MITM check...' }]
                  }
                />

                <StatusCard title="ARP Spoofing Detector" className="stagger-2"
                  data={
                    arpSpoof ? [
                      { label: 'Analysis', value: arpSpoof.analysis, className: arpSpoof.spoofingDetected ? 'error' : 'success' },
                      { label: 'Risk', value: arpSpoof.risk, className: arpSpoof.risk === 'High' ? 'error' : 'success' },
                      { label: 'Duplicate MACs', value: arpSpoof.duplicateMacs?.length || 0, className: (arpSpoof.duplicateMacs?.length || 0) > 0 ? 'error' : 'success' },
                      ...(arpSpoof.suspiciousEntries?.slice(0, 3).map((e, i) => ({ label: `Entry ${i + 1}`, value: e })) || []),
                    ] : [{ label: 'Status', value: 'Scanning ARP table...' }]
                  }
                />

                <StatusCard title="Wi-Fi Security Audit" className="stagger-3"
                  data={
                    wifiAudit ? [
                      { label: 'Strength', value: `${wifiAudit.strengthScore}/100 · ${wifiAudit.strengthLabel}`, className: wifiAudit.strengthScore >= 80 ? 'success' : (wifiAudit.strengthScore < 50 ? 'error' : '') },
                      { label: 'Encryption', value: wifiAudit.encryption || 'Unknown' },
                      { label: 'Cipher', value: wifiAudit.cipher || 'Unknown' },
                      ...(wifiAudit.vulnerabilities?.length > 0
                        ? wifiAudit.vulnerabilities.map((v, i) => ({ label: `⚠ Vuln ${i + 1}`, value: v, className: 'error' }))
                        : [{ label: 'Vulnerabilities', value: '✓ None', className: 'success' }]),
                      ...(wifiAudit.recommendations?.slice(0, 2).map((r, i) => ({ label: `Tip ${i + 1}`, value: r })) || []),
                    ] : [{ label: 'Status', value: 'Auditing Wi-Fi...' }]
                  }
                />

                <StatusCard title="DNS Leak Test" className="stagger-4"
                  data={
                    dnsLeak ? [
                      { label: 'Analysis', value: dnsLeak.analysis, className: dnsLeak.leakDetected ? 'error' : 'success' },
                      { label: 'Risk', value: dnsLeak.risk, className: dnsLeak.risk === 'High' ? 'error' : (dnsLeak.risk === 'Medium' ? '' : 'success') },
                      { label: 'Configured DNS', value: dnsLeak.configuredDns?.join(', ') || 'None' },
                      { label: 'Public IP', value: dnsLeak.publicIp || 'N/A' },
                    ] : [{ label: 'Status', value: 'Testing for leaks...' }]
                  }
                />

                <StatusCard title="Open Ports Scan" className="stagger-5"
                  data={
                    portScan ? [
                      { label: 'Scan Status', value: portScan.success ? '✓ Complete' : `✗ ${portScan.error}`, className: portScan.success ? 'success' : 'error' },
                      portScan.openPorts && { label: 'Open Ports', value: portScan.openPorts.length, className: portScan.openPorts.length > 10 ? 'error' : 'success' },
                      portScan.openPorts && portScan.openPorts.length > 0 && { label: 'Ports', value: portScan.openPorts.slice(0, 20).join(', ') + (portScan.openPorts.length > 20 ? '...' : '') },
                      { label: '', value: (<button className="cdn-test-btn" onClick={runPortScan} disabled={portScanLoading}>{portScanLoading ? 'Scanning...' : (portScan ? 'Scan Again' : 'Run Port Scan')}</button>) },
                    ].filter(Boolean) : [
                      { label: 'Status', value: 'Not scanned yet' },
                      { label: '', value: (<button className="cdn-test-btn" onClick={runPortScan} disabled={portScanLoading}>{portScanLoading ? 'Scanning...' : 'Run Port Scan'}</button>) },
                    ]
                  }
                />

                <StatusCard title="Firewall & System Security" className="stagger-6"
                  data={
                    securityScan ? [
                      { label: 'Security Status', value: securityScan.status, className: securityScan.status === 'Secure' ? 'success' : 'error' },
                      { label: 'Firewall', value: securityScan.firewall, className: securityScan.firewall?.includes('Enabled') ? 'success' : 'error' },
                      { label: 'VPN Detected', value: securityScan.vpnDetected ? '✓ Active' : '✗ None' },
                      { label: 'Proxy Detected', value: securityScan.proxyDetected ? '✓ Active' : '✗ None' },
                      { label: 'Overall Risk', value: securityScan.riskLevel, className: securityScan.riskLevel === 'High' ? 'error' : (securityScan.riskLevel === 'Medium' ? '' : 'success') },
                    ] : [{ label: 'Status', value: 'Scanning system...' }]
                  }
                />

                <StatusCard title="SSL/TLS Security" className="stagger-7"
                  data={
                    securityScan?.ssl ? [
                      { label: 'HTTPS Support', value: securityScan.ssl.httpsSupport ? '✓ Enabled' : '✗ Disabled', className: securityScan.ssl.httpsSupport ? 'success' : 'error' },
                      { label: 'Certificate Valid', value: securityScan.ssl.certValid ? '✓ Yes' : '✗ No' },
                      { label: 'TLS Version', value: securityScan.ssl.tlsVersion || 'Unknown' },
                    ] : [{ label: 'Status', value: 'Checking SSL/TLS...' }]
                  }
                />

                <StatusCard title="Network Encryption" className="stagger-8"
                  data={[
                    { label: 'Wi-Fi Encryption', value: basicStats.wifi?.authentication || 'N/A' },
                    { label: 'DNS Security', value: dnsHijack?.hijackDetected ? '⚠️ Compromised' : '✓ Secure', className: dnsHijack?.hijackDetected ? 'error' : 'success' },
                    { label: 'Data Protection', value: basicStats.wifi?.authentication?.includes('WPA') ? '✓ Strong' : '⚠️ Weak', className: basicStats.wifi?.authentication?.includes('WPA') ? 'success' : 'error' },
                  ]}
                />
              </div>
            )}

            {/* ─── DEVICES ─── */}
            {activeTab === 'devices' && (
              <div className="devices-view">
                <div className="devices-toolbar">
                  <div className="devices-summary">
                    <div className="summary-pill">
                      <span className="summary-num">{devices?.totalCount ?? 'N/A'}</span>
                      <span className="summary-lbl">Devices</span>
                    </div>
                    <div className="summary-pill">
                      <span className="summary-num">{devices?.gateway || 'N/A'}</span>
                      <span className="summary-lbl">Gateway</span>
                    </div>
                    {arpSpoof && (
                      <div className={`summary-pill ${arpSpoof.spoofingDetected ? 'pill-danger' : 'pill-success'}`}>
                        <span className="summary-num">{arpSpoof.spoofingDetected ? '⚠' : '✓'}</span>
                        <span className="summary-lbl">ARP Health</span>
                      </div>
                    )}
                  </div>
                  <button className="cdn-test-btn" onClick={fetchDevices} disabled={devicesLoading}>
                    {devicesLoading ? 'Scanning...' : '↻ Rescan'}
                  </button>
                </div>

                {!devices && <div className="loader-container"><div className="loader"></div></div>}

                {devices && devices.devices?.length === 0 && (
                  <div className="empty-state">No devices found in ARP table. Try pinging your network first.</div>
                )}

                {devices && devices.devices?.length > 0 && (
                  <div className="devices-grid">
                    {devices.devices.map((d, i) => (
                      <div key={d.mac + i} className={`device-card ${d.isGateway ? 'is-gateway' : ''}`} style={{ animationDelay: `${i * 0.04}s` }}>
                        <div className="device-header">
                          <div className="device-role">{d.role}</div>
                          <div className={`device-type-badge ${d.type === 'Dynamic' ? 'badge-blue' : 'badge-amber'}`}>{d.type}</div>
                        </div>
                        <div className="device-ip">{d.ip}</div>
                        <div className="device-rows">
                          <div className="device-row"><span>MAC</span><code>{d.mac}</code></div>
                          <div className="device-row"><span>Vendor</span><span>{d.vendor}</span></div>
                          <div className="device-row"><span>Hostname</span><span className="device-host">{d.hostname}</span></div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* ── Router Admin Panel ── */}
                <div className="full-width-card" style={{ marginTop: '1.5rem' }}>
                  <h3 className="diag-title">Router Admin: Deep Device Scan</h3>
                  <p className="diag-sub" style={{ marginBottom: '12px' }}>
                    Enter your router admin credentials to fetch the complete connected device list directly from the router (more thorough than ARP). Credentials are saved locally on this device only.
                  </p>
                  <div className="route-controls" style={{ flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
                    <input className="route-input" value={routerAdminIp} onChange={e => setRouterAdminIp(e.target.value)} placeholder="Router IP (e.g. 192.168.1.1)" style={{ width: '190px' }} />
                    <input className="route-input" value={routerAdminUser} onChange={e => setRouterAdminUser(e.target.value)} placeholder="Username (admin)" style={{ width: '140px' }} />
                    <input className="route-input" type="password" value={routerAdminPass} onChange={e => setRouterAdminPass(e.target.value)} placeholder="Password" style={{ width: '140px' }} />
                    <button className="cdn-test-btn" onClick={fetchRouterDevices} disabled={routerDevicesLoading}>{routerDevicesLoading ? 'Fetching…' : 'Fetch Devices'}</button>
                    <button className="export-btn" onClick={openRouterAdmin} title="Open router admin in browser">Open Admin Page</button>
                  </div>
                  {routerDevicesLoading && <div className="loader-inline"><div className="loader"></div><span>Connecting to router…</span></div>}
                  {routerDevices && !routerDevices.success && (
                    <p className="diag-error">{routerDevices.error || 'Failed'}{routerDevices.tip ? `. ${routerDevices.tip}` : ''}</p>
                  )}
                  {routerDevices?.success && routerDevices.devices?.length > 0 && (
                    <>
                      <p className="route-analysis">✅ {routerDevices.brand}: {routerDevices.devices.length} device{routerDevices.devices.length !== 1 ? 's' : ''} found</p>
                      <div className="route-table" style={{ marginTop: '8px' }}>
                        <div className="route-head"><span className="rh-ip">IP</span><span className="rh-isp">MAC / Vendor</span><span className="rh-lat">Type</span></div>
                        {routerDevices.devices.map((d, i) => (
                          <div className="route-line" key={i}>
                            <span className="rh-ip">{d.ip}{d.hostname !== 'N/A' ? ` (${d.hostname})` : ''}</span>
                            <span className="rh-isp">{d.mac !== 'N/A' ? d.mac : 'N/A'}</span>
                            <span className="rh-lat">{d.type || 'N/A'}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                  {routerDevices?.success && routerDevices.devices?.length === 0 && (
                    <p className="diag-placeholder">Router responded but returned no device data. Model may use a different API. Try opening the admin page manually.</p>
                  )}
                </div>
              </div>
            )}

            {/* ─── DIAGNOSTICS ─── */}
            {activeTab === 'diagnostics' && (
              <div className="dashboard">
                <StatusCard title="Network Interface" className="stagger-1"
                  data={[
                    { label: 'Interface Name', value: basicStats.wifi?.interfaceName || 'N/A' },
                    { label: 'Description', value: basicStats.wifi?.description || 'N/A' },
                    { label: 'MAC Address', value: basicStats.wifi?.macAddress || 'N/A' },
                    { label: 'Connection Type', value: basicStats.wifi?.connectionType || 'N/A' },
                    { label: 'Status', value: basicStats.wifi?.status || 'N/A' },
                  ]}
                />
                <StatusCard title="DHCP Information" className="stagger-2"
                  data={[
                    { label: 'DHCP Server', value: basicStats.ip?.dhcpServer || 'N/A' },
                    { label: 'Lease Obtained', value: basicStats.ip?.leaseObtained || 'N/A' },
                    { label: 'Lease Expires', value: basicStats.ip?.leaseExpires || 'N/A' },
                    { label: 'IPv4 Address', value: basicStats.ip?.ipv4 || 'N/A' },
                    { label: 'Subnet Mask', value: basicStats.ip?.subnetMask || 'N/A' },
                  ]}
                />
                <StatusCard title="DNS Configuration" className="stagger-3"
                  data={[
                    { label: 'DNS Servers', value: basicStats.ip?.dnsServers || 'N/A' },
                    { label: 'Resolution Time', value: dnsTime ? dnsTime.time : 'Measuring...' },
                    { label: 'DNS Hijacking', value: dnsHijack?.hijackDetected ? '⚠️ Detected' : '✓ None', className: dnsHijack?.hijackDetected ? 'error' : 'success' },
                    { label: 'DoH Status', value: dnsHijack?.doh?.ip ? '✓ Available' : '✗ Unavailable' },
                  ]}
                />
                <StatusCard title="Performance Metrics" className="stagger-4"
                  data={[
                    { label: 'Download (Current)', value: throughput ? `${throughput.downloadMbps} Mbps` : 'Measuring...' },
                    { label: 'Upload (Current)', value: throughput ? `${throughput.uploadMbps} Mbps` : 'Measuring...' },
                    { label: 'Link Speed (Max)', value: basicStats.wifi?.linkSpeed || 'N/A' },
                    { label: 'Signal Quality', value: basicStats.wifi?.signalQuality || 'N/A' },
                  ]}
                />
                <StatusCard title="Network Devices" className="stagger-5"
                  data={[
                    { label: 'Devices on Network', value: arpCount !== null ? `${arpCount} devices` : 'Counting...' },
                    { label: 'Default Gateway', value: basicStats.ip?.defaultGateway || 'N/A' },
                    { label: 'BSSID (Router MAC)', value: basicStats.wifi?.bssid || 'N/A' },
                  ]}
                />
                <StatusCard title="Wireless Details" className="stagger-6"
                  data={[
                    { label: 'SSID', value: basicStats.wifi?.ssid || 'N/A' },
                    { label: 'Radio Type', value: basicStats.wifi?.protocol || 'N/A' },
                    { label: 'Channel', value: basicStats.wifi?.radioBand || 'N/A' },
                    { label: 'Authentication', value: basicStats.wifi?.authentication || 'N/A' },
                    { label: 'Signal Quality', value: basicStats.wifi?.signalQuality || 'N/A' },
                  ]}
                />
              </div>
            )}

            {/* ─── SPEED & STABILITY ─── */}
            {activeTab === 'speed-stability' && (
              <div className="dashboard">
                <div className="full-width-card stagger-1">
                  <div className="diag-card-header">
                    <div>
                      <h3 className="diag-title">Connection Phase Breakdown</h3>
                      <p className="diag-sub">Times each stage of a real download: DNS, TCP, TLS, first byte. Reveals exactly where slowness comes from.</p>
                    </div>
                    <button className="cdn-test-btn" onClick={runSpeedDiagnostics} disabled={speedDiagLoading}>
                      {speedDiagLoading ? 'Testing…' : 'Run Speed Test'}
                    </button>
                  </div>
                  {speedDiagLoading && <div className="loader-inline"><div className="loader"></div><span>Downloading test file & measuring latency under load…</span></div>}
                  {speedDiag?.phases && !speedDiag.phases.error && (
                    <>
                      <div className="phase-row">
                        <div className="phase-pill"><span className="phase-num">{speedDiag.phases.dnsLookupMs}</span><span className="phase-lbl">DNS ms</span></div>
                        <div className="phase-arrow">→</div>
                        <div className="phase-pill"><span className="phase-num">{speedDiag.phases.tcpConnectMs}</span><span className="phase-lbl">TCP ms</span></div>
                        <div className="phase-arrow">→</div>
                        <div className="phase-pill"><span className="phase-num">{speedDiag.phases.tlsHandshakeMs}</span><span className="phase-lbl">TLS ms</span></div>
                        <div className="phase-arrow">→</div>
                        <div className="phase-pill"><span className="phase-num">{speedDiag.phases.ttfbMs}</span><span className="phase-lbl">First byte ms</span></div>
                      </div>
                      <div className="score-grid" style={{ marginTop: '16px' }}>
                        <div className="score-tile"><div className="score-tile-val highlight">{speedDiag.phases.downloadMbps}</div><div className="score-tile-lbl">Single-stream Mbps</div></div>
                        <div className="score-tile"><div className="score-tile-val">{speedDiag.phases.totalMs}</div><div className="score-tile-lbl">Total ms</div></div>
                      </div>
                      <p className="diag-sub" style={{ marginTop: '10px' }}>Single-stream throughput is limited by one TCP connection and is normally lower than your line speed. For your real download speed, use the multi-stream <strong>True CDN Speed Test</strong> on the ISP Truth tab.</p>
                    </>
                  )}
                  {speedDiag?.phases?.error && <p className="diag-error">Speed test failed: {speedDiag.phases.error}</p>}
                </div>

                {speedDiag?.bufferbloat && !speedDiag.bufferbloat.error && (
                  <StatusCard title="Bufferbloat (Latency Under Load)" className="stagger-2"
                    data={[
                      { label: 'Grade', value: `${speedDiag.bufferbloat.grade}: ${speedDiag.bufferbloat.verdict}`, className: speedDiag.bufferbloat.grade === 'A' || speedDiag.bufferbloat.grade === 'B' ? 'success' : speedDiag.bufferbloat.grade === 'F' ? 'error' : 'highlight' },
                      { label: 'Idle Latency', value: `${speedDiag.bufferbloat.idleLatency} ms` },
                      { label: 'Latency Under Load', value: `${speedDiag.bufferbloat.loadedLatency} ms` },
                      { label: 'Increase', value: `+${speedDiag.bufferbloat.increase} ms`, className: parseFloat(speedDiag.bufferbloat.increase) > 100 ? 'error' : '' },
                    ]}
                  />
                )}

                <div className="full-width-card stagger-3">
                  <div className="diag-card-header">
                    <div>
                      <h3 className="diag-title">60-Second Stability Test</h3>
                      <p className="diag-sub">Pings every second for one minute to catch micro-drops and reconnects you'd otherwise miss.</p>
                    </div>
                    <button className={`cdn-test-btn ${stabilityRunning ? 'danger' : ''}`} onClick={startStabilityTest}>
                      {stabilityRunning ? `Stop (${stabilityProgress}%)` : 'Start 60s Test'}
                    </button>
                  </div>
                  {(stabilityRunning || stabilitySamples.length > 0) && (
                    <>
                      {stabilityRunning && (
                        <div className="progress-track"><div className="progress-fill" style={{ width: `${stabilityProgress}%` }}></div></div>
                      )}
                      <StabilityGraph samples={stabilitySamples} />
                    </>
                  )}
                  {stabilityResult && (
                    <div className="score-grid" style={{ marginTop: '16px' }}>
                      <div className="score-tile"><div className={`score-tile-val ${stabilityResult.cls}`}>{stabilityResult.label.split(': ')[0]}</div><div className="score-tile-lbl">{stabilityResult.label.split(': ')[1] || 'Verdict'}</div></div>
                      <div className="score-tile"><div className="score-tile-val">{stabilityResult.drops}</div><div className="score-tile-lbl">Drops</div></div>
                      <div className="score-tile"><div className="score-tile-val">{stabilityResult.reconnects}</div><div className="score-tile-lbl">Reconnects</div></div>
                      <div className="score-tile"><div className="score-tile-val">{stabilityResult.avg}</div><div className="score-tile-lbl">Avg ms</div></div>
                      <div className="score-tile"><div className="score-tile-val">{stabilityResult.jitter}</div><div className="score-tile-lbl">Jitter ms</div></div>
                      <div className="score-tile"><div className="score-tile-val">{stabilityResult.lossPct}%</div><div className="score-tile-lbl">Packet Loss</div></div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ─── ROUTE TRACE ─── */}
            {activeTab === 'route-trace' && (
              <div className="dashboard">
                <div className="full-width-card stagger-1">
                  <div className="diag-card-header">
                    <div>
                      <h3 className="diag-title">Hop-by-Hop Route Analysis</h3>
                      <p className="diag-sub">Traces the path your traffic takes to a destination and geolocates each public hop, so you can see where latency builds up - your network, your ISP, or beyond.</p>
                    </div>
                    <div className="route-controls">
                      <input className="route-input" value={routeTarget} onChange={e => setRouteTarget(e.target.value)} placeholder="8.8.8.8 or host" />
                      <button className="cdn-test-btn" onClick={runRouteTrace} disabled={routeTraceLoading}>
                        {routeTraceLoading ? 'Tracing…' : 'Trace Route'}
                      </button>
                    </div>
                  </div>
                  {routeTraceLoading && <div className="loader-inline"><div className="loader"></div><span>Tracing route & geolocating hops…</span></div>}
                  {routeTrace?.error && <p className="diag-error">{routeTrace.error}</p>}
                  {routeTrace?.hops?.length > 0 && (
                    <>
                      <div className="route-table">
                        <div className="route-head">
                          <span className="rh-hop">#</span>
                          <span className="rh-ip">IP Address</span>
                          <span className="rh-lat">Latency</span>
                          <span className="rh-isp">Network / Location</span>
                        </div>
                        {routeTrace.hops.map(h => (
                          <div className={`route-line ${h.timeout ? 'timeout' : ''}`} key={h.hop}>
                            <span className="rh-hop">{h.hop}</span>
                            <span className="rh-ip">{h.ip}</span>
                            <span className={`rh-lat ${h.avg && parseFloat(h.avg) > 100 ? 'warn' : ''}`}>{h.timeout ? '✕ timeout' : `${h.avg} ms`}</span>
                            <span className="rh-isp">{h.isp || (h.timeout ? 'N/A' : '…')}{h.city ? ` · ${h.city}` : ''}{h.country ? `, ${h.country}` : ''}</span>
                          </div>
                        ))}
                      </div>
                      {routeTrace.analysis && <p className="route-analysis">💡 {routeTrace.analysis}</p>}
                    </>
                  )}
                  {!routeTrace && !routeTraceLoading && <p className="diag-placeholder">Enter a target and click Trace Route to map the path.</p>}
                </div>
              </div>
            )}

            {/* ─── TRENDS ─── */}
            {activeTab === 'trends' && (
              <div className="dashboard">
                <div className="full-width-card stagger-1">
                  <div className="diag-card-header">
                    <div>
                      <h3 className="diag-title">Performance History</h3>
                      <p className="diag-sub">Automatically samples your connection every 30 seconds (stored locally on this device) so you can spot patterns and recurring drop-outs over time.</p>
                    </div>
                    <button className="cdn-test-btn danger" onClick={() => { setTrends([]); try { localStorage.removeItem('nd_trends'); } catch { /* ignore */ } }}>
                      Clear History
                    </button>
                  </div>
                  {trends.length < 2 ? (
                    <p className="diag-placeholder">Collecting data… keep the app open. Graphs appear after a couple of samples (≈1 minute).</p>
                  ) : (
                    <div className="trend-grid">
                      <TrendChart title="Download" unit="Mbps" color="#22d3ee" points={trends.map(p => p.dl)} times={trends.map(p => p.t)} />
                      <TrendChart title="Upload" unit="Mbps" color="#a78bfa" points={trends.map(p => p.ul)} times={trends.map(p => p.t)} />
                      <TrendChart title="Latency" unit="ms" color="#f59e0b" points={trends.map(p => p.lat)} times={trends.map(p => p.t)} invert />
                      <TrendChart title="Wi-Fi Signal" unit="%" color="#10b981" points={trends.map(p => p.sig)} times={trends.map(p => p.t)} />
                    </div>
                  )}
                  {trends.length >= 2 && (
                    <div className="trend-meta">{trends.length} samples · oldest {new Date(trends[0].t).toLocaleString()}</div>
                  )}
                </div>
              </div>
            )}

            {/* ─── WSL TOOLS ─── */}
            {activeTab === 'wsl-tools' && (
              <div className="dashboard">
                <StatusCard title="WSL Environment" className="stagger-1"
                  data={[
                    { label: 'WSL Installed', value: wslStatus?.installed ? '✓ Yes' : '✗ No', className: wslStatus?.installed ? 'success' : 'error' },
                    { label: 'Active Distro', value: wslStatus?.distro || 'N/A', className: 'highlight' },
                    { label: 'mtr', value: !wslStatus?.toolsChecked ? 'N/A' : (wslStatus?.tools?.mtr ? '✓' : '✗'), className: wslStatus?.tools?.mtr ? 'success' : '' },
                    { label: 'dig', value: !wslStatus?.toolsChecked ? 'N/A' : (wslStatus?.tools?.dig ? '✓' : '✗'), className: wslStatus?.tools?.dig ? 'success' : '' },
                    { label: 'traceroute', value: !wslStatus?.toolsChecked ? 'N/A' : (wslStatus?.tools?.traceroute ? '✓' : '✗'), className: wslStatus?.tools?.traceroute ? 'success' : '' },
                    { label: 'nmap', value: !wslStatus?.toolsChecked ? 'N/A' : (wslStatus?.tools?.nmap ? '✓' : '✗'), className: wslStatus?.tools?.nmap ? 'success' : '' },
                    { label: 'curl', value: !wslStatus?.toolsChecked ? 'N/A' : (wslStatus?.tools?.curl ? '✓' : '✗'), className: wslStatus?.tools?.curl ? 'success' : '' },
                  ]}
                />

                {wslStatus?.installed && !wslStatus?.toolsChecked && (
                  <div className="full-width-card stagger-2">
                    <h3 className="diag-title">Check Linux Networking Tools</h3>
                    <p className="diag-sub">Detecting which tools are installed will briefly start your WSL distro (a console window may flash for a second). Click below when you're ready.</p>
                    <button className="export-btn" style={{ marginTop: '12px' }} onClick={() => checkWslTools(false)} disabled={wslToolsLoading}>{wslToolsLoading ? 'Checking…' : '🔍 Detect Linux Tools'}</button>
                  </div>
                )}

                {wslStatus?.toolsChecked && !wslStatus.anyToolAvailable && (
                  <div className="full-width-card stagger-2">
                    <h3 className="diag-title">Unlock Advanced Linux Tools</h3>
                    <p className="diag-sub">Run this once inside your Ubuntu/WSL terminal to enable mtr, traceroute, nmap, dig (DNSSEC), curl (HTTP inspection), and more:</p>
                    <div className="install-cmd">
                      <code>{wslStatus.installCommand || 'sudo apt update && sudo apt install -y mtr-tiny dnsutils traceroute nmap curl'}</code>
                      <button className="cdn-test-btn" onClick={copyWslInstall}>{wslInstallCopied ? '✓ Copied' : 'Copy'}</button>
                    </div>
                    <button className="export-btn" style={{ marginTop: '12px' }} onClick={() => checkWslTools(true)} disabled={wslToolsLoading}>{wslToolsLoading ? 'Re-checking…' : '↻ Re-check after installing'}</button>
                  </div>
                )}

                {wslStatus?.tools?.mtr && (
                  <div className="full-width-card stagger-3">
                    <div className="diag-card-header">
                      <div>
                        <h3 className="diag-title">mtr - Live Route Quality</h3>
                        <p className="diag-sub">Combines traceroute + ping to show per-hop packet loss and latency. The best tool for proving where loss occurs.</p>
                      </div>
                      <div className="route-controls">
                        <input className="route-input" value={wslMtrTarget} onChange={e => setWslMtrTarget(e.target.value)} placeholder="8.8.8.8" />
                        <button className="cdn-test-btn" onClick={runWslMtr} disabled={wslMtrLoading}>{wslMtrLoading ? 'Running…' : 'Run mtr'}</button>
                      </div>
                    </div>
                    {wslMtrLoading && <div className="loader-inline"><div className="loader"></div><span>Running mtr report (10 cycles)…</span></div>}
                    {wslMtrData?.error && <p className="diag-error">{wslMtrData.error}</p>}
                    {wslMtrData?.hops?.length > 0 && (
                      <div className="route-table">
                        <div className="route-head">
                          <span className="rh-hop">#</span>
                          <span className="rh-ip">Host</span>
                          <span className="rh-lat">Loss%</span>
                          <span className="rh-isp">Avg / Best / Worst ms</span>
                        </div>
                        {wslMtrData.hops.map(h => (
                          <div className={`route-line ${parseFloat(h.loss) > 0 ? 'timeout' : ''}`} key={h.hop}>
                            <span className="rh-hop">{h.hop}</span>
                            <span className="rh-ip">{h.host}</span>
                            <span className={`rh-lat ${parseFloat(h.loss) > 0 ? 'warn' : ''}`}>{h.loss}%</span>
                            <span className="rh-isp">{h.avg} / {h.best} / {h.worst}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {wslStatus?.tools?.dig && (
                  <div className="full-width-card stagger-4">
                    <div className="diag-card-header">
                      <div>
                        <h3 className="diag-title">dig - DNSSEC Validation</h3>
                        <p className="diag-sub">Checks whether DNS answers are cryptographically signed (DNSSEC), proving they weren't tampered with in transit.</p>
                      </div>
                      <div className="route-controls">
                        <input className="route-input" value={wslDigDomain} onChange={e => setWslDigDomain(e.target.value)} placeholder="cloudflare.com" />
                        <button className="cdn-test-btn" onClick={runWslDig} disabled={wslDigLoading}>{wslDigLoading ? 'Querying…' : 'Run dig'}</button>
                      </div>
                    </div>
                    {wslDigLoading && <div className="loader-inline"><div className="loader"></div><span>Querying DNS with DNSSEC…</span></div>}
                    {wslDigData?.error && <p className="diag-error">{wslDigData.error}</p>}
                    {wslDigData?.available === false && <p className="diag-error">{wslDigData.reason}</p>}
                    {wslDigData && wslDigData.available !== false && !wslDigData.error && (
                      <>
                        <div className="score-grid" style={{ marginTop: '8px' }}>
                          <div className="score-tile"><div className={`score-tile-val ${wslDigData.authenticated ? 'success' : ''}`}>{wslDigData.authenticated ? '✓ Validated' : (wslDigData.dnssecSigned ? '~ Signed' : '✗ Unsigned')}</div><div className="score-tile-lbl">DNSSEC (AD flag)</div></div>
                          <div className="score-tile"><div className="score-tile-val">{wslDigData.dnssecSigned ? 'Yes' : 'No'}</div><div className="score-tile-lbl">RRSIG present</div></div>
                          <div className="score-tile"><div className="score-tile-val highlight">{(wslDigData.answers && wslDigData.answers.length) || 0}</div><div className="score-tile-lbl">Answers</div></div>
                        </div>
                        {wslDigData.analysis && <p className="route-analysis">{wslDigData.analysis}</p>}
                      </>
                    )}
                  </div>
                )}

                {/* ── Traceroute (UDP, reveals ICMP-filtered hops) ── */}
                {wslStatus?.tools?.traceroute && (
                  <div className="full-width-card stagger-5">
                    <div className="diag-card-header">
                      <div>
                        <h3 className="diag-title">traceroute - UDP Path Analysis</h3>
                        <p className="diag-sub">Uses UDP probes (not ICMP like Windows tracert). Reveals hops that block ICMP but allow UDP traffic.</p>
                      </div>
                      <div className="route-controls">
                        <input className="route-input" value={wslTracerouteTarget} onChange={e => setWslTracerouteTarget(e.target.value)} placeholder="8.8.8.8" />
                        <button className="cdn-test-btn" onClick={runWslTraceroute} disabled={wslTracerouteLoading}>{wslTracerouteLoading ? 'Running…' : 'Run traceroute'}</button>
                      </div>
                    </div>
                    {wslTracerouteLoading && <div className="loader-inline"><div className="loader"></div><span>Tracing route…</span></div>}
                    {wslTracerouteData?.hops?.length > 0 && (
                      <div className="route-table">
                        <div className="route-head"><span className="rh-hop">#</span><span className="rh-ip">IP</span><span className="rh-lat">Avg ms</span></div>
                        {wslTracerouteData.hops.map(h => (
                          <div className={`route-line ${h.timeout ? 'timeout' : ''}`} key={h.hop}>
                            <span className="rh-hop">{h.hop}</span>
                            <span className="rh-ip">{h.ip}</span>
                            <span className="rh-lat">{h.timeout ? '* * *' : (h.avg + ' ms')}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {wslTracerouteData?.available === false && <p className="diag-error">{wslTracerouteData.reason}</p>}
                  </div>
                )}

                {/* ── Nmap LAN scan ── */}
                {wslStatus?.tools?.nmap && (
                  <div className="full-width-card stagger-5">
                    <div className="diag-card-header">
                      <div>
                        <h3 className="diag-title">nmap - LAN Device Discovery</h3>
                        <p className="diag-sub">Scans the local subnet using multiple probe types. More thorough than the ARP-based scan - discovers phones, TVs, and clients with isolation enabled.</p>
                      </div>
                      <div className="route-controls">
                        <input className="route-input" value={wslNmapSubnet} onChange={e => setWslNmapSubnet(e.target.value)} placeholder="auto (gateway /24)" style={{ width: '180px' }} />
                        <button className="cdn-test-btn" onClick={runWslNmap} disabled={wslNmapLoading}>{wslNmapLoading ? 'Scanning…' : 'Scan LAN'}</button>
                      </div>
                    </div>
                    {wslNmapLoading && <div className="loader-inline"><div className="loader"></div><span>Scanning subnet (up to 90s)…</span></div>}
                    {wslNmapData?.hosts?.length > 0 && (
                      <div className="route-table">
                        <div className="route-head"><span className="rh-ip">IP</span><span className="rh-isp">MAC / Vendor</span><span className="rh-lat">Latency</span></div>
                        {wslNmapData.hosts.map((h, i) => (
                          <div className="route-line" key={i}>
                            <span className="rh-ip">{h.ip}{h.hostname !== 'N/A' ? ` (${h.hostname})` : ''}</span>
                            <span className="rh-isp">{h.mac !== 'N/A' ? `${h.mac} - ${h.vendor}` : h.vendor}</span>
                            <span className="rh-lat">{h.latency || 'N/A'}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {wslNmapData?.hosts?.length === 0 && <p className="diag-placeholder">No live hosts found. Try specifying subnet manually (e.g. 192.168.1.0/24).</p>}
                    {wslNmapData?.available === false && <p className="diag-error">{wslNmapData.reason}</p>}
                  </div>
                )}

                {/* ── IPv6 connectivity test ── */}
                {wslStatus?.installed && (
                  <div className="full-width-card stagger-5">
                    <div className="diag-card-header">
                      <div>
                        <h3 className="diag-title">IPv6 Connectivity Test</h3>
                        <p className="diag-sub">Checks whether your connection supports IPv6 - required for modern services and better privacy than IPv4-only NAT.</p>
                      </div>
                      <button className="cdn-test-btn" onClick={runWslIpv6} disabled={wslIpv6Loading}>{wslIpv6Loading ? 'Testing…' : 'Test IPv6'}</button>
                    </div>
                    {wslIpv6Loading && <div className="loader-inline"><div className="loader"></div><span>Testing IPv6 connectivity…</span></div>}
                    {wslIpv6Data && (
                      <>
                        <p className="route-analysis">{wslIpv6Data.summary}</p>
                        {wslIpv6Data.addresses?.length > 0 && (
                          <div className="route-table" style={{ marginTop: '8px' }}>
                            {wslIpv6Data.addresses.map((a, i) => <div className="route-line" key={i}><span className="rh-ip">{a}</span></div>)}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {/* ── HTTP header inspection ── */}
                {wslStatus?.tools?.curl && (
                  <div className="full-width-card stagger-5">
                    <div className="diag-card-header">
                      <div>
                        <h3 className="diag-title">HTTP Header Inspector</h3>
                        <p className="diag-sub">Fetches HTTP response headers to detect ISP proxy injection, CDN/edge server, and privacy-relevant fields.</p>
                      </div>
                      <div className="route-controls">
                        <input className="route-input" value={wslHttpUrl} onChange={e => setWslHttpUrl(e.target.value)} placeholder="https://cloudflare.com" style={{ width: '220px' }} />
                        <button className="cdn-test-btn" onClick={runWslHttp} disabled={wslHttpLoading}>{wslHttpLoading ? 'Fetching…' : 'Inspect'}</button>
                      </div>
                    </div>
                    {wslHttpLoading && <div className="loader-inline"><div className="loader"></div><span>Fetching headers…</span></div>}
                    {wslHttpData?.available !== false && wslHttpData && (
                      <>
                        <p className="route-analysis">{wslHttpData.analysis}</p>
                        <div className="score-grid" style={{ marginTop: '8px' }}>
                          <div className="score-tile"><div className="score-tile-val highlight">{wslHttpData.status || 'N/A'}</div><div className="score-tile-lbl">HTTP Status</div></div>
                          <div className="score-tile"><div className="score-tile-val">{wslHttpData.cdn || 'N/A'}</div><div className="score-tile-lbl">Server / CDN</div></div>
                          <div className="score-tile"><div className={`score-tile-val ${wslHttpData.suspiciousHeaders?.length ? 'error' : 'success'}`}>{wslHttpData.suspiciousHeaders?.length || 0}</div><div className="score-tile-lbl">Suspicious headers</div></div>
                        </div>
                        {Object.keys(wslHttpData.headers || {}).length > 0 && (
                          <div className="route-table" style={{ marginTop: '8px', fontSize: '0.78rem' }}>
                            {Object.entries(wslHttpData.headers).slice(0, 12).map(([k, v]) => (
                              <div className="route-line" key={k}><span className="rh-ip" style={{ width: '200px' }}>{k}</span><span className="rh-isp">{v}</span></div>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                    {wslHttpData?.available === false && <p className="diag-error">{wslHttpData.reason}</p>}
                  </div>
                )}
              </div>
            )}

            {/* ─── HOW TO USE ─── */}
            {activeTab === 'guide' && <GuideView wslStatus={wslStatus} />}
          </div>
        )}
      </main>
    </div>
  );
}

// ═════════════ INLINE SVG GRAPHS (v1.2.0) ═════════════
function StabilityGraph({ samples }) {
  const W = 760, H = 90, pad = 4;
  const n = Math.max(samples.length, 60);
  const live = samples.filter(s => s.alive && s.latency != null).map(s => s.latency);
  const maxLat = Math.max(60, ...live);
  const barW = (W - pad * 2) / n;
  return (
    <svg className="stab-graph" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <line x1="0" y1={H - 1} x2={W} y2={H - 1} stroke="rgba(255,255,255,0.08)" />
      {samples.map((s, i) => {
        const x = pad + i * barW;
        if (!s.alive) {
          return <rect key={i} x={x} y={2} width={Math.max(barW - 0.5, 1)} height={H - 4} fill="rgba(239,68,68,0.55)" />;
        }
        const h = Math.max(2, ((s.latency || 0) / maxLat) * (H - 8));
        const color = s.latency > 150 ? '#f59e0b' : '#22d3ee';
        return <rect key={i} x={x} y={H - 2 - h} width={Math.max(barW - 0.5, 1)} height={h} fill={color} />;
      })}
    </svg>
  );
}

function TrendChart({ title, unit, color, points, times, invert }) {
  const W = 320, H = 110, padX = 6, padY = 10;
  const vals = points.map(p => (p == null ? null : p));
  const valid = vals.filter(v => v != null);
  if (valid.length < 2) return null;
  const max = Math.max(...valid);
  const min = Math.min(...valid);
  const range = max - min || 1;
  const stepX = (W - padX * 2) / (vals.length - 1);
  const y = v => padY + (H - padY * 2) * (1 - (v - min) / range);
  let d = '';
  vals.forEach((v, i) => {
    if (v == null) return;
    const x = padX + i * stepX;
    d += (d === '' ? 'M' : 'L') + x.toFixed(1) + ' ' + y(v).toFixed(1) + ' ';
  });
  const last = valid[valid.length - 1];
  const avg = valid.reduce((a, b) => a + b, 0) / valid.length;
  return (
    <div className="trend-card">
      <div className="trend-head">
        <span className="trend-title">{title}</span>
        <span className="trend-now" style={{ color }}>{last}<small> {unit}</small></span>
      </div>
      <svg className="trend-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id={`g-${title}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.28" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={`${d} L ${(padX + (vals.length - 1) * stepX).toFixed(1)} ${H - padY} L ${padX} ${H - padY} Z`} fill={`url(#g-${title})`} />
        <path d={d} fill="none" stroke={color} strokeWidth="1.8" strokeLinejoin="round" />
      </svg>
      <div className="trend-foot">
        <span>min {min}{unit}</span>
        <span>avg {avg.toFixed(invert ? 0 : 1)}{unit}</span>
        <span>max {max}{unit}</span>
      </div>
    </div>
  );
}

// ═════════════ GUIDE COMPONENT ═════════════
function GuideView({ wslStatus }) {
  const sections = [
    {
      icon: '⊞', title: 'Overview Tab',
      desc: 'A live snapshot of your current network state - refreshes every 1–5 seconds.',
      items: [
        { name: 'SSID / BSSID', what: 'Name of the Wi-Fi network and the router\'s MAC address.', how: 'BSSID is unique per access point - useful for mesh networks.' },
        { name: 'Signal Quality', what: 'Strength of the Wi-Fi signal (0–100%).', how: '✓ 70%+ Excellent · ⚠ 40–70% OK · ✗ <40% Poor (move closer to router).' },
        { name: 'Link Speed', what: 'Theoretical maximum speed of your Wi-Fi link.', how: 'Should be close to your router\'s advertised speed. If much lower, signal is weak or older Wi-Fi standard.' },
        { name: 'Download/Upload (Live)', what: 'Real-time bytes/second on your active interface (not a speed test).', how: 'Shows current usage. For true speed, use "CDN Speed Test" on ISP Truth tab.' },
        { name: 'Gateway Latency', what: 'Round-trip time to your router.', how: '✓ <5ms Excellent · ⚠ 5–20ms OK · ✗ >20ms indicates Wi-Fi or local network issue.' },
        { name: 'External Latency', what: 'Round-trip time to 8.8.8.8 (Google DNS).', how: '✓ <50ms Excellent · ⚠ 50–150ms OK · ✗ >200ms indicates ISP routing issue.' },
        { name: 'Jitter', what: 'Variation in latency between successive pings.', how: '✓ <10ms Smooth · ⚠ 10–30ms Noticeable · ✗ >30ms Bad for VoIP/games.' },
        { name: 'Connection Health Score', what: 'Composite score combining local (30%) + ISP routing (70%).', how: '✓ 90+ Excellent · 70–90 Good · 50–70 Fair · <50 Poor.' },
      ]
    },
    {
      icon: '⌖', title: 'ISP Truth Tab',
      desc: 'Proves whether your ISP\'s international routing is the bottleneck - not your Wi-Fi.',
      items: [
        { name: 'Multi-Region Latency', what: 'Pings local exchange (first ISP hop), Singapore, US East, US West.', how: 'If local exchange is fast (<20ms) but Singapore/US is slow (>200ms with loss), ISP\'s international routing is the problem - not your connection.' },
        { name: 'CDN Speed Test', what: 'Downloads 10MB from Cloudflare\'s global CDN to measure real Mbps.', how: 'Compare to your plan: should reach ~80% of advertised speed. Lower means throttling or congestion.' },
        { name: 'DNS Hijacking Detector', what: 'Resolves google.com via system DNS and Cloudflare DoH, compares answers.', how: 'If IPs differ ⚠️ ISP/router is intercepting DNS. If DoH is much faster, your DNS is slow.' },
      ]
    },
    {
      icon: '📶', title: 'Wi-Fi Analyzer Tab',
      desc: 'Professional wireless metrics - outperforms many commercial Wi-Fi analyzers.',
      items: [
        { name: 'Band (2.4 / 5 GHz)', what: 'Which radio frequency you are connected on.', how: '5 GHz is faster and less congested for nearby devices. 2.4 GHz reaches farther but is crowded. Prefer 5 GHz when close to the router.' },
        { name: 'RSSI (dBm)', what: 'Raw signal strength in decibels (derived from signal %).', how: '✓ > -50 Excellent · -60 Good · -70 Fair · ✗ < -80 Poor/unstable. Closer to 0 is stronger.' },
        { name: 'Standard (802.11)', what: 'Wi-Fi generation: ax = Wi-Fi 6, ac = Wi-Fi 5, n = Wi-Fi 4.', how: 'If you only see "n", your router or device is older - upgrading to Wi-Fi 5/6 boosts speed dramatically.' },
        { name: 'Receive / Transmit Rate', what: 'Actual negotiated link rate to the access point.', how: 'Drops when signal is weak or the standard is old. Should be hundreds of Mbps on modern Wi-Fi.' },
        { name: 'Channel Interference Scan', what: 'Counts how many nearby networks share each channel.', how: 'For 2.4 GHz, pick the recommended channel (1, 6, or 11) with the fewest overlaps to reduce interference.' },
      ]
    },
    {
      icon: '❤', title: 'Health & Tips Tab',
      desc: 'Per-category scoring and intelligent, actionable recommendations.',
      items: [
        { name: 'Category Scores', what: 'Separate 0–100 scores for Internet, Wi-Fi, Latency, Stability, Security, DNS, Streaming, Gaming.', how: 'Lets you see exactly which aspect needs attention instead of one vague number. Below 60 = needs action.' },
        { name: 'Intelligent Recommendations', what: 'Plain-English advice based on the measured results.', how: 'Follow them top-to-bottom - e.g. "switch to 5 GHz", "contact ISP about packet loss".' },
        { name: 'DNS Provider Benchmark', what: 'Times Cloudflare, Google, Quad9, and OpenDNS resolvers.', how: 'Set the fastest one in your adapter settings for snappier browsing.' },
        { name: 'Local Network Health', what: 'Gateway ping with avg/min/max/median/p95/jitter/loss over 20 samples.', how: 'p95 and jitter reveal intermittent local congestion that a single ping would miss. Avg >10ms = local Wi-Fi issue.' },
        { name: 'Device Health', what: 'CPU, RAM, and power state of your computer.', how: 'High CPU/RAM or running on battery can throttle Wi-Fi. Plug in and close heavy apps for best speed.' },
      ]
    },
    {
      icon: '⛨', title: 'Security Tab',
      desc: 'Detects threats, attacks, and weak points in your network.',
      items: [
        { name: 'MITM Attack Check', what: 'Combines ARP, DNS, and certificate checks into one verdict.', how: '✓ "Low" Safe · ⚠ "High" Investigate · 🚨 "Critical" Disconnect immediately.' },
        { name: 'ARP Spoofing Detector', what: 'Scans ARP table for the same MAC bound to multiple IPs (classic MITM signature).', how: 'Any duplicate MAC is a strong red flag - someone may be intercepting traffic.' },
        { name: 'Wi-Fi Security Audit', what: 'Rates encryption strength (WPA3/WPA2/WPA/WEP/Open).', how: '✓ WPA3 Excellent · ✓ WPA2 Strong · ⚠ WPA Weak · ✗ WEP/Open Critical (switch network).' },
        { name: 'DNS Leak Test', what: 'Identifies whether DNS queries leak to ISP instead of private resolvers.', how: 'If only ISP DNS is configured, your ISP sees every site you visit. Switch to 1.1.1.1 or 9.9.9.9.' },
        { name: 'Open Ports Scan', what: 'Lists ports your machine is listening on (incoming).', how: 'Common: 135, 445 (Windows), 5040 (Cortana). >10 open is worth reviewing. Unknown high ports = investigate.' },
        { name: 'Firewall Status', what: 'Checks Windows Firewall profiles.', how: '✓ Enabled = protected. ✗ Disabled = critical risk, enable in Windows Settings.' },
        { name: 'SSL/TLS Security', what: 'Verifies HTTPS reachability and TLS version.', how: 'Should show TLS 1.2 or 1.3. TLS 1.0/1.1 are deprecated and insecure.' },
      ]
    },
    {
      icon: '⊟', title: 'Devices Tab',
      desc: 'Lists every device currently visible on your local network.',
      items: [
        { name: 'IP Address', what: 'Local IP assigned to the device by DHCP.', how: 'Gateway (router) is usually .1 or .254.' },
        { name: 'MAC Address', what: 'Hardware identifier of the device\'s network card.', how: 'First 3 bytes identify the manufacturer (OUI).' },
        { name: 'Vendor', what: 'Hardware manufacturer derived from MAC OUI prefix.', how: 'Helps identify which device is which (Apple = iPhone/Mac, Samsung = TV/phone, etc.).' },
        { name: 'Hostname', what: 'Reverse DNS lookup of the device IP.', how: '"-" means no PTR record published. Common for IoT devices.' },
        { name: 'Type', what: 'Dynamic = DHCP-assigned · Static = manually configured.', how: 'Most home devices are Dynamic. Static usually means servers/printers.' },
      ]
    },
    {
      icon: '🚀', title: 'Speed & Stability Tab',
      desc: 'Pinpoints exactly where slowness comes from and whether your connection holds steady under load.',
      items: [
        { name: 'Connection Phase Breakdown', what: 'Times DNS lookup, TCP connect, TLS handshake, and time-to-first-byte during a real download.', how: 'A high DNS phase = change DNS server. High TLS/TTFB = slow/distant server. High TCP = routing issue.' },
        { name: 'Bufferbloat Grade', what: 'Measures how much latency rises while the link is saturated by a download.', how: '✓ A/B = great for calls & gaming · ⚠ C/D = laggy when busy · ✗ F = enable SQM/QoS on your router.' },
        { name: '60-Second Stability Test', what: 'Pings once per second for a minute, charting every result and counting drops & reconnects.', how: '0 drops = rock solid. Frequent red bars (drops) point to Wi-Fi interference or a flaky ISP line.' },
      ]
    },
    {
      icon: '🗺', title: 'Route Trace Tab',
      desc: 'Maps the full path your traffic takes and geolocates each hop to find the bottleneck.',
      items: [
        { name: 'Hop Table', what: 'Each router (hop) between you and the destination, with its latency.', how: 'Watch where latency suddenly jumps - that hop is the bottleneck.' },
        { name: 'Network / Location', what: 'ISP/organisation and city/country of each public hop.', how: 'Tells you whether a slow hop is inside your ISP or further out on the internet.' },
        { name: 'Largest Jump Analysis', what: 'Automatically highlights the biggest latency increase along the path.', how: 'If the jump is at an early ISP hop, your provider is the cause - useful evidence for support tickets.' },
      ]
    },
    {
      icon: '📈', title: 'Trends Tab',
      desc: 'Keeps a local history of your connection so you can spot recurring problems over time.',
      items: [
        { name: 'Download / Upload Graphs', what: 'Sampled every 30 seconds and stored on your device (no cloud).', how: 'Dips at certain times of day reveal peak-hour congestion.' },
        { name: 'Latency & Signal Graphs', what: 'Tracks ping and Wi-Fi signal strength over time.', how: 'Rising latency or falling signal that repeats daily points to interference or ISP congestion.' },
        { name: 'Clear History', what: 'Wipes the stored samples.', how: 'Use before starting a fresh monitoring session.' },
      ]
    },
    {
      icon: '⚙', title: 'Diagnostics Tab',
      desc: 'Deeper technical details for troubleshooting.',
      items: [
        { name: 'DHCP Lease', what: 'When your IP was leased and when it expires.', how: 'If expiring soon and acting weird, run `ipconfig /renew`.' },
        { name: 'DNS Servers', what: 'The DNS servers your system is using.', how: 'Switch to 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9) for privacy + speed.' },
        { name: 'Interface MAC', what: 'Your computer\'s own MAC address.', how: 'Used to identify your device on the network.' },
      ]
    },
    ...(wslStatus?.installed ? [{
      icon: '🐧', title: 'WSL Tools Tab (Advanced)',
      desc: 'Appears only when WSL (Windows Subsystem for Linux) is detected - unlocks professional Linux networking tools.',
      items: [
        { name: 'mtr - Live Route Quality', what: 'Sends many probes per hop to report per-hop packet loss and latency together.', how: 'The gold standard for proving exactly which hop drops packets. Any loss% before the final hop = that link is the culprit.' },
        { name: 'dig - DNSSEC Validation', what: 'Checks whether DNS answers are cryptographically signed and validated.', how: '✓ Validated (AD flag) = tamper-proof DNS · Unsigned = common but offers no integrity guarantee.' },
        { name: 'Install Command', what: 'One-line command to add mtr & dig to your WSL distro if missing.', how: 'Copy it, paste into your Ubuntu/WSL terminal, then click "Re-check".' },
      ]
    }] : []),
    {
      icon: '⎘', title: 'Report Export (Header Buttons)',
      desc: 'In the header - export your current results in multiple formats.',
      items: [
        { name: 'Copy Report', what: 'Copies a formatted plain-text report to the clipboard.', how: 'Paste in support tickets, emails to ISP, or save for trend analysis.' },
        { name: 'JSON Export', what: 'Downloads a complete structured snapshot of every metric.', how: 'Best for bug reports, scripting, or feeding into other tools.' },
        { name: 'MD (Markdown) Export', what: 'Downloads a readable Markdown report with scores and recommendations.', how: 'Great for sharing on GitHub issues, forums, or documentation.' },
      ]
    },
  ];

  return (
    <div className="guide-view">
      <div className="guide-intro">
        <h2>📘 How to Use Network Detector</h2>
        <p>This app measures every aspect of your network in real time. Below is a complete reference for every metric, what it means, and how to interpret the result.</p>
        <div className="guide-legend">
          <span><b>✓ Green</b> = healthy</span>
          <span><b>⚠ Yellow</b> = caution</span>
          <span><b>✗ Red</b> = problem</span>
        </div>
      </div>

      {sections.map((s, idx) => (
        <div key={s.title} className="guide-section" style={{ animationDelay: `${idx * 0.08}s` }}>
          <div className="guide-section-head">
            <span className="guide-section-icon">{s.icon}</span>
            <div>
              <h3>{s.title}</h3>
              <p>{s.desc}</p>
            </div>
          </div>
          <div className="guide-items">
            {s.items.map(item => (
              <div key={item.name} className="guide-item">
                <div className="guide-item-name">{item.name}</div>
                <div className="guide-item-what"><b>What it measures:</b> {item.what}</div>
                <div className="guide-item-how"><b>How to read it:</b> {item.how}</div>
              </div>
            ))}
          </div>
        </div>
      ))}

      <div className="guide-footer">
        <p>💡 <b>Pro tip:</b> If your internet is slow, start with the <b>ISP Truth</b> tab. Compare local exchange latency vs Singapore latency - if local is fast but international is bad, the problem is your ISP, not your Wi-Fi.</p>
      </div>
    </div>
  );
}

export default App;
