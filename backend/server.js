const express = require('express');
const cors = require('cors');
const path = require('path');
const bridge = require('./ipc-bridge');
const { 
    getWifiStats, 
    getIpConfig, 
    getPingStats, 
    getPublicInfo, 
    getDnsResolutionTime,
    getThroughput,
    getArpDeviceCount,
    getGlobalPingMatrix,
    runCdnSpeedTest,
    detectDnsHijacking,
    runSecurityScan,
    runPortScan,
    getConnectedDevices,
    detectArpSpoofing,
    detectDnsLeak,
    runWifiSecurityAudit,
    runMitmCheck,
    getActiveInterface,
    getDetailedGatewayHealth,
    getWifiAnalysis,
    scanWifiNetworks,
    getDnsBenchmark,
    getDeviceHealth,
    getHealthBreakdown,
    runSpeedDiagnostics,
    getRouteAnalysis,
    getQuickPing,
    getWifiCapabilities
} = require('./networkScanner');
const { detectWsl, checkWslTools, wslMtr, wslDig, wslTraceroute, wslNmapLan, wslIpv6Test, wslHttpInspect } = require('./wslTools');
const { getRouterDevices } = require('./routerAdmin');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

app.get('/api/network/basic', async (req, res) => {
    try {
        const wifi = await getWifiStats();
        const ip = await getIpConfig();
        res.json({ wifi, ip });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch basic stats' });
    }
});

app.get('/api/network/ping-gateway', async (req, res) => {
    try {
        const ip = await getIpConfig();
        const gateway = ip.defaultGateway || '';
        const stats = await getPingStats(gateway);
        res.json({ gateway, ...stats });
    } catch (err) {
        res.status(500).json({ error: 'Failed to ping gateway' });
    }
});

app.get('/api/network/ping-external', async (req, res) => {
    try {
        const stats = await getPingStats('8.8.8.8');
        res.json(stats);
    } catch (err) {
        res.status(500).json({ error: 'Failed to ping external' });
    }
});

app.get('/api/network/public-ip', async (req, res) => {
    try {
        const info = await getPublicInfo();
        res.json(info);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch public info' });
    }
});

app.get('/api/network/dns-time', async (req, res) => {
    try {
        const time = await getDnsResolutionTime();
        res.json({ time });
    } catch (err) {
        res.status(500).json({ error: 'Failed to resolve DNS' });
    }
});

app.get('/api/network/throughput', async (req, res) => {
    try {
        const stats = await getThroughput();
        res.json(stats);
    } catch (err) {
        res.status(500).json({ error: 'Failed to get throughput' });
    }
});

app.get('/api/network/arp-count', async (req, res) => {
    try {
        const count = await getArpDeviceCount();
        res.json({ count });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get ARP count' });
    }
});

// ── ISP Truth Detector Endpoints ──────────────────────────────────────────────
app.get('/api/network/ping-global', async (req, res) => {
    try {
        const matrix = await getGlobalPingMatrix();
        res.json(matrix);
    } catch (err) {
        res.status(500).json({ error: 'Failed to get global ping matrix' });
    }
});

app.post('/api/network/speedtest-cdn', async (req, res) => {
    try {
        const result = await runCdnSpeedTest();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run CDN speed test' });
    }
});

app.get('/api/network/dns-hijacking', async (req, res) => {
    try {
        const result = await detectDnsHijacking();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to check DNS hijacking' });
    }
});

app.get('/api/network/security-scan', async (req, res) => {
    try {
        const result = await runSecurityScan();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run security scan' });
    }
});

app.post('/api/network/port-scan', async (req, res) => {
    try {
        const result = await runPortScan();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run port scan' });
    }
});

app.get('/api/network/connected-devices', async (req, res) => {
    try {
        const result = await getConnectedDevices();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch connected devices' });
    }
});

app.get('/api/network/arp-spoof-check', async (req, res) => {
    try {
        const result = await detectArpSpoofing();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to check ARP spoofing' });
    }
});

app.get('/api/network/dns-leak', async (req, res) => {
    try {
        const result = await detectDnsLeak();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run DNS leak test' });
    }
});

app.get('/api/network/wifi-audit', async (req, res) => {
    try {
        const result = await runWifiSecurityAudit();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run WiFi audit' });
    }
});

app.get('/api/network/mitm-check', async (req, res) => {
    try {
        const result = await runMitmCheck();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run MITM check' });
    }
});

// ── Advanced Diagnostics Endpoints (v1.1.0) ───────────────────────────────────
app.get('/api/network/active-interface', async (req, res) => {
    try {
        const result = await getActiveInterface();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to detect active interface' });
    }
});

app.get('/api/network/gateway-health', async (req, res) => {
    try {
        const result = await getDetailedGatewayHealth();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to measure gateway health' });
    }
});

app.get('/api/network/wifi-analysis', async (req, res) => {
    try {
        const result = await getWifiAnalysis();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to analyze Wi-Fi' });
    }
});

app.get('/api/network/wifi-scan', async (req, res) => {
    try {
        const result = await scanWifiNetworks();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to scan Wi-Fi networks' });
    }
});

app.get('/api/network/dns-benchmark', async (req, res) => {
    try {
        const result = await getDnsBenchmark();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to benchmark DNS' });
    }
});

app.get('/api/network/device-health', async (req, res) => {
    try {
        const result = await getDeviceHealth();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to read device health' });
    }
});

app.get('/api/network/health-breakdown', async (req, res) => {
    try {
        const result = await getHealthBreakdown();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to compute health breakdown' });
    }
});

// ── Speed phases · Route analysis · Stability (v1.2.0) ────────────────────────
app.get('/api/network/speed-diagnostics', async (req, res) => {
    try {
        const result = await runSpeedDiagnostics();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run speed diagnostics' });
    }
});

app.get('/api/network/route-analysis', async (req, res) => {
    try {
        const target = req.query.target || '8.8.8.8';
        const geo = req.query.geo !== 'false';
        const result = await getRouteAnalysis(target, geo);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run route analysis' });
    }
});

app.get('/api/network/ping-once', async (req, res) => {
    try {
        const target = req.query.target || '8.8.8.8';
        const result = await getQuickPing(target);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Ping failed' });
    }
});

// ── Wi-Fi adapter capabilities ─────────────────────────────────────────────
app.get('/api/network/wifi-capabilities', async (req, res) => {
    try { res.json(await getWifiCapabilities()); }
    catch (err) { res.status(500).json({ error: 'Failed to read Wi-Fi capabilities' }); }
});

// ── Router admin device list ────────────────────────────────────────────────
app.post('/api/network/router-devices', async (req, res) => {
    try {
        const { ip, user, pass } = req.body || {};
        if (!ip || typeof ip !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
            return res.status(400).json({ error: 'Invalid router IP' });
        }
        // Sanitise: only allow private/LAN IPs — router creds must never be sent to public IPs
        const [a, b] = ip.split('.').map(Number);
        const isPrivate = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
        if (!isPrivate) return res.status(403).json({ error: 'Only local network IPs allowed' });
        res.json(await getRouterDevices(ip, user || '', pass || ''));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── Open URL in system browser (router admin page) ─────────────────────────
app.post('/api/network/open-browser', (req, res) => {
    const { url } = req.body || {};
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'Missing url' });
    try {
        const u = new URL(url);
        const [a, b] = (u.hostname || '').split('.').map(Number);
        const isPrivate = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
        if (!isPrivate) return res.status(403).json({ error: 'Only local network URLs allowed' });
        bridge.emit('shell:open-external', url);
        res.json({ ok: true });
    } catch { res.status(400).json({ error: 'Invalid URL' }); }
});

// ── WSL-powered advanced tools (v1.2.0) ───────────────────────────────────────
app.get('/api/network/wsl-status', async (req, res) => {
    try {
        const force = req.query.force === 'true';
        const result = await detectWsl(force);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to detect WSL' });
    }
});

app.get('/api/network/wsl-tools', async (req, res) => {
    try {
        const force = req.query.force === 'true';
        const result = await checkWslTools(force);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to check WSL tools' });
    }
});

app.get('/api/network/wsl-mtr', async (req, res) => {
    try {
        const target = req.query.target || '8.8.8.8';
        const result = await wslMtr(target);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run mtr' });
    }
});

app.get('/api/network/wsl-dig', async (req, res) => {
    try {
        const domain = req.query.domain || 'cloudflare.com';
        const result = await wslDig(domain);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run dig' });
    }
});

app.get('/api/network/wsl-traceroute', async (req, res) => {
    try {
        const target = req.query.target || '8.8.8.8';
        const result = await wslTraceroute(target);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run traceroute' });
    }
});

app.get('/api/network/wsl-nmap-lan', async (req, res) => {
    try {
        // Accept explicit subnet or default to the gateway's /24
        let subnet = req.query.subnet || '';
        if (!subnet) {
            const { getIpConfig } = require('./networkScanner');
            const ip = await getIpConfig();
            const gw = ip.defaultGateway || '';
            const parts = gw.split('.');
            subnet = parts.length === 4 ? `${parts.slice(0, 3).join('.')}.0/24` : '192.168.1.0/24';
        }
        const result = await wslNmapLan(subnet);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run nmap scan' });
    }
});

app.get('/api/network/wsl-ipv6', async (req, res) => {
    try {
        const result = await wslIpv6Test();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run IPv6 test' });
    }
});

app.get('/api/network/wsl-http-inspect', async (req, res) => {
    try {
        const url = req.query.url || 'https://cloudflare.com';
        const result = await wslHttpInspect(url);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Failed to run HTTP inspection' });
    }
});

// ── Toolbar control routes ────────────────────────────────────────────────────
app.get('/api/toolbar/status', (req, res) => {
    let result = { visible: false, pinned: true };
    bridge.emit('toolbar:get-status', (s) => { result = s; });
    res.json(result);
});

app.post('/api/toolbar/toggle', (req, res) => {
    bridge.emit('toolbar:toggle');
    res.json({ ok: true });
});

app.post('/api/toolbar/pin-toggle', (req, res) => {
    bridge.emit('toolbar:pin-toggle');
    let result = { pinned: true };
    bridge.emit('toolbar:get-status', (s) => { result = s; });
    res.json(result);
});

app.post('/api/toolbar/opacity', (req, res) => {
    const { opacity } = req.body || {};
    if (typeof opacity !== 'number' || opacity < 0.1 || opacity > 1.0) {
        return res.status(400).json({ error: 'Invalid opacity value' });
    }
    bridge.emit('toolbar:set-opacity', opacity);
    res.json({ ok: true });
});

// Floating toolbar — served as a standalone HTML page (no React, no bundler)
app.get('/toolbar', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;height:38px;overflow:hidden;background:transparent;-webkit-app-region:drag;user-select:none}
.bar{display:flex;align-items:center;height:38px;padding:0 8px 0 10px;gap:6px;font-family:'Segoe UI',system-ui,sans-serif;font-size:11.5px;background:rgba(6,12,28,0.92);color:#e2e8f0;border:1px solid rgba(255,255,255,0.09);border-radius:0 0 8px 8px;white-space:nowrap}
.lbl{color:#475569;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px}
.val{font-weight:600;transition:color .4s}
.g{color:#10b981}.y{color:#f59e0b}.r{color:#ef4444}.d{color:#64748b}
.sep{width:1px;height:16px;background:rgba(255,255,255,.08);flex-shrink:0}
.sp{flex:1;min-width:2px}
.btn{-webkit-app-region:no-drag;background:transparent;border:none;cursor:pointer;font-size:11px;height:20px;border-radius:3px;display:flex;align-items:center;justify-content:center;padding:0 4px;flex-shrink:0;transition:color .2s,background .2s;font-family:inherit;font-weight:700;letter-spacing:.3px}
.pin-btn{color:#475569}
.pin-btn.on{color:#10b981}
.pin-btn:hover{background:rgba(255,255,255,.08);color:#94a3b8}
.pin-btn.on:hover{color:#10b981}
.close-btn{color:#334155;font-size:12px;width:18px;padding:0}
.close-btn:hover{color:#f87171;background:rgba(239,68,68,.12)}
</style></head>
<body>
<div class="bar">
  <span class="lbl">&#8595;</span><span class="val d" id="dl">&#8212;</span>
  <span class="lbl">&#8593;</span><span class="val d" id="ul">&#8212;</span>
  <div class="sep"></div>
  <span class="lbl">Ping</span><span class="val d" id="pg">&#8212;</span>
  <div class="sep"></div>
  <span class="lbl">Sig</span><span class="val d" id="sg">&#8212;</span>
  <div class="sp"></div>
  <button class="btn pin-btn" id="pinBtn" onclick="togglePin()" title="Toggle always-on-top">TOP</button>
  <button class="btn close-btn" onclick="window.close()" title="Hide toolbar">&#x2715;</button>
</div>
<script>
const el=id=>document.getElementById(id);
let pinned=true;

async function init(){
  try{
    const s=await fetch('/api/toolbar/status').then(r=>r.json());
    pinned=s.pinned;
    el('pinBtn').className='btn pin-btn'+(pinned?' on':'');
  }catch{}
}

async function togglePin(){
  try{
    const s=await fetch('/api/toolbar/pin-toggle',{method:'POST'}).then(r=>r.json());
    pinned=s.pinned;
    el('pinBtn').className='btn pin-btn'+(pinned?' on':'');
  }catch{}
}

async function thr(){
  try{
    const d=await fetch('/api/network/throughput').then(r=>r.json());
    const dn=parseFloat(d.downloadMbps),up=parseFloat(d.uploadMbps);
    el('dl').textContent=(dn<0.1?dn.toFixed(2):dn.toFixed(1))+' Mb/s';
    el('ul').textContent=(up<0.1?up.toFixed(2):up.toFixed(1))+' Mb/s';
    el('dl').className='val '+(dn>0.05?'g':'d');
    el('ul').className='val '+(up>0.05?'g':'d');
  }catch{}
}
async function png(){
  try{
    const d=await fetch('/api/network/ping-external').then(r=>r.json());
    const ms=parseInt(d.latency)||999;
    const lm=(d.loss||'').match(/(\\d+)%/);
    const loss=lm?+lm[1]:0;
    el('pg').textContent=(d.latency||'?')+(loss>0?' '+loss+'%loss':'');
    el('pg').className='val '+(ms<=50?'g':ms<=150?'y':'r');
  }catch{}
}
async function sig(){
  try{
    const d=await fetch('/api/network/basic').then(r=>r.json());
    const p=parseInt(d.wifi?.signalQuality)||0;
    el('sg').textContent=d.wifi?.signalQuality||'N/A';
    el('sg').className='val '+(p>=70?'g':p>=40?'y':'r');
  }catch{}
}
init();thr();png();sig();
setInterval(thr,1000);setInterval(png,5000);setInterval(sig,3000);
</script>
</body></html>`);
});

// Serve frontend static files in production
app.use(express.static(path.join(__dirname, '../frontend/dist')));

// Fallback for React
app.use((req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/dist', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
});
