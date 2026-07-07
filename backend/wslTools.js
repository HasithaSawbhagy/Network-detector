const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

// Only IP addresses and safe hostnames are ever interpolated into commands
const SAFE_TARGET_RE = /^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}$/;

const WSL_EXE = path.join(process.env.WINDIR || 'C:\\Windows', 'System32', 'wsl.exe');

// Run wsl.exe directly (no cmd.exe shell) with the console window hidden.
const runWsl = (args, { timeoutMs = 60000, encoding = 'utf8' } = {}) => new Promise((resolve, reject) => {
    execFile(WSL_EXE, args, { windowsHide: true, timeout: timeoutMs, maxBuffer: 1024 * 1024 * 16, encoding }, (error, stdout) => {
        if (error) {
            if (stdout) return resolve(stdout);
            return reject(error);
        }
        resolve(stdout);
    });
});

function wslBinaryExists() {
    try { return fs.existsSync(WSL_EXE); } catch { return false; }
}

let wslCache = null;
let wslCacheTime = 0;

/**
 * Lightweight WSL detection — lists installed distros only.
 * IMPORTANT: `wsl -l -q` does NOT boot any distro, so it never shows the
 * Ubuntu/systemd boot console. Tool availability is checked separately and
 * only on explicit user action (see checkWslTools), because that DOES boot
 * the distro and can briefly show a WSL console.
 */
async function detectWsl(force = false) {
    if (!force && wslCache && Date.now() - wslCacheTime < 300000) return wslCache;

    const result = {
        installed: false,
        distro: null,
        distros: [],
        toolsChecked: false,
        tools: { mtr: false, dig: false, traceroute: false, nmap: false },
        anyToolAvailable: false,
        installCommand: 'sudo apt update && sudo apt install -y mtr-tiny dnsutils traceroute nmap',
        error: null
    };

    if (!wslBinaryExists()) {
        wslCache = result; wslCacheTime = Date.now();
        return result;
    }

    try {
        // utf16le: `wsl -l -q` emits UTF-16. Decode properly then clean stray nulls.
        const out = await runWsl(['-l', '-q'], { timeoutMs: 12000, encoding: 'utf16le' });
        const distros = out.replace(/\u0000/g, '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
        result.distros = distros;

        // Prefer a real Linux distro over the minimal docker-desktop helper distro
        const preferred = distros.find(d => !/docker-desktop/i.test(d)) || distros[0];
        if (preferred) {
            result.installed = true;
            result.distro = preferred;
        }
    } catch (e) {
        result.error = e.message;
    }

    wslCache = result;
    wslCacheTime = Date.now();
    return result;
}

/**
 * Check which networking tools are installed inside WSL.
 * This BOOTS the distro (a brief WSL console may appear), so it is only ever
 * called when the user explicitly asks for it.
 */
async function checkWslTools(force = false) {
    const base = await detectWsl(force);
    if (!base.installed) return base;

    try {
        const check = await runWsl(
            ['-d', base.distro, '--', 'bash', '-c',
             'command -v mtr >/dev/null && echo HAS_MTR; ' +
             'command -v dig >/dev/null && echo HAS_DIG; ' +
             'command -v traceroute >/dev/null && echo HAS_TR; ' +
             'command -v nmap >/dev/null && echo HAS_NMAP; ' +
             'command -v speedtest-cli >/dev/null && echo HAS_SPEEDTEST; ' +
             'command -v curl >/dev/null && echo HAS_CURL'],
            { timeoutMs: 30000 }
        );
        base.tools.mtr = /HAS_MTR/.test(check);
        base.tools.dig = /HAS_DIG/.test(check);
        base.tools.traceroute = /HAS_TR/.test(check);
        base.tools.nmap = /HAS_NMAP/.test(check);
        base.tools.speedtest = /HAS_SPEEDTEST/.test(check);
        base.tools.curl = /HAS_CURL/.test(check);
        base.anyToolAvailable = Object.values(base.tools).some(Boolean);
        base.installCommand = 'sudo apt update && sudo apt install -y mtr-tiny dnsutils traceroute nmap curl';
        base.installCommandFull = 'sudo apt update && sudo apt install -y mtr-tiny dnsutils traceroute nmap curl && sudo pip3 install speedtest-cli 2>/dev/null || sudo apt install -y python3-pip && pip3 install speedtest-cli';
    } catch (e) {
        base.error = e.message;
    }
    base.toolsChecked = true;

    wslCache = base;
    wslCacheTime = Date.now();
    return base;
}

/**
 * MTR (My TraceRoute) — best-in-class route analysis.
 * Sends multiple probes per hop and reports per-hop loss %, avg/best/worst latency.
 */
async function wslMtr(target) {
    if (!SAFE_TARGET_RE.test(target)) throw new Error('Invalid target');
    const wsl = await checkWslTools();
    if (!wsl.installed || !wsl.tools.mtr) {
        return { available: false, reason: 'mtr is not installed in WSL', installCommand: wsl.installCommand, hops: [] };
    }

    const out = await runWsl(
        ['-d', wsl.distro, '--', 'mtr', '--report', '--report-cycles', '10', '--no-dns', '-c', '10', target],
        { timeoutMs: 60000 }
    );

    const hops = [];
    out.split('\n').forEach(line => {
        // " 1.|-- 192.168.1.1   0.0%  10  0.5  0.6  0.5  0.9  0.1"
        const m = line.match(/^\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
        if (m) {
            hops.push({
                hop: parseInt(m[1]),
                host: m[2],
                loss: parseFloat(m[3]),
                sent: parseInt(m[4]),
                last: parseFloat(m[5]),
                avg: parseFloat(m[6]),
                best: parseFloat(m[7]),
                worst: parseFloat(m[8]),
                stdev: parseFloat(m[9])
            });
        }
    });

    return { available: true, tool: 'mtr', target, hops };
}

/**
 * DNSSEC / DNS validation via dig.
 */
async function wslDig(domain) {
    if (!SAFE_TARGET_RE.test(domain)) throw new Error('Invalid domain');
    const wsl = await checkWslTools();
    if (!wsl.installed || !wsl.tools.dig) {
        return { available: false, reason: 'dig is not installed in WSL', installCommand: wsl.installCommand };
    }

    const out = await runWsl(['-d', wsl.distro, '--', 'dig', '+dnssec', domain], { timeoutMs: 20000 });

    const flagsMatch = out.match(/flags:\s*([a-z ]+);/);
    const flags = flagsMatch ? flagsMatch[1].trim() : '';
    const authenticated = /\bad\b/.test(flags); // AD = Authenticated Data
    const hasRrsig = /RRSIG/.test(out);

    const answers = [];
    let inAnswer = false;
    out.split('\n').forEach(line => {
        if (/;; ANSWER SECTION:/.test(line)) { inAnswer = true; return; }
        if (inAnswer) {
            if (/^;;/.test(line) || line.trim() === '') { inAnswer = false; return; }
            const parts = line.split(/\s+/);
            if (parts.length >= 5) answers.push({ type: parts[3], value: parts.slice(4).join(' ') });
        }
    });

    return {
        available: true,
        tool: 'dig',
        domain,
        dnssecSigned: hasRrsig,
        authenticated,
        flags,
        answers: answers.slice(0, 6),
        analysis: hasRrsig
            ? (authenticated ? '✅ DNSSEC signed and validated (AD flag present).' : '⚠️ DNSSEC records present but not validated by your resolver.')
            : 'ℹ️ Domain is not DNSSEC-signed (common — not necessarily a problem).'
    };
}

/**
 * Traceroute — Linux UDP-based traceroute (different probe type from Windows tracert,
 * reveals hops that filter ICMP but not UDP).
 */
async function wslTraceroute(target) {
    if (!SAFE_TARGET_RE.test(target)) throw new Error('Invalid target');
    const wsl = await checkWslTools();
    if (!wsl.installed || !wsl.tools.traceroute) {
        return { available: false, reason: 'traceroute is not installed in WSL', installCommand: wsl.installCommand, hops: [] };
    }
    const out = await runWsl(
        ['-d', wsl.distro, '--', 'traceroute', '-n', '-w', '1', '-m', '20', target],
        { timeoutMs: 60000 }
    );
    const hops = [];
    out.split('\n').forEach(line => {
        const m = line.match(/^\s*(\d+)\s+(.+)$/);
        if (!m) return;
        const hop = parseInt(m[1]);
        const rest = m[2];
        if (/\*\s+\*\s+\*/.test(rest)) { hops.push({ hop, ip: '*', avg: null, timeout: true }); return; }
        const ipM = rest.match(/(\d+\.\d+\.\d+\.\d+)/);
        const times = [...rest.matchAll(/([\d.]+)\s+ms/g)].map(x => parseFloat(x[1]));
        const avg = times.length ? (times.reduce((a, b) => a + b, 0) / times.length).toFixed(1) : null;
        hops.push({ hop, ip: ipM ? ipM[1] : '?', avg, timeout: false });
    });
    return { available: true, tool: 'traceroute', target, hops };
}

/**
 * Nmap LAN scan — discovers all live hosts on the local subnet using
 * multiple probe types (ICMP + TCP), far more thorough than ARP-only.
 */
async function wslNmapLan(subnet) {
    if (!SAFE_TARGET_RE.test(subnet.replace(/\/\d+$/, ''))) throw new Error('Invalid subnet');
    const wsl = await checkWslTools();
    if (!wsl.installed || !wsl.tools.nmap) {
        return { available: false, reason: 'nmap is not installed in WSL', installCommand: wsl.installCommand, hosts: [] };
    }
    const out = await runWsl(
        ['-d', wsl.distro, '--', 'nmap', '-sn', '--host-timeout', '3s', subnet],
        { timeoutMs: 90000 }
    );
    const hosts = [];
    let current = null;
    out.split('\n').forEach(line => {
        const hostM = line.match(/Nmap scan report for (.+)/);
        if (hostM) {
            if (current) hosts.push(current);
            const raw = hostM[1].trim();
            const ipM = raw.match(/\((\d+\.\d+\.\d+\.\d+)\)/);
            const ip = ipM ? ipM[1] : raw;
            const hostname = ipM ? raw.replace(ipM[0], '').trim() : '';
            current = { ip, hostname: hostname || '—', mac: '—', vendor: '—', latency: null };
        }
        if (current) {
            const macM = line.match(/MAC Address: ([0-9A-F:]{17})\s*\((.+)\)/i);
            if (macM) { current.mac = macM[1]; current.vendor = macM[2]; }
            const latM = line.match(/Host is up \((\S+)s latency\)/);
            if (latM) current.latency = (parseFloat(latM[1]) * 1000).toFixed(1) + ' ms';
        }
    });
    if (current) hosts.push(current);
    return { available: true, tool: 'nmap', subnet, hosts, total: hosts.length };
}

/**
 * IPv6 connectivity test — checks if working IPv6 is available.
 */
async function wslIpv6Test() {
    const wsl = await checkWslTools();
    if (!wsl.installed) return { available: false, reason: 'WSL not installed' };
    try {
        const out = await runWsl(
            ['-d', wsl.distro, '--', 'bash', '-c',
             'ip -6 addr show scope global 2>/dev/null | grep inet6; ' +
             'ping6 -c 3 -W 2 2001:4860:4860::8888 2>&1 | tail -3'],
            { timeoutMs: 20000 }
        );
        const pingOk = /\d+ received/.test(out) && !/ 0 received/.test(out);
        const addrs = (out.match(/inet6 ([0-9a-f:]+\/\d+)/g) || []).map(x => x.replace('inet6 ', ''));
        const hasGlobal = addrs.some(a => !a.startsWith('fe80'));
        return {
            available: true,
            hasGlobalAddress: hasGlobal,
            pingSucceeded: pingOk,
            addresses: addrs,
            summary: pingOk ? '✅ IPv6 connectivity working' : (hasGlobal ? '⚠️ Has IPv6 address but pings failed' : '❌ No IPv6 (IPv4-only connection)')
        };
    } catch (e) {
        return { available: true, hasGlobalAddress: false, pingSucceeded: false, summary: '❌ IPv6 test error: ' + e.message };
    }
}

/**
 * HTTP header inspection — detects ISP proxy injection, identifies CDN/edge,
 * and compares response headers for privacy/security issues.
 */
async function wslHttpInspect(url) {
    const domain = url.replace(/^https?:\/\//, '').split('/')[0];
    if (!SAFE_TARGET_RE.test(domain)) throw new Error('Invalid URL');
    const wsl = await checkWslTools();
    if (!wsl.installed || !wsl.tools.curl) {
        return { available: false, reason: 'curl is not installed in WSL', installCommand: wsl.installCommand };
    }
    const out = await runWsl(
        ['-d', wsl.distro, '--', 'curl', '-sI', '--max-time', '8', '--connect-timeout', '4', url],
        { timeoutMs: 12000 }
    );
    const headers = {};
    out.split('\n').forEach(line => {
        const m = line.match(/^([^:\r]+):\s*(.+)/);
        if (m) headers[m[1].toLowerCase().trim()] = m[2].trim();
    });
    const statusM = out.match(/HTTP\/\S+\s+(\d+)/);
    const status = statusM ? parseInt(statusM[1]) : null;
    const suspicious = ['x-forwarded-for', 'via', 'x-cache', 'x-squid', 'x-isp', 'x-proxy'].filter(h => headers[h]);
    return {
        available: true, url, status, headers,
        cdn: headers['server'] || headers['x-served-by'] || headers['x-cache'] || '—',
        suspiciousHeaders: suspicious,
        analysis: suspicious.length
            ? `⚠️ Possible ISP/proxy injection — suspicious headers found: ${suspicious.join(', ')}`
            : '✅ No proxy/ISP injection headers detected'
    };
}

module.exports = { detectWsl, checkWslTools, wslMtr, wslDig, wslTraceroute, wslNmapLan, wslIpv6Test, wslHttpInspect };
