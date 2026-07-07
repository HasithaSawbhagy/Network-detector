const { exec } = require('child_process');
const net = require('net');
const { promises: dnsPromises } = require('dns');
const https = require('https');
const si = require('systeminformation');

// Allowlist pattern: only IP addresses and safe hostnames
const SAFE_TARGET_RE = /^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}$/;

// Helper to execute commands (windowsHide prevents console windows from flashing)
const runCmd = (cmd, timeoutMs = 0) => new Promise((resolve, reject) => {
    const opts = { windowsHide: true, maxBuffer: 1024 * 1024 * 16 };
    if (timeoutMs > 0) opts.timeout = timeoutMs;
    exec(cmd, opts, (error, stdout, stderr) => {
        if (error) {
            if (stdout) return resolve(stdout);
            return reject(error);
        }
        resolve(stdout);
    });
});

// ─── TCP connectivity check (no subprocess) ────────────────────────────────
// Establishes a TCP connection to measure one-way RTT without spawning ping.exe.
// Port 53 (TCP-DNS) is open on all major public resolvers (8.8.8.8, 1.1.1.1…).
// Returns in actual RTT time (~50ms), never queues behind subprocess pool.
function tcpPing(host, port = 53, timeoutMs = 1500) {
    return new Promise((resolve) => {
        const start = Date.now();
        const socket = new net.Socket();
        let settled = false;
        const finish = (result) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(result);
        };
        socket.setTimeout(timeoutMs);
        socket.on('connect', () => finish({ alive: true,  latency: Date.now() - start }));
        socket.on('timeout', () => finish({ alive: false, latency: null }));
        socket.on('error',   () => finish({ alive: false, latency: null }));
        socket.connect(port, host);
    });
}

async function getWifiStats() {
    try {
        // netsh wlan show interfaces
        const netshOut = await runCmd('netsh wlan show interfaces');
        
        let interfaceName = '';
        let description = '';
        let status = 'Disconnected';
        let ssid = '';
        let bssid = '';
        let radioType = '';
        let channel = '';
        let signal = '';
        let auth = '';
        let cipher = '';
        let receiveRate = '';
        let transmitRate = '';
        
        const lines = netshOut.split('\n');
        lines.forEach(line => {
            const parts = line.split(':');
            if (parts.length < 2) return;
            const key = parts[0].trim();
            const val = parts.slice(1).join(':').trim();
            
            if (key === 'Name') interfaceName = val;
            if (key === 'Description') description = val;
            if (key === 'State') status = val === 'connected' ? 'Operational' : 'Disconnected';
            if (key === 'SSID') ssid = val;
            if (key === 'BSSID') bssid = val;
            if (key === 'Radio type') radioType = val;
            if (key === 'Channel') channel = val;
            if (key === 'Signal') signal = val;
            if (key === 'Receive rate (Mbps)') receiveRate = val;
            if (key === 'Transmit rate (Mbps)') transmitRate = val;
            if (key === 'Authentication') auth = val;
            if (key === 'Cipher') cipher = val;
        });

        // Get-NetAdapter for link speed, mac, connection type
        let linkSpeed = '';
        if (receiveRate && transmitRate) {
            linkSpeed = `${receiveRate} Mbps (Rx) / ${transmitRate} Mbps (Tx)`;
        }
        
        let connectionType = 'Wireless'; // default assumption
        let macAddress = '';
        
        try {
            const netAdapterCmd = `powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object MacAddress, MediaType, LinkSpeed | ConvertTo-Json"`;
            const netAdapterOut = await runCmd(netAdapterCmd);
            if (netAdapterOut.trim()) {
                const adapters = JSON.parse(netAdapterOut);
                const activeAdapter = Array.isArray(adapters) ? adapters[0] : adapters;
                if (activeAdapter) {
                    macAddress = activeAdapter.MacAddress;
                    connectionType = activeAdapter.MediaType === '802.3' ? 'Ethernet (802.3)' : (activeAdapter.MediaType || 'Wireless (802.11)');
                    if (!linkSpeed) {
                        linkSpeed = activeAdapter.LinkSpeed;
                    }
                }
            }
        } catch (e) {
            console.error('Error getting netadapter details', e.message);
        }

        return {
            interfaceName,
            description,
            status,
            macAddress,
            linkSpeed,
            connectionType,
            ssid,
            bssid,
            radioBand: channel ? `Channel ${channel}` : '',
            protocol: radioType,
            signalQuality: signal,
            authentication: auth && cipher ? `${auth} / ${cipher}` : ''
        };

    } catch (err) {
        console.error('Error getting wifi stats:', err.message);
        return {};
    }
}

async function getIpConfig() {
    try {
        const ipconfigOut = await runCmd('ipconfig /all');
        
        let ipv4 = '';
        let subnetMask = '';
        let defaultGateway = '';
        let dhcpServer = '';
        let leaseObtained = '';
        let leaseExpires = '';
        let dnsServers = [];
        
        let isCurrentAdapter = false;
        let adapterFound = false;

        const lines = ipconfigOut.split('\n');
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].replace('\r', '');
            
            // Check if it's an adapter section
            if (!line.startsWith(' ') && line.includes('adapter')) {
                isCurrentAdapter = true; 
            }

            if (!isCurrentAdapter) continue;
            
            const parts = line.split('. :');
            if (parts.length < 2) continue;
            const key = parts[0].trim();
            const val = parts.slice(1).join('. :').trim();
            
            if (key.includes('IPv4 Address')) {
                ipv4 = val.replace('(Preferred)', '').trim();
                adapterFound = true; 
            }
            if (key.includes('Subnet Mask')) subnetMask = val;
            if (key.includes('Default Gateway')) {
                // Prefer an IPv4 gateway; ipconfig often lists IPv6 (fe80::...) first
                // with the IPv4 address on a following continuation line.
                const ipv4Re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
                if (ipv4Re.test(val)) {
                    defaultGateway = val;
                } else {
                    let j = i + 1;
                    while (j < lines.length && lines[j].startsWith(' ') && !lines[j].includes('. :')) {
                        const cont = lines[j].replace('\r', '').trim();
                        if (ipv4Re.test(cont)) { defaultGateway = cont; break; }
                        if (cont === '') break;
                        j++;
                    }
                }
            }
            if (key.includes('DHCP Server')) dhcpServer = val;
            if (key.includes('Lease Obtained')) leaseObtained = val;
            if (key.includes('Lease Expires')) leaseExpires = val;
            if (key.includes('DNS Servers')) {
                dnsServers.push(val);
                let j = i + 1;
                while(j < lines.length && lines[j].startsWith(' ') && !lines[j].includes(':')) {
                    const extraDns = lines[j].trim();
                    if (extraDns) dnsServers.push(extraDns);
                    j++;
                }
            }
            
            if (adapterFound && line === '') {
                if (defaultGateway && ipv4) {
                    break;
                }
            }
        }

        return {
            ipv4,
            subnetMask,
            defaultGateway,
            dhcpServer,
            leaseObtained,
            leaseExpires,
            dnsServers: dnsServers.join(', ')
        };
    } catch (err) {
        console.error('Error getting ip config', err.message);
        return {};
    }
}

async function getPingStats(target) {
    if (!target || !SAFE_TARGET_RE.test(target)) return { latency: 'N/A', loss: 'N/A', jitter: 'N/A' };
    try {
        const pingOut = await runCmd(`ping -n 6 ${target}`);

        let latency = '';
        let loss = '';
        const times = [];

        const lines = pingOut.split('\n');
        lines.forEach(line => {
            if (line.includes('Lost =')) {
                const match = line.match(/Lost = \d+ \((.*?)\)/);
                if (match) loss = match[1];
            }
            if (line.includes('Average =')) {
                const match = line.match(/Average = (.*)/);
                if (match) latency = match[1].trim();
            }
            // Parse individual reply times e.g. "time=54ms" or "time<1ms"
            const timeMatch = line.match(/time[=<](\d+)ms/i);
            if (timeMatch) times.push(parseInt(timeMatch[1]));
        });

        let jitter = 'N/A';
        if (times.length >= 2) {
            let diff = 0;
            for (let i = 1; i < times.length; i++) diff += Math.abs(times[i] - times[i - 1]);
            jitter = `${(diff / (times.length - 1)).toFixed(1)} ms`;
        }

        return { latency, loss, jitter };
    } catch (err) {
        console.error('Error pinging', target, err.message);
        return { latency: 'Error', loss: 'Error', jitter: 'Error' };
    }
}

function getPublicInfo() {
    return new Promise((resolve) => {
        const req = https.get('https://ipinfo.io/json', { headers: { 'Accept': 'application/json' } }, (resp) => {
            let data = '';
            resp.on('data', (chunk) => { data += chunk; });
            resp.on('end', () => {
                try {
                    const p = JSON.parse(data);
                    resolve({
                        ip: p.ip || 'Unknown',
                        org: p.org || 'Unknown',
                        city: p.city || '',
                        country: p.country || '',
                        timezone: p.timezone || '',
                    });
                } catch(e) {
                    resolve({ ip: 'Unknown', org: 'Unknown', city: '', country: '', timezone: '' });
                }
            });
        });
        req.setTimeout(6000, () => { req.destroy(); resolve({ ip: 'Timeout', org: 'Unknown', city: '', country: '', timezone: '' }); });
        req.on('error', () => resolve({ ip: 'Error', org: 'Unknown', city: '', country: '', timezone: '' }));
    });
}

async function getDnsResolutionTime() {
    try {
        const start = performance.now();
        await dnsPromises.lookup('google.com');
        return `${(performance.now() - start).toFixed(2)} ms`;
    } catch {
        return 'Error';
    }
}

async function getThroughput() {
    try {
        // networkStats returns array of interfaces, or we can get default
        const stats = await si.networkStats();
        // sum across active interfaces or find default
        let rx_sec = 0;
        let tx_sec = 0;
        stats.forEach(iface => {
            if (iface.operstate === 'up') {
                rx_sec += iface.rx_sec || 0;
                tx_sec += iface.tx_sec || 0;
            }
        });
        
        // Convert to Mbps (Bytes/sec * 8 / 1,000,000)
        return {
            downloadMbps: ((rx_sec * 8) / 1000000).toFixed(2),
            uploadMbps: ((tx_sec * 8) / 1000000).toFixed(2)
        };
    } catch (err) {
        console.error('Error getting throughput:', err.message);
        return { downloadMbps: '0.00', uploadMbps: '0.00' };
    }
}

async function getArpDeviceCount() {
    try {
        const out = await runCmd('arp -a');
        return (out.match(/dynamic/gi) || []).length;
    } catch {
        return 0;
    }
}

// ═══════════════════════════════════════════════════════════════
// ISP TRUTH DETECTOR FEATURES
// ═══════════════════════════════════════════════════════════════

/**
 * Multi-Region Latency & Jitter Matrix
 * Pings local exchange, regional (Singapore), and Western nodes
 * to expose international routing choke points
 */
async function getGlobalPingMatrix() {
    const results = {
        localExchange: { target: '', latency: 'N/A', loss: 'N/A', jitter: 'N/A', type: 'Local Exchange' },
        singapore: { target: '1.1.1.1', latency: 'N/A', loss: 'N/A', jitter: 'N/A', type: 'Singapore (Cloudflare)' },
        usEast: { target: '8.8.8.8', latency: 'N/A', loss: 'N/A', jitter: 'N/A', type: 'US East (Google)' },
        usWest: { target: '208.67.222.222', latency: 'N/A', loss: 'N/A', jitter: 'N/A', type: 'US West (OpenDNS)' }
    };

    try {
        // Get first hop past gateway (local exchange)
        const ip = await getIpConfig();
        const gateway = ip.defaultGateway;
        
        if (gateway) {
            // Use tracert to find the first hop beyond the gateway
            try {
                const tracertOut = await runCmd(`tracert -d -h 3 -w 500 8.8.8.8`);
                const lines = tracertOut.split('\n');
                let foundGateway = false;
                
                for (const line of lines) {
                    // Look for IP addresses in tracert output
                    const ipMatch = line.match(/\d+\.\d+\.\d+\.\d+/);
                    if (ipMatch) {
                        const hopIp = ipMatch[0];
                        if (hopIp === gateway) {
                            foundGateway = true;
                        } else if (foundGateway && hopIp !== gateway) {
                            // This is the first hop after gateway (ISP's local exchange)
                            results.localExchange.target = hopIp;
                            results.localExchange = { ...results.localExchange, ...(await getPingStats(hopIp)) };
                            break;
                        }
                    }
                }
            } catch (e) {
                console.error('Error getting local exchange:', e.message);
            }
        }

        // Ping Singapore (Cloudflare) - typically ~35-50ms from Sri Lanka
        results.singapore = { ...results.singapore, ...(await getPingStats('1.1.1.1')) };
        
        // Ping US East (Google DNS)
        results.usEast = { ...results.usEast, ...(await getPingStats('8.8.8.8')) };
        
        // Ping US West (OpenDNS)
        results.usWest = { ...results.usWest, ...(await getPingStats('208.67.222.222')) };

    } catch (err) {
        console.error('Error in global ping matrix:', err.message);
    }

    return results;
}

/**
 * Real CDN Speed Test
 * Downloads a test file from a global CDN to measure true international throughput
 * without relying on ISP-whitelisted speed test servers
 */
async function runCdnSpeedTest() {
    return new Promise((resolve) => {
        // Using Cloudflare's speed test file (10MB)
        const testUrl = 'https://speed.cloudflare.com/__down?bytes=10000000';
        const startTime = Date.now();
        let downloadedBytes = 0;

        const req = https.get(testUrl, { headers: { 'User-Agent': 'NetworkDetector/1.0' } }, (resp) => {
            if (resp.statusCode !== 200) {
                return resolve({
                    success: false,
                    error: `HTTP ${resp.statusCode}`,
                    speedMbps: 0,
                    duration: 0,
                    bytesDownloaded: 0
                });
            }

            resp.on('data', (chunk) => {
                downloadedBytes += chunk.length;
            });

            resp.on('end', () => {
                const endTime = Date.now();
                const durationSeconds = (endTime - startTime) / 1000;
                const speedMbps = ((downloadedBytes * 8) / (durationSeconds * 1000000)).toFixed(2);

                resolve({
                    success: true,
                    speedMbps: parseFloat(speedMbps),
                    duration: durationSeconds.toFixed(2),
                    bytesDownloaded: downloadedBytes,
                    testServer: 'Cloudflare CDN',
                    timestamp: new Date().toISOString()
                });
            });
        });

        req.setTimeout(30000, () => {
            req.destroy();
            resolve({
                success: false,
                error: 'Timeout (30s)',
                speedMbps: 0,
                duration: 0,
                bytesDownloaded: downloadedBytes
            });
        });

        req.on('error', (err) => {
            resolve({
                success: false,
                error: err.message,
                speedMbps: 0,
                duration: 0,
                bytesDownloaded: downloadedBytes
            });
        });
    });
}

/**
 * DNS Censorship / Hijacking Detector
 * Compares DNS resolution between system DNS and independent DNS-over-HTTPS
 * to detect ISP tampering, hijacking, or DNS cache failures
 */
async function detectDnsHijacking() {
    const testDomain = 'www.google.com';
    const results = {
        domain: testDomain,
        systemDns: { ip: null, time: 0, error: null },
        doh: { ip: null, time: 0, error: null },
        hijackDetected: false,
        mismatch: false,
        analysis: ''
    };

    // Test 1: System DNS
    try {
        const startSystem = performance.now();
        const systemResult = await dnsPromises.resolve4(testDomain);
        results.systemDns.time = parseFloat((performance.now() - startSystem).toFixed(2));
        results.systemDns.ip = systemResult[0];
    } catch (err) {
        results.systemDns.error = err.message;
    }

    // Test 2: DNS-over-HTTPS (using Cloudflare's DoH)
    try {
        const startDoh = performance.now();
        const dohResult = await new Promise((resolve, reject) => {
            const dohUrl = `https://cloudflare-dns.com/dns-query?name=${testDomain}&type=A`;
            const req = https.get(dohUrl, { 
                headers: { 
                    'Accept': 'application/dns-json',
                    'User-Agent': 'NetworkDetector/1.0'
                } 
            }, (resp) => {
                let data = '';
                resp.on('data', (chunk) => { data += chunk; });
                resp.on('end', () => {
                    try {
                        const parsed = JSON.parse(data);
                        if (parsed.Answer && parsed.Answer.length > 0) {
                            resolve(parsed.Answer[0].data);
                        } else {
                            reject(new Error('No DNS answer'));
                        }
                    } catch (e) {
                        reject(e);
                    }
                });
            });
            req.setTimeout(5000, () => { req.destroy(); reject(new Error('Timeout')); });
            req.on('error', reject);
        });
        
        results.doh.time = parseFloat((performance.now() - startDoh).toFixed(2));
        results.doh.ip = dohResult;
    } catch (err) {
        results.doh.error = err.message;
    }

    // Analysis
    if (results.systemDns.error && !results.doh.error) {
        results.hijackDetected = true;
        results.analysis = '⚠️ System DNS FAILED but DoH succeeded. Your ISP may be blocking/throttling DNS.';
    } else if (!results.systemDns.error && !results.doh.error) {
        // Check if IPs are in same /16 subnet (common for CDNs with multiple IPs)
        const sameSubnet = results.systemDns.ip && results.doh.ip && 
            results.systemDns.ip.split('.').slice(0, 2).join('.') === 
            results.doh.ip.split('.').slice(0, 2).join('.');
        
        // Check if IPs are completely different organizations (first octet differs by >50)
        const systemFirst = parseInt(results.systemDns.ip.split('.')[0]);
        const dohFirst = parseInt(results.doh.ip.split('.')[0]);
        const suspiciousDifference = Math.abs(systemFirst - dohFirst) > 50;
        
        if (results.systemDns.ip !== results.doh.ip) {
            results.mismatch = true;
            
            // Only flag hijacking if IPs are from different subnets AND suspiciously different
            if (!sameSubnet && suspiciousDifference) {
                results.hijackDetected = true;
                results.analysis = '🚨 DNS HIJACKING DETECTED! System DNS returned IP from different organization than DoH.';
            } else if (!sameSubnet) {
                results.analysis = `ℹ️ DNS returned different IPs (${results.systemDns.ip} vs ${results.doh.ip}). Likely CDN load balancing — normal for Google/Cloudflare.`;
            } else {
                results.analysis = '✅ DNS healthy. Different IPs but same network (normal for CDN).';
            }
        } else if (results.systemDns.time > results.doh.time * 3) {
            results.analysis = '⚠️ System DNS is significantly slower than DoH. ISP DNS cache may be failing.';
        } else {
            results.analysis = '✅ DNS appears healthy. No hijacking detected.';
        }
    } else if (results.systemDns.error && results.doh.error) {
        results.analysis = '❌ Both DNS methods failed. Network connectivity issue.';
    } else {
        results.analysis = '✅ System DNS working normally.';
    }

    return results;
}

/**
 * Advanced Security Scan
 * Checks firewall status, VPN detection, proxy detection, and overall security posture
 */
async function runSecurityScan() {
    const results = {
        status: 'Secure',
        firewall: 'Unknown',
        vpnDetected: false,
        proxyDetected: false,
        riskLevel: 'Low',
        ssl: {
            httpsSupport: false,
            certValid: false,
            tlsVersion: 'Unknown'
        },
        threats: {
            suspicious: false,
            ddosProtection: false,
            intrusionAttempts: 0
        },
        anomalies: {
            throttling: false,
            unusualTraffic: false,
            connectionDrops: 0
        }
    };

    try {
        // Check Windows Firewall status
        try {
            const firewallOut = await runCmd('netsh advfirewall show allprofiles state');
            if (firewallOut.includes('State                                 ON')) {
                results.firewall = '✓ Enabled';
                results.threats.ddosProtection = true;
            } else {
                results.firewall = '✗ Disabled';
                results.riskLevel = 'High';
                results.status = 'At Risk';
            }
        } catch (e) {
            console.error('Error checking firewall:', e.message);
        }

        // VPN Detection - check for common VPN adapters
        try {
            const ipconfig = await runCmd('ipconfig /all');
            const vpnKeywords = ['VPN', 'TAP-Windows', 'WireGuard', 'OpenVPN', 'NordVPN', 'ExpressVPN'];
            results.vpnDetected = vpnKeywords.some(keyword => ipconfig.includes(keyword));
        } catch (e) {
            console.error('Error detecting VPN:', e.message);
        }

        // Proxy Detection - check system proxy settings
        try {
            const proxyOut = await runCmd('netsh winhttp show proxy');
            if (!proxyOut.includes('Direct access')) {
                results.proxyDetected = true;
            }
        } catch (e) {
            console.error('Error detecting proxy:', e.message);
        }

        // SSL/TLS Support check
        try {
            const testUrl = 'https://www.google.com';
            await new Promise((resolve, reject) => {
                const req = https.get(testUrl, { rejectUnauthorized: false }, (resp) => {
                    results.ssl.httpsSupport = true;
                    results.ssl.certValid = resp.socket.authorized || false;
                    results.ssl.tlsVersion = resp.socket.getProtocol() || 'Unknown';
                    resolve();
                });
                req.setTimeout(5000, () => { req.destroy(); reject(new Error('Timeout')); });
                req.on('error', reject);
            });
        } catch (e) {
            console.error('Error checking SSL:', e.message);
        }

        // Check for bandwidth throttling indicators
        const stats = await getThroughput();
        const downloadMbps = parseFloat(stats.downloadMbps);
        const uploadMbps = parseFloat(stats.uploadMbps);
        
        // If download/upload is very low during active testing, might indicate throttling
        if (downloadMbps > 0 && downloadMbps < 0.5) {
            results.anomalies.throttling = true;
            results.riskLevel = results.riskLevel === 'High' ? 'High' : 'Medium';
        }

    } catch (err) {
        console.error('Error in security scan:', err.message);
    }

    return results;
}

/**
 * Port Scan
 * Scans common ports on the local machine to identify open/listening ports
 */
async function runPortScan() {
    const results = {
        success: false,
        openPorts: [],
        scannedPorts: []
    };

    try {
        // Use netstat to find listening ports
        const netstatOut = await runCmd('netstat -ano | findstr LISTENING');
        const lines = netstatOut.split('\n');
        const portSet = new Set();

        lines.forEach(line => {
            const match = line.match(/:(\d+)\s/);
            if (match) {
                const port = parseInt(match[1]);
                if (port > 0 && port < 65536) {
                    portSet.add(port);
                }
            }
        });

        results.openPorts = Array.from(portSet).sort((a, b) => a - b);
        results.scannedPorts = results.openPorts;
        results.success = true;

    } catch (err) {
        console.error('Error in port scan:', err.message);
        results.error = err.message;
    }

    return results;
}

// ═══════════════════════════════════════════════════════════════
// ADVANCED NETWORK SECURITY TOOLS
// ═══════════════════════════════════════════════════════════════

// Minimal MAC OUI vendor map (most common manufacturers)
const OUI_VENDORS = {
    '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:1c:14': 'VMware',
    '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
    '3c:5a:b4': 'Google', 'f4:f5:e8': 'Google', '6c:ad:f8': 'Azurewave',
    '00:1a:11': 'Google', 'a4:77:33': 'Google',
    '00:25:00': 'Apple', '3c:07:54': 'Apple', '8c:85:90': 'Apple',
    '00:50:e4': 'Apple', '00:23:6c': 'Apple', 'f4:5c:89': 'Apple',
    'bc:52:b7': 'Apple', '00:0a:95': 'Apple',
    '00:1d:0f': 'TP-Link', '50:c7:bf': 'TP-Link', '60:e3:27': 'TP-Link',
    'a4:2b:b0': 'TP-Link', 'c4:6e:1f': 'TP-Link',
    '00:05:5d': 'D-Link', '00:0f:3d': 'D-Link', '00:13:46': 'D-Link',
    '00:11:32': 'Synology', '00:1b:11': 'D-Link',
    '00:1d:7e': 'Cisco', '00:18:f8': 'Cisco', '00:1a:e2': 'Cisco',
    '00:50:f1': 'Cisco', '00:24:d7': 'Intel', '00:13:02': 'Intel',
    '00:13:e8': 'Intel', '00:15:00': 'Intel', '00:16:6f': 'Intel',
    '00:19:d1': 'Intel', '00:1c:bf': 'Intel', '00:1f:3b': 'Intel',
    '00:21:6a': 'Intel', '00:22:fa': 'Intel', '00:24:d6': 'Intel',
    '50:eb:f6': 'Samsung', '38:aa:3c': 'Samsung', '90:18:7c': 'Samsung',
    '94:51:03': 'Samsung', 'cc:fe:3c': 'Samsung',
    '00:18:de': 'Xiaomi', '8c:be:be': 'Xiaomi', '78:11:dc': 'Xiaomi',
    '5c:0e:8b': 'Xiaomi', 'f0:b4:29': 'Xiaomi',
    '00:1e:c2': 'Apple', '04:0c:ce': 'Apple', '14:10:9f': 'Apple',
    '00:1f:f3': 'Apple', '40:b0:fa': 'Apple', '50:ea:d6': 'Apple',
    '00:09:bf': 'Nintendo', '00:17:ab': 'Nintendo',
    '00:1f:c1': 'Sony', '7c:ed:8d': 'Microsoft', '00:1d:d8': 'Microsoft',
    '7c:1e:52': 'Microsoft', '60:45:bd': 'Microsoft',
    '00:17:88': 'Philips', 'b0:c5:54': 'D-Link', '00:1a:79': 'Cisco-Linksys',
    'c0:c9:e3': 'ASUSTek', '38:d5:47': 'ASUSTek', '04:d4:c4': 'ASUSTek',
    '00:0e:a6': 'ASUSTek', '00:11:2f': 'ASUSTek', '00:13:d4': 'ASUSTek',
    '00:15:f2': 'ASUSTek', '00:17:31': 'ASUSTek', '00:18:f3': 'ASUSTek',
    '00:1a:92': 'ASUSTek', '00:1b:fc': 'ASUSTek', '00:1d:60': 'ASUSTek',
    '00:1e:8c': 'ASUSTek', '00:1f:c6': 'ASUSTek', '00:22:15': 'ASUSTek',
    '00:23:54': 'ASUSTek', '00:24:8c': 'ASUSTek', '00:26:18': 'ASUSTek',
    'ac:9e:17': 'ASUSTek', 'd8:50:e6': 'ASUSTek',
    '88:ae:dd': 'Huawei', '00:e0:fc': 'Huawei', '00:18:82': 'Huawei',
    '70:72:3c': 'Huawei', 'e8:cd:2d': 'Huawei',
    'c8:3a:35': 'Tenda', '00:90:4c': 'Epigram', '24:6a:73': 'Realtek',
    '00:e0:4c': 'Realtek', '52:54:01': 'Realtek',
};

function getMacVendor(mac) {
    if (!mac || typeof mac !== 'string') return 'Unknown';
    const normalized = mac.toLowerCase().replace(/-/g, ':');
    const prefix = normalized.substring(0, 8);
    return OUI_VENDORS[prefix] || 'Unknown';
}

/**
 * Get Connected Devices on Local Network
 * Parses ARP table and resolves vendor information from MAC OUI prefixes
 */
async function getConnectedDevices() {
    const result = {
        success: false,
        devices: [],
        totalCount: 0,
        gateway: null,
        timestamp: new Date().toISOString()
    };

    try {
        const ipInfo = await getIpConfig();
        result.gateway = ipInfo.defaultGateway;

        // Derive the /24 subnet base (e.g. "192.168.1") from the gateway or local IP
        const base = (() => {
            const src = result.gateway || ipInfo.ipv4 || '';
            const parts = src.split('.');
            return parts.length === 4 ? parts.slice(0, 3).join('.') : null;
        })();

        // Parallel ping sweep to populate the ARP cache before reading it.
        // Windows ping with -n 1 -w 300 is fast; we run 254 in parallel batches.
        if (base) {
            const hosts = Array.from({ length: 254 }, (_, i) => `${base}.${i + 1}`);
            const BATCH = 50;
            for (let i = 0; i < hosts.length; i += BATCH) {
                const batch = hosts.slice(i, i + BATCH);
                await Promise.all(batch.map(h =>
                    runCmd(`ping -n 1 -w 300 ${h}`, 2000).catch(() => null)
                ));
            }
        }

        const arpOut = await runCmd('arp -a');
        const lines = arpOut.split('\n');
        const seen = new Set();

        for (const line of lines) {
            const match = line.match(/^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\w+)/i);
            if (match) {
                const ip = match[1];
                const macRaw = match[2].toLowerCase();
                const macColon = macRaw.replace(/-/g, ':');
                const type = match[3].toLowerCase();

                if (ip.endsWith('.255') || ip.startsWith('224.') || ip.startsWith('239.')) continue;
                if (macColon === 'ff:ff:ff:ff:ff:ff') continue;
                if (seen.has(ip)) continue;
                // Only include IPs that match the scanned subnet
                if (base && !ip.startsWith(base + '.')) continue;
                seen.add(ip);

                const vendor = getMacVendor(macColon);
                const isGateway = ip === result.gateway;

                let hostname = '';
                try {
                    const hosts = await Promise.race([
                        dnsPromises.reverse(ip),
                        new Promise((_, rej) => setTimeout(() => rej(), 300))
                    ]);
                    if (hosts && hosts.length > 0) hostname = hosts[0];
                } catch { hostname = ''; }

                result.devices.push({
                    ip, mac: macColon, vendor,
                    hostname: hostname || '—',
                    type: type === 'dynamic' ? 'Dynamic' : 'Static',
                    isGateway,
                    role: isGateway ? '🌐 Router/Gateway' : (vendor !== 'Unknown' ? `📱 ${vendor} Device` : '💻 Unknown Device')
                });
            }
        }

        result.devices.sort((a, b) => {
            if (a.isGateway) return -1; if (b.isGateway) return 1;
            const ap = a.ip.split('.').map(Number), bp = b.ip.split('.').map(Number);
            for (let i = 0; i < 4; i++) if (ap[i] !== bp[i]) return ap[i] - bp[i];
            return 0;
        });
        result.totalCount = result.devices.length;
        result.success = true;
    } catch (err) {
        result.error = err.message;
    }
    return result;
}

/**
 * Detect ARP Spoofing
 * Checks for duplicate MAC addresses (one MAC mapped to multiple IPs)
 * which is a classic indicator of ARP poisoning / MITM attack
 */
// Track the gateway MAC across calls — real ARP spoofing shows the gateway IP
// switching to a different MAC between readings, not just multiple IPs per MAC
// (the latter is normal on any machine with VMs/VPN adapters).
const arpGatewayHistory = new Map(); // gatewayIP → Set<mac>

async function detectArpSpoofing() {
    const result = {
        spoofingDetected: false,
        suspiciousEntries: [],
        duplicateMacs: [],
        analysis: '',
        risk: 'Low'
    };

    try {
        const arpOut = await runCmd('arp -a');
        const ipToMac = {};

        arpOut.split('\n').forEach(line => {
            const match = line.match(/^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\w+)/i);
            if (match) {
                const ip = match[1];
                const mac = match[2].toLowerCase().replace(/-/g, ':');
                if (mac === 'ff:ff:ff:ff:ff:ff') return;
                ipToMac[ip] = mac;
            }
        });

        // --- Gateway MAC change detection (reliable indicator) ---
        const ipInfo = await getIpConfig();
        const gateway = ipInfo.defaultGateway;
        if (gateway && ipToMac[gateway]) {
            const gwMac = ipToMac[gateway];
            if (!arpGatewayHistory.has(gateway)) {
                arpGatewayHistory.set(gateway, new Set());
            }
            const history = arpGatewayHistory.get(gateway);
            history.add(gwMac);
            // Only flag if the gateway has been seen with TWO DIFFERENT MACs
            if (history.size > 1) {
                result.spoofingDetected = true;
                result.risk = 'High';
                const macs = [...history].join(', ');
                result.suspiciousEntries.push(`Gateway ${gateway} has been seen with multiple MACs: ${macs}`);
                result.analysis = `⚠️ Gateway MAC instability detected. ${gateway} has appeared with ${history.size} different MAC addresses across readings, which is a strong indicator of ARP spoofing.`;
                return result;
            }
        }

        // --- Duplicate-MAC check (lower confidence — flag as Medium only) ---
        // A single MAC owning multiple IPs is normal for VMs and VPN adapters.
        // We only treat it as suspicious when the shared MAC is also the gateway.
        const macToIps = {};
        for (const [ip, mac] of Object.entries(ipToMac)) {
            if (!macToIps[mac]) macToIps[mac] = [];
            macToIps[mac].push(ip);
        }
        for (const [mac, ips] of Object.entries(macToIps)) {
            if (ips.length > 1 && gateway && ips.includes(gateway)) {
                result.duplicateMacs.push({ mac, ips });
                result.suspiciousEntries.push(`Gateway MAC ${mac} also answers for ${ips.filter(i => i !== gateway).join(', ')}`);
            }
        }
        if (result.duplicateMacs.length > 0) {
            result.spoofingDetected = true;
            result.risk = 'Medium';
            result.analysis = `⚠️ Gateway MAC ${result.duplicateMacs[0].mac} responds to multiple IPs including the gateway. Possible MITM — investigate with mtr or dig.`;
        } else {
            result.analysis = '✅ No ARP spoofing detected. Gateway MAC address is stable and unique.';
        }
    } catch (err) {
        result.analysis = '❌ Could not perform ARP spoofing check.';
        result.error = err.message;
    }

    return result;
}

/**
 * DNS Leak Test
 * Resolves a domain and identifies which DNS servers actually responded.
 * Detects if traffic is leaking outside expected (configured) DNS servers.
 */
async function detectDnsLeak() {
    const result = {
        leakDetected: false,
        configuredDns: [],
        actualResolvers: [],
        publicIp: null,
        analysis: '',
        risk: 'Low'
    };

    try {
        // Get configured DNS servers
        const ipInfo = await getIpConfig();
        result.configuredDns = (ipInfo.dnsServers || '').split(',').map(s => s.trim()).filter(Boolean);

        // Resolve a test domain
        const testDomains = ['whoami.akamai.net', 'resolver.dnscrypt.info'];
        for (const domain of testDomains) {
            try {
                const start = performance.now();
                const addresses = await dnsPromises.resolve4(domain);
                const time = (performance.now() - start).toFixed(2);
                if (addresses && addresses.length > 0) {
                    result.actualResolvers.push({ domain, ip: addresses[0], time: `${time}ms` });
                }
            } catch (e) {
                // domain not resolvable - skip
            }
        }

        // Get public IP for comparison
        const publicInfo = await getPublicInfo();
        result.publicIp = publicInfo.ip;

        // Check for common privacy DNS hijacking (configured = 8.8.8.8 but resolver shows ISP IP)
        const hasPrivateDns = result.configuredDns.some(dns =>
            dns === '1.1.1.1' || dns === '8.8.8.8' || dns === '9.9.9.9' || dns === '208.67.222.222'
        );

        if (hasPrivateDns && result.actualResolvers.length > 0) {
            result.analysis = '✅ DNS appears properly configured. Using public privacy resolvers.';
        } else if (result.configuredDns.length > 0 && result.configuredDns.every(dns => dns.startsWith('192.168.') || dns.startsWith('10.') || dns.startsWith('172.'))) {
            result.analysis = '⚠️ Only ISP/router DNS detected. Your ISP can monitor all DNS queries.';
            result.risk = 'Medium';
            result.leakDetected = true;
        } else {
            result.analysis = '✅ DNS configuration looks normal.';
        }
    } catch (err) {
        console.error('Error in DNS leak test:', err.message);
        result.analysis = '❌ DNS leak test failed.';
        result.error = err.message;
    }

    return result;
}

/**
 * Wi-Fi Security Audit
 * Analyzes connection encryption, authentication strength, and recommendations
 */
async function runWifiSecurityAudit() {
    const result = {
        ssid: '',
        encryption: '',
        authentication: '',
        cipher: '',
        strengthScore: 0,
        strengthLabel: 'Unknown',
        vulnerabilities: [],
        recommendations: [],
        hiddenSsid: false
    };

    try {
        const wifi = await getWifiStats();
        result.ssid = wifi.ssid || 'N/A';
        result.authentication = wifi.authentication || 'Unknown';
        result.cipher = wifi.cipher || 'Unknown';
        result.encryption = wifi.authentication || 'Unknown';

        const auth = (wifi.authentication || '').toLowerCase();

        // Score & analyze
        if (auth.includes('wpa3')) {
            result.strengthScore = 100;
            result.strengthLabel = 'Excellent';
        } else if (auth.includes('wpa2')) {
            result.strengthScore = 80;
            result.strengthLabel = 'Strong';
            result.recommendations.push('Consider upgrading to WPA3 if your router supports it');
        } else if (auth.includes('wpa')) {
            result.strengthScore = 50;
            result.strengthLabel = 'Moderate';
            result.vulnerabilities.push('WPA (original) is vulnerable to TKIP attacks');
            result.recommendations.push('Upgrade router to WPA2/WPA3 immediately');
        } else if (auth.includes('wep')) {
            result.strengthScore = 10;
            result.strengthLabel = 'Critical';
            result.vulnerabilities.push('WEP is completely broken - can be cracked in minutes');
            result.recommendations.push('Change router encryption to WPA2/WPA3 NOW');
        } else if (auth.includes('open') || !auth) {
            result.strengthScore = 0;
            result.strengthLabel = 'No Security';
            result.vulnerabilities.push('Open network - all traffic is unencrypted');
            result.recommendations.push('Avoid sensitive activities on this network');
            result.recommendations.push('Use a VPN immediately');
        } else {
            result.strengthScore = 50;
            result.strengthLabel = 'Unknown';
        }

        // Check cipher
        const cipher = (wifi.cipher || '').toLowerCase();
        if (cipher.includes('tkip')) {
            result.vulnerabilities.push('TKIP cipher is deprecated and weak');
            result.strengthScore -= 20;
        }
        if (!cipher.includes('aes') && !cipher.includes('ccmp') && result.strengthScore > 10) {
            result.recommendations.push('Ensure AES/CCMP cipher is enabled');
        }

        // Signal-based safety (low signal can encourage downgrade attacks)
        const signalMatch = (wifi.signalQuality || '').match(/(\d+)/);
        if (signalMatch && parseInt(signalMatch[1]) < 30) {
            result.recommendations.push('Weak signal may allow attackers to perform downgrade attacks - move closer to router');
        }
    } catch (err) {
        console.error('Error in WiFi security audit:', err.message);
        result.error = err.message;
    }

    return result;
}

/**
 * MITM (Man-in-the-Middle) Quick Check
 * Combines ARP spoofing and DNS hijacking checks into a single threat assessment
 */
async function runMitmCheck() {
    const result = {
        mitmDetected: false,
        indicators: [],
        risk: 'Low',
        analysis: '',
        details: {
            arpSpoofing: false,
            dnsHijacking: false,
            certificateMismatch: false
        }
    };

    try {
        const arpResult = await detectArpSpoofing();
        result.details.arpSpoofing = arpResult.spoofingDetected;
        if (arpResult.spoofingDetected) {
            result.indicators.push('ARP table contains duplicate MAC bindings');
        }

        const dnsResult = await detectDnsHijacking();
        result.details.dnsHijacking = dnsResult.hijackDetected || false;
        if (dnsResult.hijackDetected) {
            result.indicators.push('DNS responses differ between system DNS and trusted DoH');
        }

        // SSL/cert check by hitting a known-good site
        try {
            await new Promise((resolve, reject) => {
                const req = https.get('https://www.google.com', { rejectUnauthorized: true }, (resp) => {
                    if (!resp.socket.authorized) {
                        result.details.certificateMismatch = true;
                        result.indicators.push('TLS certificate validation failed for google.com');
                    }
                    resolve();
                });
                req.setTimeout(4000, () => { req.destroy(); reject(new Error('timeout')); });
                req.on('error', (e) => {
                    if (e.code === 'CERT_HAS_EXPIRED' || e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || e.code === 'SELF_SIGNED_CERT_IN_CHAIN') {
                        result.details.certificateMismatch = true;
                        result.indicators.push(`Certificate problem: ${e.code}`);
                    }
                    resolve();
                });
            });
        } catch (e) {
            // ignore timeouts
        }

        const flagCount = Object.values(result.details).filter(Boolean).length;
        if (flagCount >= 2) {
            result.mitmDetected = true;
            result.risk = 'Critical';
            result.analysis = '🚨 Multiple MITM indicators detected. Disconnect from this network immediately.';
        } else if (flagCount === 1) {
            result.mitmDetected = true;
            result.risk = 'High';
            result.analysis = '⚠️ Suspicious activity detected. Investigate before continuing sensitive activities.';
        } else {
            result.analysis = '✅ No MITM indicators detected. Connection appears safe.';
        }
    } catch (err) {
        console.error('Error in MITM check:', err.message);
        result.analysis = '❌ MITM check failed.';
        result.error = err.message;
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════
// ADVANCED DIAGNOSTICS (v1.1.0)
// Active interface detection · detailed ping stats · Wi-Fi analyzer
// interference scan · DNS benchmark · device health · health breakdown
// ═══════════════════════════════════════════════════════════════

/**
 * Detailed Ping Statistics
 * Pings a target N times and computes avg/min/max/median/p95/jitter/loss
 */
async function pingDetailed(target, count = 10) {
    const empty = {
        target: target || 'N/A', avg: 'N/A', min: 'N/A', max: 'N/A',
        median: 'N/A', p95: 'N/A', jitter: 'N/A', loss: 'N/A', samples: 0
    };
    if (!target || !SAFE_TARGET_RE.test(target)) return empty;

    try {
        const out = await runCmd(`ping -n ${count} ${target}`);
        const times = [];
        let loss = 0;

        out.split('\n').forEach(line => {
            const tm = line.match(/time[=<](\d+)ms/i);
            if (tm) times.push(parseInt(tm[1]));
            const lm = line.match(/Lost = \d+ \((\d+)% loss\)/i);
            if (lm) loss = parseInt(lm[1]);
        });

        if (times.length === 0) return { ...empty, target, loss: `${loss}%` };

        const sorted = [...times].sort((a, b) => a - b);
        const sum = times.reduce((a, b) => a + b, 0);
        const avg = sum / times.length;
        const median = sorted[Math.floor(sorted.length / 2)];
        const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];

        let jitterSum = 0;
        for (let i = 1; i < times.length; i++) jitterSum += Math.abs(times[i] - times[i - 1]);
        const jitter = times.length > 1 ? jitterSum / (times.length - 1) : 0;

        return {
            target,
            avg: avg.toFixed(1),
            min: sorted[0],
            max: sorted[sorted.length - 1],
            median,
            p95,
            jitter: jitter.toFixed(1),
            loss: `${loss}%`,
            samples: times.length
        };
    } catch (err) {
        return { ...empty, target, error: err.message };
    }
}

/**
 * Active Interface Detection (default-route based)
 * Correctly identifies Wi-Fi vs Ethernet vs VPN by examining the default route,
 * instead of assuming the Wi-Fi adapter is in use.
 */
async function getActiveInterface() {
    const result = {
        name: '', description: '', type: 'Unknown', status: 'Unknown',
        mac: '', linkSpeed: '', duplex: '', driverVersion: '', mediaType: '', isVpn: false
    };
    try {
        const ps = `powershell -NoProfile -Command "$ErrorActionPreference='SilentlyContinue'; $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1; $a = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex; $a | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,FullDuplex,DriverVersionString,MediaType,PhysicalMediaType | ConvertTo-Json -Compress"`;
        const out = await runCmd(ps);
        const parsed = JSON.parse(out);
        const adapter = Array.isArray(parsed) ? parsed[0] : parsed;
        if (adapter) {
            result.name = adapter.Name || '';
            result.description = adapter.InterfaceDescription || '';
            result.status = adapter.Status || '';
            result.mac = adapter.MacAddress || '';
            result.linkSpeed = (typeof adapter.LinkSpeed === 'object' ? '' : adapter.LinkSpeed) || '';
            result.duplex = adapter.FullDuplex === true ? 'Full Duplex' : (adapter.FullDuplex === false ? 'Half Duplex' : '');
            result.driverVersion = adapter.DriverVersionString || '';
            result.mediaType = adapter.PhysicalMediaType || adapter.MediaType || '';

            const desc = (result.description || '').toLowerCase();
            const phys = (result.mediaType || '').toLowerCase();
            if (/vpn|tap|wireguard|openvpn|wintun|nordlynx|expressvpn/.test(desc)) {
                result.type = 'VPN'; result.isVpn = true;
            } else if (phys.includes('802.11') || phys.includes('wireless')) {
                result.type = 'Wi-Fi';
            } else if (phys.includes('802.3') || phys.includes('ethernet')) {
                result.type = 'Ethernet';
            } else {
                result.type = result.mediaType || 'Unknown';
            }
        }
    } catch (err) {
        result.error = err.message;
    }
    return result;
}

/**
 * Detailed Local Network Health (gateway)
 * Pings the gateway many times to expose local wireless congestion.
 */
async function getDetailedGatewayHealth() {
    try {
        const ip = await getIpConfig();
        const gateway = ip.defaultGateway || '';
        if (!gateway) {
            return { latency: 'N/A', loss: 'N/A', jitter: 'N/A', min: 'N/A', max: 'N/A', avg: 'N/A', samples: [], gateway: '', verdict: 'Gateway not found', cls: '' };
        }
        const stats = await pingDetailed(gateway, 10);

        let verdict = 'Unknown', cls = '';
        if (stats && stats.avg !== 'N/A') {
            const avg = parseFloat(stats.avg);
            if (avg <= 5) { verdict = 'Excellent — no local congestion'; cls = 'good'; }
            else if (avg <= 10) { verdict = 'Good'; cls = 'good'; }
            else if (avg <= 25) { verdict = 'Moderate — some local congestion'; cls = 'warn'; }
            else { verdict = 'Poor — local wireless congestion detected'; cls = 'bad'; }
        }
        return { ...stats, gateway, verdict, cls };
    } catch (err) {
        return { latency: 'N/A', loss: 'N/A', jitter: 'N/A', min: 'N/A', max: 'N/A', avg: 'N/A', samples: [], gateway: '', verdict: 'Measurement failed', cls: 'bad', error: err.message };
    }
}

/**
 * Wi-Fi Analyzer
 * Detailed wireless metrics: band, channel, RSSI (dBm), standard, Rx/Tx rates.
 */
async function getWifiAnalysis() {
    const result = {
        connected: false, ssid: '', bssid: '', band: '', channel: '',
        signalPercent: '', rssi: '', standard: '', rxRate: '', txRate: '',
        auth: '', cipher: ''
    };
    try {
        const out = await runCmd('netsh wlan show interfaces');
        let signalNum = null, channelNum = null, bandStr = '';

        out.split('\n').forEach(line => {
            const parts = line.split(':');
            if (parts.length < 2) return;
            const k = parts[0].trim();
            const v = parts.slice(1).join(':').trim();
            if (k === 'SSID') result.ssid = v;
            if (k === 'BSSID') result.bssid = v;
            if (k === 'Radio type') result.standard = v;
            if (k === 'Band') bandStr = v;
            if (k === 'Channel') { result.channel = v; channelNum = parseInt(v); }
            if (k === 'Signal') { result.signalPercent = v; signalNum = parseInt(v); }
            if (k === 'Receive rate (Mbps)') result.rxRate = `${v} Mbps`;
            if (k === 'Transmit rate (Mbps)') result.txRate = `${v} Mbps`;
            if (k === 'Authentication') result.auth = v;
            if (k === 'Cipher') result.cipher = v;
            if (k === 'State') result.connected = v.toLowerCase() === 'connected';
        });

        if (signalNum != null) result.rssi = `${Math.round(signalNum / 2 - 100)} dBm`;
        if (bandStr) result.band = bandStr;
        else if (channelNum != null) result.band = channelNum <= 14 ? '2.4 GHz' : '5 GHz';
    } catch (err) {
        result.error = err.message;
    }
    return result;
}

/**
 * Wi-Fi Interference Scan
 * Lists nearby networks and counts how many occupy each channel,
 * then recommends the least-congested 2.4 GHz channel (1/6/11).
 */
async function scanWifiNetworks() {
    const result = { networks: [], channelUsage: {}, recommendation: '', totalNetworks: 0 };
    try {
        const out = await runCmd('netsh wlan show networks mode=bssid');
        const blocks = out.split(/SSID \d+ :/).slice(1);

        for (const b of blocks) {
            const name = (b.split('\n')[0] || '').trim() || '(hidden)';
            const sigMatch = b.match(/Signal\s*:\s*(\d+)%/);
            const chMatch = b.match(/Channel\s*:\s*(\d+)/);
            const radioMatch = b.match(/Radio type\s*:\s*(.+)/);
            const channel = chMatch ? parseInt(chMatch[1]) : null;
            const signal = sigMatch ? parseInt(sigMatch[1]) : null;
            result.networks.push({
                ssid: name,
                channel,
                signal,
                radio: radioMatch ? radioMatch[1].trim() : '',
                band: channel ? (channel <= 14 ? '2.4 GHz' : '5 GHz') : ''
            });
            if (channel) result.channelUsage[channel] = (result.channelUsage[channel] || 0) + 1;
        }

        result.totalNetworks = result.networks.length;
        // sort by signal desc
        result.networks.sort((a, b) => (b.signal || 0) - (a.signal || 0));

        // recommend best of 1/6/11 for 2.4 GHz
        const counts = { 1: 0, 6: 0, 11: 0 };
        for (const n of result.networks) {
            if (n.channel && n.channel <= 14) {
                const nearest = [1, 6, 11].reduce((p, c) => Math.abs(c - n.channel) < Math.abs(p - n.channel) ? c : p);
                counts[nearest]++;
            }
        }
        const best = Object.entries(counts).sort((a, b) => a[1] - b[1])[0];
        result.recommendation = `Channel ${best[0]} is least congested (${best[1]} overlapping networks) for 2.4 GHz.`;
    } catch (err) {
        result.error = err.message;
    }
    return result;
}

/**
 * DNS Provider Benchmark
 * Times resolution across major public resolvers and recommends the fastest.
 */
async function getDnsBenchmark() {
    const providers = [
        { name: 'Cloudflare', ip: '1.1.1.1' },
        { name: 'Google', ip: '8.8.8.8' },
        { name: 'Quad9', ip: '9.9.9.9' },
        { name: 'OpenDNS', ip: '208.67.222.222' }
    ];
    const testDomain = 'www.wikipedia.org';

    // Test all providers in parallel — cuts benchmark time from up to 10s to max(individual).
    const testOne = async (p) => {
        try {
            const r = new dnsPromises.Resolver();
            r.setServers([p.ip]);
            const start = performance.now();
            await Promise.race([
                r.resolve4(testDomain),
                new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 2500))
            ]);
            return { ...p, time: parseFloat((performance.now() - start).toFixed(1)), status: 'ok' };
        } catch {
            return { ...p, time: null, status: 'fail' };
        }
    };

    const results = await Promise.all(providers.map(testOne));
    const ok = results.filter(r => r.status === 'ok').sort((a, b) => a.time - b.time);
    return {
        results,
        fastest: ok[0] || null,
        recommendation: ok[0]
            ? `Fastest DNS: ${ok[0].name} (${ok[0].ip}) at ${ok[0].time}ms — set this in your adapter for snappier browsing.`
            : 'No public DNS providers reachable.'
    };
}

/**
 * Device Health
 * CPU, RAM, and battery/power state that can silently throttle Wi-Fi performance.
 */
async function getDeviceHealth() {
    const result = { recommendations: [] };
    try {
        const [load, mem, battery] = await Promise.all([
            si.currentLoad(),
            si.mem(),
            si.battery()
        ]);
        result.cpuLoad = Math.round(load.currentLoad || 0);
        const usedBytes = mem.active || (mem.total - mem.available);
        result.memTotalGB = (mem.total / 1073741824).toFixed(1);
        result.memUsedGB = (usedBytes / 1073741824).toFixed(1);
        result.memUsedPercent = Math.round((usedBytes / mem.total) * 100);
        result.hasBattery = battery.hasBattery;
        result.batteryPercent = battery.hasBattery ? battery.percent : null;
        result.onBattery = battery.hasBattery ? !battery.acConnected : false;

        if (result.cpuLoad > 85) result.recommendations.push('High CPU usage may limit network throughput — close heavy apps.');
        if (result.memUsedPercent > 90) result.recommendations.push('High RAM usage — free memory for better performance.');
        if (result.onBattery) result.recommendations.push('On battery — Windows power saving may throttle the Wi-Fi adapter. Plug in for best speed.');
        if (result.recommendations.length === 0) result.recommendations.push('System resources are healthy.');
    } catch (err) {
        result.error = err.message;
    }
    return result;
}

/**
 * Health Score Breakdown + Intelligent Recommendations
 * Computes per-category scores (internet, wifi, latency, stability, dns,
 * security, streaming, gaming) and generates actionable advice.
 */
async function getHealthBreakdown() {
    const result = { categories: {}, overall: 0, recommendations: [] };
    try {
        const ipInfo = await getIpConfig();
        const [gw, ext, wifi, dnsBench] = await Promise.all([
            pingDetailed(ipInfo.defaultGateway || '', 6),
            pingDetailed('8.8.8.8', 6),
            getWifiAnalysis(),
            getDnsBenchmark()
        ]);

        const extAvg = ext && ext.avg !== 'N/A' ? parseFloat(ext.avg) : 0;
        const extJit = ext && ext.jitter !== 'N/A' ? parseFloat(ext.jitter) : 0;
        const extLoss = ext && ext.loss !== 'N/A' ? parseInt(ext.loss) : 0;
        const gwAvg = gw && gw.avg !== 'N/A' ? parseFloat(gw.avg) : 0;
        const sig = wifi.signalPercent ? parseInt(wifi.signalPercent) : 100;

        // Latency
        let latency = 100;
        if (extAvg > 200) latency = 40; else if (extAvg > 100) latency = 65; else if (extAvg > 50) latency = 85;

        // Stability
        let stability = 100;
        stability -= extLoss * 4;
        if (extJit > 50) stability -= 30; else if (extJit > 30) stability -= 18; else if (extJit > 15) stability -= 8;
        stability = Math.max(0, stability);

        // Wi-Fi
        let wifiScore = 100;
        if (wifi.connected) {
            if (sig < 40) wifiScore = 45; else if (sig < 60) wifiScore = 70; else if (sig < 75) wifiScore = 88;
            if (wifi.band === '2.4 GHz') wifiScore = Math.max(0, wifiScore - 10);
        }

        // Internet (local link to router)
        let internet = 100;
        if (gwAvg > 25) internet = 60; else if (gwAvg > 10) internet = 80;

        // DNS
        let dnsScore = 90;
        if (dnsBench.fastest) {
            if (dnsBench.fastest.time > 60) dnsScore = 70; else if (dnsBench.fastest.time > 30) dnsScore = 85;
        }

        // Security (baseline — detailed in Security tab)
        let security = 100;
        const auth = (wifi.auth || '').toLowerCase();
        if (auth.includes('open') || !auth) security = 30;
        else if (auth.includes('wep')) security = 25;
        else if (auth.includes('wpa') && !auth.includes('wpa2') && !auth.includes('wpa3')) security = 60;

        result.categories = {
            internet, wifi: wifiScore, latency, stability, security, dns: dnsScore,
            streaming: Math.round(latency * 0.3 + stability * 0.4 + wifiScore * 0.3),
            gaming: Math.round(latency * 0.5 + stability * 0.4 + wifiScore * 0.1)
        };

        const core = [internet, wifiScore, latency, stability, security, dnsScore];
        result.overall = Math.round(core.reduce((a, b) => a + b, 0) / core.length);

        // Recommendations
        if (wifi.connected && wifi.band === '2.4 GHz')
            result.recommendations.push({ type: 'warn', text: 'Connected on 2.4 GHz — switch to 5 GHz for faster, less congested Wi-Fi.' });
        if (wifi.connected && sig < 60)
            result.recommendations.push({ type: 'warn', text: `Wi-Fi signal is ${wifi.signalPercent} — move closer to the router or add a mesh node.` });
        if (extAvg > 150)
            result.recommendations.push({ type: 'warn', text: 'High internet latency — likely ISP routing. Compare at different times of day.' });
        if (extLoss > 0)
            result.recommendations.push({ type: 'bad', text: `${extLoss}% packet loss to the internet — contact your ISP if it persists.` });
        if (gwAvg > 15)
            result.recommendations.push({ type: 'warn', text: 'High latency to your router — local Wi-Fi congestion or interference.' });
        if (security < 70)
            result.recommendations.push({ type: 'bad', text: 'Weak Wi-Fi encryption detected — upgrade your router to WPA2/WPA3.' });
        if (dnsBench.fastest && dnsBench.fastest.time > 40)
            result.recommendations.push({ type: 'warn', text: dnsBench.recommendation });
        if (result.recommendations.length === 0)
            result.recommendations.push({ type: 'good', text: 'Network is healthy. No issues detected.' });

        result.dnsBenchmark = dnsBench;
        result.wifi = wifi;
        result.gateway = gw;
        result.external = ext;
    } catch (err) {
        result.error = err.message;
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════
// SPEED PHASES · ROUTE ANALYSIS · STABILITY (v1.2.0)
// ═══════════════════════════════════════════════════════════════

function isPublicIp(ip) {
    const o = ip.split('.').map(Number);
    if (o.length !== 4 || o.some(isNaN)) return false;
    if (o[0] === 10) return false;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
    if (o[0] === 192 && o[1] === 168) return false;
    if (o[0] === 127 || o[0] === 0) return false;
    if (o[0] === 169 && o[1] === 254) return false;
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return false; // CGNAT
    return true;
}

// In-memory cache for ipinfo.io results — same ISP hops repeat across every
// route trace, so caching eliminates redundant API calls and prevents rate-limiting.
const geoCache = new Map();

function ipGeo(ip) {
    if (geoCache.has(ip)) return Promise.resolve(geoCache.get(ip));
    return new Promise((resolve) => {
        const req = https.get(`https://ipinfo.io/${ip}/json`, { headers: { 'Accept': 'application/json' } }, (resp) => {
            let d = '';
            resp.on('data', c => d += c);
            resp.on('end', () => {
                try {
                    const p = JSON.parse(d);
                    const result = { org: p.org || '', country: p.country || '', city: p.city || '' };
                    geoCache.set(ip, result);
                    resolve(result);
                }
                catch { resolve({ org: '', country: '', city: '' }); }
            });
        });
        req.setTimeout(2500, () => { req.destroy(); resolve({ org: '', country: '', city: '' }); });
        req.on('error', () => resolve({ org: '', country: '', city: '' }));
    });
}

async function pingAvgMs(target, count) {
    try {
        const out = await runCmd(`ping -n ${count} ${target}`);
        const times = [];
        out.split('\n').forEach(l => { const m = l.match(/time[=<](\d+)ms/i); if (m) times.push(parseInt(m[1])); });
        if (!times.length) return 0;
        return times.reduce((a, b) => a + b, 0) / times.length;
    } catch { return 0; }
}

/**
 * Speed Test Phase Breakdown + Bufferbloat
 * Uses Windows' built-in curl.exe to time DNS / TCP / TLS / TTFB / total,
 * then measures latency increase under load (bufferbloat).
 */
async function runSpeedDiagnostics() {
    const result = { phases: null, bufferbloat: null };

    // Phase breakdown on a 25MB download from Cloudflare
    try {
        const url = 'https://speed.cloudflare.com/__down?bytes=25000000';
        const fmt = 'dns=%{time_namelookup};conn=%{time_connect};tls=%{time_appconnect};ttfb=%{time_starttransfer};total=%{time_total};speed=%{speed_download}';
        const out = await runCmd(`curl.exe -s --max-time 20 -o NUL -w "${fmt}" "${url}"`, 25000);
        const get = (k) => { const m = out.match(new RegExp(`${k}=([\\d.]+)`)); return m ? parseFloat(m[1]) : 0; };
        const dns = get('dns'), conn = get('conn'), tls = get('tls'), ttfb = get('ttfb'), total = get('total'), speed = get('speed');
        result.phases = {
            dnsLookupMs: (dns * 1000).toFixed(1),
            tcpConnectMs: ((conn - dns) * 1000).toFixed(1),
            tlsHandshakeMs: (tls > 0 ? (tls - conn) * 1000 : 0).toFixed(1),
            ttfbMs: ((ttfb - (tls > 0 ? tls : conn)) * 1000).toFixed(1),
            totalMs: (total * 1000).toFixed(0),
            downloadMbps: ((speed * 8) / 1000000).toFixed(2)
        };
    } catch (e) {
        result.phases = { error: e.message };
    }

    // Bufferbloat: idle latency vs latency during a sustained download
    try {
        const idle = await pingAvgMs('8.8.8.8', 5);
        const dl = runCmd('curl.exe -s --max-time 10 -o NUL "https://speed.cloudflare.com/__down?bytes=50000000"', 12000).catch(() => {});
        await new Promise(r => setTimeout(r, 1500));
        const loaded = await pingAvgMs('8.8.8.8', 6);
        await dl;
        const increase = Math.max(0, loaded - idle);
        let grade, verdict;
        if (increase < 30) { grade = 'A'; verdict = 'Excellent — no bufferbloat'; }
        else if (increase < 60) { grade = 'B'; verdict = 'Good — minor bufferbloat'; }
        else if (increase < 100) { grade = 'C'; verdict = 'Fair — noticeable under load'; }
        else if (increase < 200) { grade = 'D'; verdict = 'Poor — laggy when busy'; }
        else { grade = 'F'; verdict = 'Bad — severe bufferbloat (enable SQM/QoS on router)'; }
        result.bufferbloat = {
            idleLatency: idle.toFixed(1),
            loadedLatency: loaded.toFixed(1),
            increase: increase.toFixed(1),
            grade, verdict
        };
    } catch (e) {
        result.bufferbloat = { error: e.message };
    }

    return result;
}

/**
 * Route Analysis (traceroute)
 * Builds a full hop table via Windows tracert and enriches public hops
 * with ISP/country via geolocation. Highlights where latency jumps.
 */
async function getRouteAnalysis(target = '8.8.8.8', geo = true) {
    const result = { target, hops: [], analysis: '' };
    if (!SAFE_TARGET_RE.test(target)) { result.error = 'Invalid target'; return result; }

    try {
        const out = await runCmd(`tracert -d -h 15 -w 500 ${target}`, 60000);
        const hops = [];
        out.split(/\r?\n/).forEach(line => {
            const hm = line.match(/^\s*(\d+)\s+(.*)$/);
            if (!hm) return;
            const hop = parseInt(hm[1]);
            const rest = hm[2];
            const ipMatch = rest.match(/(\d+\.\d+\.\d+\.\d+)/);
            const times = [...rest.matchAll(/[<]?(\d+)\s*ms/gi)].map(x => parseInt(x[1]));
            if (/Request timed out/i.test(rest) || !ipMatch) {
                hops.push({ hop, ip: '*', avg: null, timeout: true });
            } else {
                const avg = times.length ? times.reduce((a, b) => a + b, 0) / times.length : null;
                hops.push({ hop, ip: ipMatch[1], avg: avg != null ? avg.toFixed(0) : null, timeout: false });
            }
        });

        // Geo-enrich (public hops in parallel — sequential lookups were the
        // main source of slowness on long routes)
        if (geo) {
            await Promise.all(hops.map(async (h) => {
                if (h.ip && h.ip !== '*' && isPublicIp(h.ip)) {
                    const g = await ipGeo(h.ip);
                    h.isp = g.org || '—';
                    h.country = g.country || '';
                    h.city = g.city || '';
                } else if (h.ip && h.ip !== '*') {
                    h.isp = 'Private / LAN';
                    h.country = '';
                }
            }));
        }

        // Find biggest latency jump between consecutive responding hops
        let prevAvg = null, maxJump = 0, jumpHop = null;
        for (const h of hops) {
            if (h.avg != null) {
                const a = parseFloat(h.avg);
                if (prevAvg != null && (a - prevAvg) > maxJump) { maxJump = a - prevAvg; jumpHop = h.hop; }
                prevAvg = a;
            }
        }
        result.hops = hops;
        result.analysis = jumpHop
            ? `Largest latency jump (+${maxJump.toFixed(0)} ms) at hop ${jumpHop}. If this is an ISP hop, that's your bottleneck.`
            : 'Route traced. No single large latency jump detected.';
    } catch (e) {
        result.error = e.message;
    }
    return result;
}

/**
 * Quick single connectivity check.
 * Uses a TCP socket instead of spawning ping.exe — returns in one RTT (~50ms)
 * and never competes with the subprocess pool, fixing the stability-test delay.
 */
async function getQuickPing(target = '8.8.8.8') {
    if (!SAFE_TARGET_RE.test(target)) return { alive: false, latency: null };
    return tcpPing(target, 53, 1500).catch(() => ({ alive: false, latency: null }));
}

/**
 * Wi-Fi Adapter Capabilities
 * Extracts which bands (2.4/5/6 GHz) and standards (802.11a/ac/ax…) the
 * physical NIC supports — regardless of what band it's currently connected to.
 */
async function getWifiCapabilities() {
    const result = { supportedBands: [], isDualBand: false, supportedStandards: [], driver: '', vendor: '', error: null };
    try {
        const out = await runCmd('netsh wlan show drivers');
        // Radio types line, e.g. "802.11b 802.11g 802.11n 802.11a 802.11ac 802.11ax"
        const radioM = out.match(/Radio types supported\s*:\s*(.+)/i);
        if (radioM) {
            const radios = radioM[1].trim().split(/\s+/).map(r => r.trim()).filter(Boolean);
            result.supportedStandards = radios;
            // 802.11a/ac/ax/n-on-5GHz all imply 5 GHz support
            if (radios.some(r => /802\.11[a]$/i.test(r) || /802\.11ac/i.test(r) || /802\.11ax/i.test(r))) result.supportedBands.push('5 GHz');
            if (radios.some(r => /802\.11[bgn]/i.test(r))) result.supportedBands.push('2.4 GHz');
            if (radios.some(r => /802\.11be/i.test(r))) result.supportedBands.push('6 GHz');
            // 802.11n adapters can be 2.4-only or dual-band; treat n+a as dual
            if (!result.supportedBands.includes('2.4 GHz') && radios.some(r => /802\.11n/i.test(r))) result.supportedBands.push('2.4 GHz');
        }
        const driverM = out.match(/Driver\s*:\s*(.+)/i);
        const vendorM = out.match(/Vendor\s*:\s*(.+)/i);
        if (driverM) result.driver = driverM[1].trim();
        if (vendorM) result.vendor = vendorM[1].trim();
        result.isDualBand = result.supportedBands.length >= 2;
    } catch (err) {
        result.error = err.message;
    }
    return result;
}

module.exports = {
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
    pingDetailed,
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
};
