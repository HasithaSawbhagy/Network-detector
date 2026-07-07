/**
 * Router Admin Integration
 * Tries to read connected-device lists from home routers using their
 * built-in REST/SOAP APIs. Supports:
 *   - TP-Link Archer (modern REST via cgi-bin/luci)
 *   - TP-Link TL-WR/older (form-based, MD5 auth)
 *   - ASUS (REST /appGet.cgi + token)
 *   - Generic UPnP / fallback open-in-browser
 *
 * NOTE: Credentials are sent only to the local gateway (never leave LAN).
 */

const http = require('http');
const { createHash } = require('crypto');

// ── Tiny HTTP helper ────────────────────────────────────────────────────────
function httpReq(method, url, body, extraHeaders = {}, timeoutMs = 6000) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const payload = body != null ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
        const req = http.request({
            hostname: u.hostname,
            port: parseInt(u.port) || 80,
            path: u.pathname + u.search,
            method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': payload ? Buffer.byteLength(payload) : 0,
                Accept: 'application/json, text/html',
                ...extraHeaders
            },
            timeout: timeoutMs
        }, (res) => {
            let raw = '';
            res.on('data', d => raw += d);
            res.on('end', () => {
                let parsed = null;
                try { parsed = JSON.parse(raw); } catch { /* HTML page */ }
                resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw });
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        if (payload) req.write(payload);
        req.end();
    });
}

// ── Brand auto-detection ────────────────────────────────────────────────────
async function detectBrand(ip) {
    try {
        const r = await httpReq('GET', `http://${ip}/`, null, {}, 3000);
        let text = (r.raw || '').toLowerCase();
        const server = (r.headers?.server || '').toLowerCase();
        const auth = (r.headers?.['www-authenticate'] || '').toLowerCase();
        const title = (text.match(/<title>(.*?)<\/title>/)?.[1] || '');

        // Follow one redirect (many ONTs 302 to /admin/login.asp) to read branding
        const loc = r.headers?.location;
        if (r.status >= 300 && r.status < 400 && loc) {
            try {
                const lr = await httpReq('GET', new URL(loc, `http://${ip}`).href, null, {}, 3000);
                text += ' ' + (lr.raw || '').toLowerCase();
            } catch { /* ignore */ }
        }

        if (text.includes('tp-link') || text.includes('tplink') || server.includes('tplink')) return 'tplink';
        if (text.includes('asus router') || server.includes('asus')) return 'asus';
        if (text.includes('d-link') || text.includes('dlink') || server.includes('dlink')) return 'dlink';
        if (text.includes('netgear') || server.includes('netgear')) return 'netgear';
        if (text.includes('mikrotik') || server.includes('routeros')) return 'mikrotik';
        if (text.includes('huawei') || text.includes('echolife') || text.includes('hg8')) return 'huawei';
        if (text.includes('zte') || text.includes('zxhn')) return 'zte';
        if (text.includes('sltmobitel') || text.includes('slt') || text.includes('broadband device') || /hg\d/.test(title)) return 'broadband-ont';
        // Boa / GoAhead / mini_httpd are embedded servers used by Realtek/Broadcom ONTs
        if (server.includes('boa') || server.includes('goahead') || server.includes('mini_httpd') || text.includes('/boaform/')) return 'broadband-ont';
        if (auth.includes('basic')) return 'basic-auth';
    } catch { /* unreachable or timeout */ }
    return 'unknown';
}

// ── Realtek / Boa SDK ONT (SLT HG-series, many ISP routers) ─────────────────
// Login via form POST → session cookie → scrape DHCP/client pages for IP+MAC.
async function boaRealtekRouter(ip, user, pass) {
    // 1) Log in and capture the session cookie
    const form = `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}&submit-url=%2Fadmin%2Flogin.asp&postSecurityFlag=`;
    let cookie = '';
    try {
        const lr = await httpReq('POST', `http://${ip}/boaform/admin/formLogin`, form,
            { 'Content-Type': 'application/x-www-form-urlencoded', Referer: `http://${ip}/admin/login.asp` });
        cookie = (lr.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
        // Some firmwares reject bad creds with the login page again
        if (/login\.asp|username|password error|invalid/i.test(lr.raw || '') && !cookie) {
            throw new Error('Router login failed — check username/password');
        }
    } catch (e) {
        throw new Error('Router login failed — ' + e.message);
    }

    // 2) Scan common Realtek-SDK client/DHCP pages for IP+MAC pairs
    const candidates = [
        '/admin/dhcpclient.asp', '/admin/status_deviceinfo.asp', '/admin/dev_info.asp',
        '/admin/lan_dhcp.asp', '/admin/status_lan.asp', '/admin/assocaintedptmm.asp',
        '/admin/wlanaccess.asp', '/admin/wlstationlist.asp', '/admin/wlbasic.asp',
        '/admin/lanhostinfo.asp', '/admin/dhcp_clients.asp', '/saveconf.asp'
    ];
    const devices = [];
    const seen = new Set();
    const headers = cookie ? { Cookie: cookie } : {};
    const rowRe = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s\S]{0,160}?([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})/g;
    const rowReMacFirst = /([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})[\s\S]{0,160}?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;

    for (const path of candidates) {
        try {
            const r = await httpReq('GET', `http://${ip}${path}`, null, headers, 4000);
            if (!r.raw || r.status >= 400) continue;
            for (const [re, ipIdx, macIdx] of [[rowRe, 1, 2], [rowReMacFirst, 2, 1]]) {
                let m; re.lastIndex = 0;
                while ((m = re.exec(r.raw))) {
                    const dip = m[ipIdx];
                    const dmac = m[macIdx].replace(/-/g, ':').toLowerCase();
                    if (dip === ip || dmac === '00:00:00:00:00:00' || dmac === 'ff:ff:ff:ff:ff:ff') continue;
                    const key = dip + dmac;
                    if (seen.has(key)) continue;
                    seen.add(key);
                    devices.push({ ip: dip, mac: dmac, hostname: '—', type: '—', connected: true });
                }
            }
            if (devices.length) return { brand: 'SLT / Realtek ONT', devices };
        } catch { /* next */ }
    }
    return { brand: 'SLT / Realtek ONT', devices };
}

// ── TP-Link Archer (modern REST API) ───────────────────────────────────────
async function tplinkArcher(ip, _user, pass) {
    // Step 1: login — try plain password, then MD5
    let stok = null;
    for (const pwd of [pass, createHash('md5').update(pass).digest('hex').toUpperCase()]) {
        try {
            const r = await httpReq('POST', `http://${ip}/cgi-bin/luci/;stok=/login`,
                { method: 'do', login: { password: pwd } });
            if (r.body?.error_code === 0 && r.body?.data?.stok) {
                stok = r.body.data.stok; break;
            }
        } catch { /* try next */ }
    }
    if (!stok) throw new Error('TP-Link login failed — wrong password or unsupported model');

    const base = `http://${ip}/cgi-bin/luci/;stok=${stok}`;
    const devices = [];

    // Step 2a: wireless client list
    try {
        const r = await httpReq('POST', `${base}/admin/wireless`,
            { method: 'get', client_list: {} });
        const data = r.body?.data;
        if (data) {
            Object.values(data).forEach(band => {
                if (!Array.isArray(band)) return;
                band.forEach(c => {
                    if (c?.mac) devices.push({
                        ip: c.ip || '—', mac: c.mac,
                        hostname: c.hostname || c.name || '—',
                        band: c.band || '—', type: 'Wireless', connected: true
                    });
                });
            });
        }
    } catch { /* try alternative */ }

    // Step 2b: host info (covers wired + wireless)
    if (devices.length === 0) {
        try {
            const r = await httpReq('POST', `${base}/admin/status`, { method: 'get', host_info: {} });
            const hosts = r.body?.data?.host_info;
            if (hosts) {
                Object.values(hosts).forEach(h => {
                    if (h?.mac) devices.push({
                        ip: h.ip || '—', mac: h.mac,
                        hostname: h.hostname || h.name || '—',
                        type: h.type === 1 ? 'Wireless' : (h.type === 2 ? 'Wired' : '—'),
                        connected: true
                    });
                });
            }
        } catch { /* best effort */ }
    }

    return { brand: 'TP-Link Archer', devices };
}

// ── ASUS (httpd REST) ─────────────────────────────────────────────────────
async function asusRouter(ip, user, pass) {
    const auth = Buffer.from(`${user}:${pass}`).toString('base64');
    // Login
    const lr = await httpReq('POST', `http://${ip}/login.cgi`,
        `login_authorization=${auth}`,
        { 'Content-Type': 'application/x-www-form-urlencoded' });
    const asus_token = lr.headers['set-cookie']?.join(';').match(/asus_token=([^;]+)/)?.[1];
    if (!asus_token) throw new Error('ASUS login failed');

    const dr = await httpReq('GET', `http://${ip}/appGet.cgi?hook=get_clientlist()`,
        null, { Cookie: `asus_token=${asus_token}` });
    const raw = dr.body?.get_clientlist || {};
    const devices = Object.values(raw)
        .filter(c => c?.mac)
        .map(c => ({ ip: c.ip || '—', mac: c.mac, hostname: c.name || '—', type: c.type === '1' ? 'Wireless' : 'Wired', connected: c.isOnline === '1' }));
    return { brand: 'ASUS', devices };
}

// ── Generic scraper (Basic-auth / open pages) ───────────────────────────────
// Best-effort: tries common DHCP/LAN client-list pages and extracts any
// IP+MAC pairs from the returned HTML. Works on many Realtek/Broadcom-SDK
// broadband ONTs (SLT HG-series, Huawei, ZTE) that expose a client table.
async function genericScrape(ip, user, pass) {
    const auth = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
    const candidates = [
        '/',
        '/status_deviceinfo.asp', '/status_lan.asp', '/lan_dhcp.asp', '/RgDhcp.asp',
        '/dhcpinfo.html', '/DHCPClient.htm', '/dhcpclient.html',
        '/wlstationlist.cmd', '/arp.cmd', '/statsifc.html',
        '/DevInfo.htm', '/status_pon.asp', '/network_lan.asp',
        '/html/status/lanstatus.asp', '/cgi-bin/lan.cgi'
    ];
    const devices = [];
    const seen = new Set();
    // Match an IP followed (within a short span) by a MAC address — covers most
    // HTML table layouts regardless of column order.
    const rowRe = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s\S]{0,160}?([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})/g;

    for (const path of candidates) {
        try {
            const r = await httpReq('GET', `http://${ip}${path}`, null, { Authorization: auth }, 4000);
            if (!r.raw || r.status >= 400) continue;
            let m;
            rowRe.lastIndex = 0;
            while ((m = rowRe.exec(r.raw))) {
                const dip = m[1];
                const dmac = m[2].replace(/-/g, ':').toLowerCase();
                if (dip === ip || dmac === '00:00:00:00:00:00' || dmac === 'ff:ff:ff:ff:ff:ff') continue;
                const key = dip + dmac;
                if (seen.has(key)) continue;
                seen.add(key);
                devices.push({ ip: dip, mac: dmac, hostname: '—', type: '—', connected: true });
            }
            if (devices.length) return { brand: 'Broadband ONT (generic)', devices };
        } catch { /* try next path */ }
    }
    return { brand: 'Broadband ONT (generic)', devices };
}

// ── Main entry point ────────────────────────────────────────────────────────
async function getRouterDevices(ip, user, pass) {
    const result = { success: false, brand: 'Unknown', model: '', devices: [], error: null, tip: '', adminUrl: `http://${ip}` };
    if (!ip) { result.error = 'No gateway IP'; return result; }

    const brand = await detectBrand(ip);
    const brandNames = {
        tplink: 'TP-Link', asus: 'ASUS', dlink: 'D-Link', netgear: 'Netgear',
        mikrotik: 'MikroTik', huawei: 'Huawei', zte: 'ZTE',
        'broadband-ont': 'Broadband ONT (SLT / ISP router)', 'basic-auth': 'Generic router', unknown: 'Unknown'
    };
    result.brand = brandNames[brand] || 'Unknown';

    if (!user && !pass) {
        result.error = 'Enter router admin credentials to fetch the device list.';
        return result;
    }

    // Choose scrapers in priority order based on detected brand
    const attempts = [];
    if (brand === 'tplink') attempts.push(() => tplinkArcher(ip, user, pass));
    if (brand === 'asus') attempts.push(() => asusRouter(ip, user, pass));
    // SLT / Realtek / Boa ONTs use a session-cookie form login
    if (brand === 'broadband-ont' || brand === 'unknown' || brand === 'basic-auth') {
        attempts.push(() => boaRealtekRouter(ip, user, pass));
    }
    // Generic scrape works for basic-auth pages and unknowns
    attempts.push(() => genericScrape(ip, user, pass));
    // As a last resort also try the vendor APIs for unknown devices
    if (brand === 'unknown' || brand === 'basic-auth') {
        attempts.push(() => tplinkArcher(ip, user, pass));
    }

    let lastError = null;
    for (const attempt of attempts) {
        try {
            const r = await attempt();
            if (r.devices && r.devices.length > 0) {
                result.devices = r.devices;
                result.brand = r.brand || result.brand;
                result.success = true;
                return result;
            }
        } catch (e) {
            lastError = e.message;
        }
    }

    // Nothing worked — be honest and point the user to the working Open Admin Page
    result.success = false;
    result.error = `Automatic device fetch isn't supported for this router (${result.brand}).`;
    result.tip = 'Click "Open Admin Page", then go to the LAN or DHCP section to see connected devices. The nmap scan under WSL Tools also discovers most devices.';
    return result;
}

module.exports = { getRouterDevices, detectBrand };
