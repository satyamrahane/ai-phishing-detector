import os
import re

FRONTEND_DIR = "frontend"

def patch_links(content):
    # Regex to replace href="#" for the nav elements
    content = re.sub(r'href="[^"]*"(.*?>Home<)', r'href="index.html"\1', content)
    content = re.sub(r'href="[^"]*"(.*?>Scanner<)', r'href="scanner.html"\1', content)
    content = re.sub(r'href="[^"]*"(.*?>Dashboard<)', r'href="dashboard.html"\1', content)
    content = re.sub(r'href="[^"]*"(.*?>About<)', r'href="report.html"\1', content) # Stitch dashboard had About instead of Report? Let's fix global navs.
    content = re.sub(r'href="[^"]*"(.*?>Login<)', r'href="login.html"\1', content)
    return content

# 1. Update Index.html
with open(os.path.join(FRONTEND_DIR, 'index.html'), 'r', encoding='utf-8') as f:
    idx = f.read()

idx = patch_links(idx)
with open(os.path.join(FRONTEND_DIR, 'index.html'), 'w', encoding='utf-8') as f:
    f.write(idx)

# 2. Update Dashboard.html
with open(os.path.join(FRONTEND_DIR, 'dashboard.html'), 'r', encoding='utf-8') as f:
    dash = f.read()

dash = patch_links(dash)
# Inject IDs into stat cards
dash = dash.replace('<p class="text-blue-400 font-mono text-3xl font-bold">12,842</p>', '<p id="statTotal" class="text-blue-400 font-mono text-3xl font-bold">0</p>')
dash = dash.replace('<p class="text-red-400 font-mono text-3xl font-bold">432</p>', '<p id="statPhishing" class="text-red-400 font-mono text-3xl font-bold">0</p>')
dash = dash.replace('<p class="text-yellow-400 font-mono text-3xl font-bold">1,056</p>', '<p id="statSuspicious" class="text-yellow-400 font-mono text-3xl font-bold">0</p>')
dash = dash.replace('<p class="text-primary font-mono text-3xl font-bold">11,354</p>', '<p id="statSafe" class="text-primary font-mono text-3xl font-bold">0</p>')

# Inject ID into tbody
dash = dash.replace('<tbody class="divide-y divide-primary/10">', '<tbody id="scanTableBody" class="divide-y divide-primary/10">')
dash = dash.replace('<tbody class="divide-y divide-primary/5">', '<tbody id="scanTableBody" class="divide-y divide-primary/5">') # some versions use 5

dash += """
<script>
async function loadLogs() {
    try {
        const token = localStorage.getItem('token');
        if(!token) {
            window.location.href = 'login.html';
            return;
        }

        const res = await fetch('http://localhost:5000/logs', {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        if(res.status === 401) {
            window.location.href = 'login.html';
            return;
        }
        const data = await res.json();
        
        document.getElementById('statTotal').innerText = data.total_scans;
        document.getElementById('statPhishing').innerText = data.phishing_count;
        document.getElementById('statSuspicious').innerText = data.suspicious_count;
        document.getElementById('statSafe').innerText = data.safe_count;

        const tb = document.getElementById('scanTableBody');
        if(tb) {
            tb.innerHTML = '';
            data.scans.forEach(s => {
                let colorCls = s.status === 'Phishing' ? 'text-red-500 bg-red-500/10 border-red-500/20' : 
                               s.status === 'Suspicious' ? 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20' : 
                               'text-primary bg-primary/10 border-primary/20';

                let rawColor = s.status === 'Phishing' ? 'text-red-500' : s.status === 'Suspicious' ? 'text-yellow-500' : 'text-primary';
                
                let viewBtn = `<a href="report.html?url=${encodeURIComponent(s.url)}" class="p-1.5 hover:bg-slate-800 rounded-md transition-colors"><span class="material-symbols-outlined text-[16px] text-primary/60 hover:text-primary">visibility</span></a>`;

                tb.innerHTML += `
                    <tr class="hover:bg-primary/5 transition-colors">
                        <td class="whitespace-nowrap px-6 py-4">
                            <div class="flex items-center gap-3">
                                <span class="material-symbols-outlined ${rawColor} bg-slate-800 rounded-lg p-1 text-[16px]">public</span>
                                <span class="max-w-[200px] truncate block text-slate-300">${s.url}</span>
                            </div>
                        </td>
                        <td class="whitespace-nowrap px-6 py-4">
                            <span class="${rawColor} font-bold">${s.risk_score}</span>
                        </td>
                        <td class="whitespace-nowrap px-6 py-4">
                            <span class="inline-flex items-center rounded-md border ${colorCls} px-2 py-0.5 text-xs font-medium uppercase min-w-24 justify-center">${s.status}</span>
                        </td>
                        <td class="whitespace-nowrap items-center px-6 py-4 text-xs tracking-wide text-slate-500">${s.timestamp}</td>
                        <td class="whitespace-nowrap items-center px-6 py-4 text-xs tracking-wide text-slate-500">${viewBtn}</td>
                    </tr>
                `;
            });
        }
    } catch (e) { console.error('Error fetching logs', e); }
}

document.addEventListener('DOMContentLoaded', () => {
    loadLogs();
    setInterval(loadLogs, 30000); // 30s auto reload
});
</script>
"""

with open(os.path.join(FRONTEND_DIR, 'dashboard.html'), 'w', encoding='utf-8') as f:
    f.write(dash)


# 3. Update Report.html
with open(os.path.join(FRONTEND_DIR, 'report.html'), 'r', encoding='utf-8') as f:
    rep = f.read()

rep = patch_links(rep)
rep += """
<script>
document.addEventListener('DOMContentLoaded', async () => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    if(!url) return;

    // Typically you'd have a /scan or /logs/details endpoint, but here we can just execute a scan check locally
    const token = localStorage.getItem('token');
    if(!token) { window.location.href = 'login.html'; return; }

    try {
        const res = await fetch('http://localhost:5000/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ url: url })
        });
        const data = await res.json();
        
        // Find safe/target elements and append raw URL
        let urlEl = document.querySelector('h1 + p');
        if(urlEl) urlEl.innerText = url;
    } catch(e) {}
});
</script>
"""
with open(os.path.join(FRONTEND_DIR, 'report.html'), 'w', encoding='utf-8') as f:
    f.write(rep)

print("Patching complete.")
