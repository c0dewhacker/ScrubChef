function escapeHtml(str: string): string {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// JSON.stringify does not escape </script>, which can break inline script blocks.
function safeJsonStringify(data: unknown): string {
    return JSON.stringify(data)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/&/g, '\\u0026');
}

export const generateMappingSidecar = (
    canonicalMap: unknown,
    fileName: string
) => {
    const timestamp = new Date().toISOString();
    type Entry = { id: string; type: string; method?: string; context_before?: string; context_after?: string; original: string; occurrences: number };
    const canonical = ((canonicalMap as Record<string, unknown>).canonical ?? {}) as Record<string, Entry>;
    const entries = Object.values(canonical);
    const totalRedactions = entries.reduce((acc, v) => acc + (v.occurrences || 0), 0);

    const rows = entries.map((value) => `
        <tr>
            <td class="token">${escapeHtml(value.id)}</td>
            <td><span class="type-tag">${escapeHtml(value.type)}</span></td>
            <td><span class="method-tag">${escapeHtml(value.method || 'regex')}</span></td>
            <td class="context-cell">
                <div class="context-container">
                    <span class="context-text">${escapeHtml(value.context_before || '')}</span>
                    <span class="context-highlight">${escapeHtml(value.id)}</span>
                    <span class="context-text">${escapeHtml(value.context_after || '')}</span>
                </div>
            </td>
            <td><span class="original" onclick="this.classList.toggle('revealed')">${escapeHtml(value.original)}</span></td>
            <td>${escapeHtml(String(value.occurrences))}</td>
        </tr>`).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <title>ScrubChef Mapping - ${escapeHtml(fileName)}</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border: #334155;
            --accent: #38bdf8;
            --success: #10b981;
            --danger: #ef4444;
        }
        body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg-primary); color: var(--text-primary); margin: 0; line-height: 1.5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .banner { background: var(--danger); color: white; text-align: center; padding: 1rem; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; }
        .header { margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
        .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; background: var(--bg-secondary); padding: 1rem; border-radius: 0.5rem; }
        .meta-item label { display: block; color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 0.25rem; }
        .mapping-table { width: 100%; border-collapse: collapse; background: var(--bg-secondary); border-radius: 0.5rem; overflow: hidden; font-size: 0.875rem; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: rgba(0,0,0,0.2); font-weight: 600; color: var(--text-secondary); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
        .token { font-family: monospace; color: var(--accent); font-weight: bold; }
        .type-tag { background: rgba(56,189,248,0.1); color: var(--accent); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
        .method-tag { background: rgba(16,185,129,0.1); color: var(--success); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
        .context-cell { max-width: 400px; }
        .context-container { font-family: monospace; background: rgba(0,0,0,0.2); padding: 0.5rem; border-radius: 4px; white-space: pre-wrap; word-break: break-all; line-height: 1.4; }
        .context-text { color: var(--text-secondary); opacity: 0.6; }
        .context-highlight { color: var(--accent); background: rgba(56,189,248,0.2); padding: 0 2px; font-weight: bold; }
        .original { font-family: monospace; filter: blur(4px); transition: filter 0.2s; cursor: pointer; padding: 2px 4px; border-radius: 4px; }
        .original:hover, .original.revealed { filter: none; background: rgba(255,255,255,0.05); }
        .search-box { width: 100%; padding: 1rem; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; color: var(--text-primary); margin-bottom: 2rem; font-size: 1rem; box-sizing: border-box; }
    </style>
</head>
<body>
    <div class="banner">⚠️ PRIVATE MAPPING FILE — DO NOT SHARE EXTERNALLY ⚠️</div>
    <div class="container">
        <div class="header">
            <h1>Redaction Mapping Sidecar</h1>
            <p style="color: var(--text-secondary)">This file contains the mapping between redacted tokens and their original values. Keep this file secure and separate from the redacted output.</p>
        </div>
        <div class="meta">
            <div class="meta-item"><label>Source File</label><div>${escapeHtml(fileName)}</div></div>
            <div class="meta-item"><label>Generated At</label><div>${escapeHtml(new Date(timestamp).toLocaleString())}</div></div>
            <div class="meta-item"><label>Total Redactions</label><div>${totalRedactions}</div></div>
        </div>
        <input type="text" class="search-box" placeholder="Search for tokens (e.g. EMAIL_1) or original values..." oninput="filterTable(this.value)">
        <table class="mapping-table">
            <thead>
                <tr><th>Token ID</th><th>Type</th><th>Method</th><th>Context</th><th>Original Value (Hover/Click)</th><th>Count</th></tr>
            </thead>
            <tbody id="table-body">${rows}</tbody>
        </table>
    </div>
    <script>
        const canonicalMap = ${safeJsonStringify(canonicalMap)};
        function filterTable(query) {
            const rows = document.querySelectorAll('#table-body tr');
            const q = query.toLowerCase();
            rows.forEach(row => {
                row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
            });
        }
    </script>
</body>
</html>`;
};
