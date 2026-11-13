<script lang="ts">
  export let path: string;
  export let onNewScan: () => void;

  let reportContent = '';

  async function loadReport() {
    try {
      const response = await fetch(path);
      if (response.ok) {
        reportContent = await response.text();
      } else {
        throw new Error('Failed to load report');
      }
    } catch (err) {
      console.error('Failed to load report:', err);
    }
  }

  function handleNewScan() {
    // Navigate back to setup
    window.location.reload();
  }
</script>

{#if reportContent}
  <div class="report-viewer">
    <div class="report-header">
      <h1>🕷 NightCrawler — Reconnaissance Report</h1>
      <div class="report-actions">
        <button class="btn-secondary" onclick={onNewScan}>← New Scan</button>
        <a href={path} download class="btn-primary">📥 Download Report</a>
      </div>
    </div>
    <div class="report-content" innerHTML={reportContent} />
  {:else}
  <div class="loading">
    <div class="spinner"></div>
    <p>Loading report...</p>
  </div>
{/if}

<style>
  .report-viewer {
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
  }

  .report-header {
    background: linear-gradient(120deg, #1b0b23, #0a1a2e);
    border: 1px solid #2c1f3d;
    border-radius: 14px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .report-header h1 {
    margin: 0;
    font-size: 1.75rem;
    background: linear-gradient(90deg, #e879f9, #22d3ee);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }

  .report-actions {
    display: flex;
    gap: 0.75rem;
  }

  .btn-secondary {
    padding: 0.75rem 1.5rem;
    background: var(--panel);
    border: 1px solid var(--border);
    color: var(--text);
    font-weight: 600;
    border-radius: 8px;
    cursor: pointer;
    transition: background 0.2s;
  }

  .btn-secondary:hover {
    background: var(--panel2);
  }

  .btn-primary {
    padding: 0.75rem 1.5rem;
    background: linear-gradient(90deg, #d946ef, #22d3ee);
    color: #0a0e14;
    font-weight: 700;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    text-decoration: none;
    transition: opacity 0.2s, transform 0.1s;
  }

  .btn-primary:hover {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  .report-content {
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }

  .report-content h1,
  .report-content h2,
  .report-content h3,
  .report-content h4 {
    color: #cbd5e1;
  }

  .report-content h1 {
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 16px;
  }

  .report-content h2 {
    margin-top: 24px;
    margin-bottom: 12px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
  }

  .report-content h3 {
    margin-top: 18px;
    margin-bottom: 8px;
  }

  .report-content p {
    line-height: 1.7;
    margin-bottom: 12px;
  }

  .report-content a {
    color: var(--cyan);
    text-decoration: none;
  }

  .report-content a:hover {
    text-decoration: underline;
  }

  .report-content code {
    background: #1a2332;
    padding: 1px 5px;
    border-radius: 5px;
    font-size: 12.5px;
    color: #a5f3fc;
  }

  .report-content pre {
    background: #0a0e14;
    border: 1px solid #17202e;
    padding: 1rem;
    border-radius: 8px;
    overflow-x: auto;
    font-size: 12.5px;
  }

  .report-content pre code {
    background: none;
    padding: 0;
    color: inherit;
  }

  .report-content table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13.5px;
    margin: 12px 0;
  }

  .report-content th {
    text-align: left;
    color: #93a6c1;
    font-weight: 600;
    padding: 8px 10px;
    border-bottom: 2px solid var(--border);
    font-size: 12.5px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .report-content td {
    padding: 7px 10px;
    border-bottom: 1px solid #17202e;
    vertical-align: top;
  }

  .report-content tr:hover td {
    background: #0d1420;
  }

  .report-content .chip {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    color: #0a0e14;
    letter-spacing: 0.5px;
  }

  .report-content .finding {
    background: var(--panel);
    border: 1px solid var(--border);
    border-left: 4px solid #333;
    border-radius: 10px;
    padding: 14px 16px;
    margin: 12px 0;
  }

  .report-content .finding h3 {
    margin: 0 0 8px;
    font-size: 15.5px;
  }

  .report-content .finding .meta {
    color: var(--muted);
    font-size: 12.5px;
    margin-bottom: 6px;
  }

  .report-content .finding pre {
    background: #0a0e14;
    border: 1px solid #17202e;
    padding: 10px;
    border-radius: 8px;
    overflow-x: auto;
    font-size: 12.5px;
  }

  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 60vh;
    gap: 1rem;
    color: var(--muted);
  }

  .spinner {
    width: 3rem;
    height: 3rem;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>