<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import AttackSurfaceMap from './visualizations/AttackSurfaceMap.svelte';
  import KillChainGraph from './visualizations/KillChainGraph.svelte';
  import AttackPathGraph from './visualizations/AttackPathGraph.svelte';
  import VulnHeatmap from './visualizations/VulnHeatmap.svelte';

  export let scanStarted = false;

  let state = $state({
    scan_started: false,
    target: '',
    model: '',
    thinking: false,
    done: false,
    elapsed: 0,
    stats: {} as Record<string, number>,
    progress: { label: '', current: 0, total: 0 } | null,
    phases: [] as any[],
    findings: [] as any[],
    tasks: [] as any[],
    reasoning: [] as string[],
    logs: [] as string[],
    error: string | null,
    geo: any,
    scan_started: false,
  };

  let unlisten: (() => void) | null = null;
  let tickInterval: ReturnType<typeof setInterval> | null = null;
  let startedAt = Date.now();

  function formatElapsed(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h > 0 ? `${h}h ` : ''}${m}m ${s}s`;
  }

  async function fetchState() {
    try {
      const response = await invoke('get_state');
      state = { ...state, ...response };
    } catch (err) {
      console.error('Failed to fetch state:', err);
    }
  }

  function startPolling() {
    tickInterval = setInterval(() => {
      fetchState();
    }, 700);
  }

  function stopPolling() {
    if (tickInterval) {
      clearInterval(tickInterval);
      tickInterval = null;
    }
  }

  function formatElapsed(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h > 0 ? `${h}h ` : ''}${m}m ${s}s`;
  }

  function getSeverityClass(severity: string): string {
    return severity.toLowerCase();
  }

  function icon(status: string): string {
    switch (status) {
      case 'done': return '✔';
      case 'running': return '<span class="spinner"></span>';
      case 'skipped': return '–';
      case 'failed': return '✖';
      default: return '◌';
    }
  }

  function formatElapsedShort(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h > 0 ? `${h}h ` : ''}${m}m ${s}s`;
  }
</script>

<div class="dashboard">
  <header class="header">
    <div>
      <h1>🕷 Night Crawler — Live Recon</h1>
      <div class="meta">
        <span>target: <b>{target || '—'}</b></span>
        <span>agent: <b>{model || 'agent offline'}</b></span>
        <span>elapsed: <b>{formatElapsed(elapsed)}</b></span>
      </div>
    </div>
    <div class="meta" id="stats">
      {#each Object.entries($state.stats) as [k, v]}
        <span>{k}: <b>{v}</b></span>
      {/each}
    </div>
  </header>

  <div class="bar" id="bar">
    <span id="phase-now" class="thinking">{thinking ? '🧠 thinking...' : (done ? '✔ complete' : (runningNow || 'working…'))}</span>
    <div class="track"><div class="fill" style="width: {pct}%"></div></div>
    <span id="pct" class="meta">{pct}%</span>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>Phases</h2>
      <div id="phases">
        {#each phases as p}
          <div class="phase {p.status}">
            <span class="ic">{icon(p.status)}</span>
            <span>{p.name}{p.summary ? ` <span class="sum"> {p.summary}</span>` : ''}{p.detail && (p.status === 'skipped' || p.status === 'failed') ? ` <span class="sum">({p.detail})</span>` : ''}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="panel">
      <h2>🕷 NightCrawler Brain</h2>
      <div class="agent-line">{thinking ? '<span class="thinking pulse">🧠 NightCrawler is reasoning over the evidence…</span>' : (done ? '✔ assessment complete' : '▶ acting')}</div>
      <div id="tasks">
        {#each tasks as t}
          <div class="task {t.status}">
            <span class="ic">{icon(t.status)}</span>{t.name}
          </div>
        {/each}
      </div>
      <h2 style="margin-top:12px">Reasoning</h2>
      <div id="reasoning">
        {#each reasoning.slice(-10) as r}
          <div class="reason">{r}</div>
        {/each}
      </div>
    </div>

    <div class="panel">
      <h2>Findings</h2>
      <div id="findings">
        {#each findings.slice(-60) as f}
          <div class="finding">
            <span class="sev {f.severity.toLowerCase()}">{f.severity}</span>
            <b>{f.category}</b> {f.title}
          </div>
        {/each}
        {#if findings.length === 0}
          <div class="finding">no findings yet…</div>
        {/if}
      </div>
      <h2 style="margin-top:12px">Activity</h2>
      <div id="logs">
        {#each logs.slice(-25) as l}
          <div class="log">· {l}</div>
        {/each}
      </div>
    </div>
  </div>

  <!-- Advanced Visualizations Row -->
  <div class="viz-row">
    <AttackSurfaceMap />
    <KillChainGraph />
  </div>
  <div class="viz-row">
    <AttackPathGraph />
    <VulnHeatmap />
  </div>

  {#if done}
    <div class="done-banner">
      <h2 style="border:none;color:var(--green)">✔ Scan complete</h2>
      <a class="btn" href="#" onclick="window.location.reload()">Start new scan</a>
    </div>
  {/if}
</div>

<style>
  .dashboard {
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
  }

  .header {
    background: linear-gradient(120deg, #1b0b23, #0a1a2e);
    border: 1px solid #2c1f3d;
    border-radius: 14px;
    padding: 18px 22px;
    margin-bottom: 16px;
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
  }

  .header h1 {
    margin: 0;
    font-size: 22px;
    letter-spacing: .5px;
    background: linear-gradient(90deg, #e879f9, #22d3ee);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }

  .meta {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    font-size: 13px;
    color: #b7c3d7;
  }

  .meta b { color: #fff; }

  .bar {
    position: sticky;
    top: 8px;
    z-index: 5;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 16px;
    margin-bottom: 16px;
    display: flex;
    gap: 14px;
    align-items: center;
    flex-wrap: wrap;
  }

  .track {
    flex: 1;
    height: 12px;
    background: #0a0e14;
    border-radius: 6px;
    overflow: hidden;
    min-width: 200px;
  }

  .fill {
    height: 100%;
    background: linear-gradient(90deg, #d946ef, #22d3ee);
    width: 0%;
    border-radius: 6px;
    transition: width 0.4s;
  }

  .thinking {
    color: var(--accent);
    font-size: 13px;
  }

  .pulse {
    animation: pulse 1.6s ease infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.45; }
  }

  .spinner {
    display: inline-block;
    animation: spin 1s steps(10) infinite;
  }

  @keyframes spin {
    0% { transform: rotate(0); }
    100% { transform: rotate(360deg); }
  }

  .pulse {
    animation: pulse 1.6s ease infinite;
  }

  .grid {
    display: grid;
    grid-template-columns: 340px 1fr 1.2fr;
    gap: 14px;
    margin-bottom: 16px;
  }

  .viz-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    margin-bottom: 16px;
  }

  @media (max-width: 1100px) {
    .grid { grid-template-columns: 1fr; }
    .viz-row { grid-template-columns: 1fr; }
  }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .panel h2 {
    margin: 0 0 10px;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #93a6c1;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
  }

  .phase {
    display: flex;
    gap: 8px;
    padding: 3px 0;
    font-size: 13px;
    align-items: center;
  }

  .phase .n {
    color: var(--muted);
    width: 22px;
    text-align: right;
  }

  .phase .ic {
    width: 18px;
    text-align: center;
  }

  .done { color: var(--green); }
  .running { color: var(--accent); font-weight: 600; }
  .skipped { color: var(--muted); }
  .failed { color: var(--red); }
  .pending { color: #4b5563; }

  .sum {
    color: var(--muted);
    font-size: 11.5px;
    margin-left: 2px;
  }

  .agent-line {
    font-size: 13px;
    padding: 3px 0;
  }

  .task {
    display: flex;
    gap: 8px;
    font-size: 13px;
    padding: 2px 0;
  }

  .reason {
    font-size: 12.5px;
    color: #cbd5e1;
    padding: 2px 0 2px 14px;
    border-left: 2px solid #2c1f3d;
    margin: 2px 0;
  }

  .reason::before {
    content: "» ";
    color: var(--muted);
  }

  .log {
    font-size: 11.5px;
    color: var(--green);
    padding: 1px 0;
    font-family: ui-monospace, monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .finding {
    padding: 5px 0;
    border-bottom: 1px solid #17202e;
    font-size: 13px;
  }

  .sev {
    display: inline-block;
    min-width: 44px;
    text-align: center;
    border-radius: 10px;
    font-size: 10.5px;
    font-weight: 700;
    padding: 1px 6px;
    margin-right: 8px;
    color: #0a0e14;
  }

  .critical { background: #ef4444; }
  .high { background: #f97316; }
  .medium { background: #fbbf24; }
  .low { background: #22d3ee; }
  .info { background: #475569; color: #cbd5e1; }

  .done-banner {
    background: var(--panel);
    border: 1px solid var(--green);
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 16px;
    text-align: center;
  }

  .done-banner h2 {
    border: none;
    color: var(--green);
  }

  .done-banner a.btn {
    display: inline-block;
    margin-top: 10px;
    background: linear-gradient(90deg, #d946ef, #22d3ee);
    color: #0a0e14;
    font-weight: 700;
    padding: 10px 22px;
    border-radius: 8px;
    text-decoration: none;
  }

  .spinner {
    display: inline-block;
    animation: spin 1s steps(10) infinite;
  }

  @keyframes spin {
    0% { transform: rotate(0); }
    100% { transform: rotate(360deg); }
  }

  .pulse {
    animation: pulse 1.6s ease infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.45; }
  }
</style>