<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let onScanStart: (event: CustomEvent<{ target: string; provider: string }>) => void;

  let target = '';
  let provider = '';
  let starting = false;
  let error = '';

  const dispatch = createEventDispatcher();

  async function handleSubmit(event: Event) {
    event.preventDefault();
    if (!target.trim()) {
      return;
    }

    // Dispatch event to parent
    dispatch('scanStart', { target: target.trim(), provider: provider.trim() });
  }
</script>

<div class="setup-container">
  <div class="setup-card">
    <div class="setup-header">
      <div class="logo">🕷</div>
      <h1>NightCrawler</h1>
      <p class="subtitle">Adversary Simulation Agent</p>
    </div>

    <form on:submit|preventDefault={handleSubmit}>
      <div class="form-group">
        <label for="target">Target</label>
        <input
          id="target"
          type="text"
          placeholder="e.g., scanme.nmap.org or 192.168.1.0/24"
          bind:value={target}
          required
          autocomplete="off"
        />
        <p class="hint">IP address, domain, or CIDR range</p>
      </div>

      <div class="form-group">
        <label for="provider">NVIDIA API Key / Provider Config (optional)</label>
        <input
          id="provider"
          type="text"
          placeholder="nvapi-... or path to provider.toml"
          bind:value={provider}
          autocomplete="off"
        />
        <p class="hint">Leave empty to use saved provider or run tools-only</p>
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button type="submit" class="btn-primary" disabled={starting || !target.trim()}>
        {#if starting}
          <span class="spinner"></span> Starting...
        {:else}
          🕷 Start Autonomous Scan
        {/if}
      </button>
    </form>

    <div class="modes">
      <p class="muted">Or run in terminal mode:</p>
      <code class="cmd">night-crawler --verbose --recursive scanme.nmap.org</code>
    </div>
  </div>
</div>

<style>
  .setup-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem;
  }

  .setup-card {
    width: 100%;
    max-width: 520px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2.5rem;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
  }

  .setup-header {
    text-align: center;
    margin-bottom: 2rem;
  }

  .logo {
    font-size: 3rem;
    margin-bottom: 0.5rem;
  }

  h1 {
    font-size: 1.75rem;
    font-weight: 700;
    background: linear-gradient(90deg, #e879f9, #22d3ee);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    margin: 0 0 0.5rem;
  }

  .subtitle {
    color: var(--muted);
    font-size: 0.95rem;
  }

  .form-group {
    margin-bottom: 1.25rem;
  }

  label {
    display: block;
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--text);
    margin-bottom: 0.5rem;
  }

  input {
    width: 100%;
    padding: 0.875rem 1rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text);
    font-size: 1rem;
    font-family: inherit;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(217, 70, 239, 0.2);
  }

  .hint {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.35rem;
  }

  .error {
    background: rgba(248, 113, 113, 0.15);
    border: 1px solid #f87171;
    color: #fca5a5;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }

  .btn-primary {
    width: 100%;
    padding: 1rem;
    background: linear-gradient(90deg, #d946ef, #22d3ee);
    color: #0a0e14;
    font-weight: 700;
    font-size: 1rem;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: opacity 0.2s, transform 0.1s;
  }

  .btn-primary:hover:not(:disabled) {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .spinner {
    display: inline-block;
    width: 1rem;
    height: 1rem;
    border: 2px solid transparent;
    border-top-color: #0a0e14;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-right: 0.5rem;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .modes {
    margin-top: 1.5rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    text-align: center;
  }

  .cmd {
    display: inline-block;
    background: var(--bg);
    border: 1px solid var(--border);
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.8rem;
    color: var(--cyan);
    font-family: 'Fira Code', monospace;
  }
</style>