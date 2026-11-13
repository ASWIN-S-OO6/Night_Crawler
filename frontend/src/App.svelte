<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import SetupForm from './components/SetupForm.svelte';
  import Dashboard from './components/Dashboard.svelte';
  import ReportViewer from './components/ReportViewer.svelte';

  let mode: 'setup' | 'scanning' | 'report' = 'setup';
  let scanStarted = false;
  let scanCompleted = false;
  let reportPath = '';

  async function handleScanStart(event: CustomEvent<{ target: string; provider: string }>) {
    const { target, provider } = event.detail;
    try {
      await invoke('start_scan', {
        target: event.detail.target,
        provider: event.detail.provider,
        ports: undefined,
        recursive: true,
        no_ai: false,
        no_pivot: false
      });
      scanStarted = true;
      mode = 'scanning';
    } catch (err) {
      console.error('Failed to start scan:', err);
      alert('Failed to start scan: ' + err);
    }
  }

  async function checkForReport() {
    try {
      const path = await invoke('get_report');
      if (path) {
        reportCompleted = true;
        reportPath = path;
        mode = 'report';
      }
    } catch (err) {
      console.error('Failed to get report:', err);
    }
  }

  onMount(() => {
    // Listen for scan completion
    const unlisten = listen('scan_complete', (event: any) => {
      scanCompleted = true;
      checkForReport();
    });

    return () => unlisten();
  });

  function handleScanComplete() {
    scanCompleted = true;
    checkForReport();
  }

  function handleNewScan() {
    scanStarted = false;
    scanCompleted = false;
    reportPath = '';
    mode = 'setup';
  }
</script>

<div class="app">
  {#if mode === 'setup'}
    <SetupForm on:scanStart={handleScanStart} />
  {:else if mode === 'scanning'}
    <Dashboard />
  {:else if mode === 'report'}
    <ReportViewer path={reportPath} onNewScan={handleNewScan} />
  {/if}
</div>

<style>
  .app {
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
  }
</style>