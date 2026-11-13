<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import * as d3 from 'd3';
  import { sevColor, sevLabel } from '$lib/visualizations';

  export let data: any[] = [];
  export let filters = { severity: 'all', type: 'all' };

  let svg: any;
  let heatmapData: any[] = [];

  function initVulnHeatmap() {
    const container = document.getElementById('vuln-heatmap');
    if (!container) return;

    const width = container.clientWidth || 800;
    const height = 500;

    const svg = d3.select('#vuln-heatmap')
      .append('svg')
      .attr('width', '100%')
      .attr('height', 500)
      .attr('viewBox', `0 0 ${800} 500`);

    // This is a simplified version - the full implementation would be in the report HTML
  }
</script>

<div id="vuln-heatmap" class="viz-container" style="height: 500px;"></div>

<div class="viz-controls" style="margin-bottom: 12px;">
  <select class="viz-btn vuln-filter-sev" bind:value={filters.severity}>
    <option value="all">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <select class="viz-btn vuln-filter-type" bind:value={filters.type}>
    <option value="all">All Types</option>
    <option value="vuln">Vulnerabilities</option>
    <option value="exposure">Exposures</option>
    <option value="misconfig">Misconfigurations</option>
    <option value="credential">Credentials</option>
  </select>
</div>

<div id="vuln-heatmap" class="viz-container" style="height: 500px;"></div>

<div class="heatmap-legend" style="margin-top: 12px;">
  <span class="legend-item"><span class="legend-color" style="background:#ef4444"></span>Critical</span>
  <span class="legend-item"><span class="legend-color" style="background:#f97316"></span>High</span>
  <span class="legend-item"><span class="legend-color" style="background:#fbbf24"></span>Medium</span>
  <span class="legend-item"><span class="legend-color" style="background:#22d3ee"></span>Low</span>
  <span class="legend-item"><span class="legend-color" style="background:#64748b"></span>Info</span>
</div>

<style>
  :global(#vuln-heatmap) {
    width: 100%;
    height: 500px;
    background: #0a0e14;
    border: 1px solid #17202e;
    border-radius: 10px;
  }
</style>