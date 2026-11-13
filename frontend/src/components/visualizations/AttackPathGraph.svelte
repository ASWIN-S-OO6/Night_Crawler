<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import * as d3 from 'd3';
  import { sevColor, sevLabel } from '$lib/visualizations';

  export let data: any[] = [];

  let svg: any;

  function initAttackPathGraph() {
    const container = document.getElementById('attack-path-graph');
    if (!container) return;

    const width = container.clientWidth || 800;
    const height = 500;

    const svg = d3.select('#attack-path-graph')
      .append('svg')
      .attr('width', '100%')
      .attr('height', 500)
      .attr('viewBox', `0 0 ${800} 500`);

    // This is a simplified version - the full implementation would be in the report HTML
    // The actual D3.js code is in the report HTML template
  }
</script>

<div id="attack-path-graph" class="viz-container" style="height: 500px;"></div>

<style>
  :global(#attack-path-graph) {
    width: 100%;
    height: 500px;
    background: #0a0e14;
    border: 1px solid #17202e;
    border-radius: 10px;
  }
</style>