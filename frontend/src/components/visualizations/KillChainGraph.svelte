<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import * as d3 from 'd3';
  import { sevColor, sevLabel } from '$lib/visualizations';

  export let data: any[] = [];

  let svg: any;
  let simulation: any;

  function initKillChain() {
    const container = document.getElementById('kill-chain-graph');
    if (!container) return;

    const width = container.clientWidth || 800;
    const height = 300;

    const svg = d3.select('#kill-chain-graph')
      .append('svg')
      .attr('width', '100%')
      .attr('height', 300)
      .attr('viewBox', `0 0 ${width} 300`);

    const stages = [
      { id: 'recon', label: 'Reconnaissance', color: '#22d3ee', icon: '🔍' },
      { id: 'initial', label: 'Initial Access', color: '#ef4444', icon: '🎯' },
      { id: 'privilege', label: 'Privilege Escalation', color: '#f97316', icon: '⬆️' },
      { id: 'lateral', label: 'Lateral Movement', color: '#fbbf24', icon: '↔️' },
      { id: 'persist', label: 'Persistence', color: '#e879f9', icon: '🔒' },
      { id: 'impact', label: 'Impact', color: '#f87171', icon: '💥' },
    ];

    const svg = d3.select('#kill-chain-graph svg');
    const width = 800;
    const stageWidth = width / 6 - 20;

    const stagesG = d3.select('#kill-chain-graph svg').append('g')
      .attr('transform', 'translate(20, 20)');

    stages.forEach((stage, i) => {
      const g = d3.select('#kill-chain-graph svg')
        .append('g')
        .attr('transform', `translate(${i * (300 / 6) + 20}, 50)`);

      const rect = d3.select('#kill-chain-graph svg')
        .append('rect')
        .attr('x', 20 + i * (300 / 6))
        .attr('y', 50)
        .attr('width', 100)
        .attr('height', 100)
        .attr('rx', 12)
        .attr('fill', '#111826')
        .attr('stroke', d => d.color)
        .attr('stroke-width', 2);

      // This is simplified - the full implementation would be in the report
    });
  }
</script>

<div id="kill-chain-graph" class="viz-container" style="height: 300px;"></div>

<style>
  :global(#kill-chain-graph) {
    width: 100%;
    height: 300px;
    background: #0a0e14;
    border: 1px solid #17202e;
    border-radius: 10px;
  }
</style>