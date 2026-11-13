<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import * as d3 from 'd3';
  import { initTooltip, showTooltip, hideTooltip, kindColors, kindLabels } from '$lib/visualizations';

  interface AttackSurfaceNode {
    id: string;
    label: string;
    kind: string;
    label_full: string;
    degree: number;
    x?: number;
    y?: number;
    fx?: number;
    fy?: number;
    port?: number;
    service?: string;
    product?: string;
    version?: string;
    severity?: string;
    cve?: string;
    affected?: string;
    confidence?: string;
    description?: string;
    evidence?: string;
    method?: string;
    path?: string;
    api_type?: string;
    auth_required?: boolean;
    severity?: string;
    cve?: string;
    evidence?: string;
    description?: string;
    url?: string;
    method?: string;
    path?: string;
    api_type?: string;
    auth_required?: boolean;
    severity?: string;
    cve?: string;
    evidence?: string;
    description?: string;
  }

  export let data: { nodes: any[]; links: any[] } = { nodes: [], links: [] };

  let svg: any;
  let simulation: any;
  let width = 800;
  let height = 600;

  function initMap() {
    const container = document.getElementById('attack-surface-map');
    if (!container) return;

    const width = container.clientWidth || 800;
    const height = 600;

    const svg = d3.select('#attack-surface-map')
      .append('svg')
      .attr('width', '100%')
      .attr('height', '600')
      .attr('viewBox', `0 0 ${width} ${height}`);

    // Arrow markers
    const defs = d3.select('#attack-surface-map svg').append('defs');
    ['recon', 'exploit', 'lateral', 'persist', 'impact', 'cred', 'default'].forEach((type) => {
      const colors = { recon: '#22d3ee', exploit: '#ef4444', lateral: '#f97316', persist: '#e879f9', impact: '#f87171', cred: '#34d399', default: '#64748b' };
      const color = colors[type as keyof typeof colors] || colors.default;
      d3.select('svg').append('defs').append('marker')
        .attr('id', `arrowhead-${type}`)
        .attr('viewBox', '0 0 10 10')
        .attr('refX', 16)
        .attr('refY', 5)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M 0 0 L 10 5 L 0 10 Z')
        .attr('fill', ({ recon: '#22d3ee', exploit: '#ef4444', lateral: '#f97316', persist: '#e879f9', impact: '#f87171', cred: '#34d399', default: '#64748b' })[type] || '#64748b');
    });

    // Simulation setup would go here
    // This is a simplified version - the full implementation would be in the report HTML
  }

  // This component just provides the container
  // The actual D3.js initialization happens in the report HTML
</script>

<div id="attack-surface-map" class="viz-container" style="height: 600px;"></div>

<style>
  :global(#attack-surface-map) {
    width: 100%;
    height: 600px;
    background: #0a0e14;
    border: 1px solid #17202e;
    border-radius: 10px;
  }
</style>