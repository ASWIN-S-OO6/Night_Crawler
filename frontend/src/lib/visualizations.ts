// D3.js Visualization utilities for NightCrawler
// All visualizations are self-contained and work with the REPORT_DATA global

import * as d3 from 'd3';
import type { ReconResults } from '../types';

// Type definitions
export interface ReconResults {
  target: { input: string; input_kind: string; ip?: string; hostname?: string; geo?: any };
  ports: any[];
  vulns: any[];
  subdomains: any[];
  subdirs: any[];
  http: any[];
  webscan: any[];
  api_endpoints: any[];
  vulns: any[];
  cves: any[];
  cve_refs: any[];
  graph: { nodes: any[]; edges: any[] };
  attack_paths: any[];
  exploitation_recommendations: any[];
  ai_decisions: any[];
  target: any;
  meta: any;
  dns: any;
  subdomains: any[];
  subdirs: any[];
  cves: any[];
  cve_refs: any[];
  graph: { nodes: any[]; edges: any[] };
  attack_paths: any[];
  exploitation_recommendations: any[];
  dorks: any[];
  ai_decisions: any[];
  pivots: any[];
  webscan: any[];
  http: any[];
  snmp: any;
  ldap: any;
  netbios: any;
  smb: any;
  whois: any;
  dorks: any[];
  graph: { nodes: any[]; edges: any[] };
  attack_paths: any[];
  exploitation_recommendations: any[];
}

// Global data accessor
export function getData(): any {
  return (window as any).REPORT_DATA;
}

// Tooltip utilities
let tooltip: d3.Selection<HTMLDivElement, unknown, null, undefined> | null = null;

export function initTooltip() {
  if (!tooltip) {
    tooltip = d3.select('body').append('div')
      .attr('class', 'tooltip')
      .style('opacity', 0);
  }
}

export function showTooltip(event: MouseEvent, html: string) {
  const tooltip = d3.select('.tooltip');
  tooltip.html(html)
    .style('left', (event.pageX + 10) + 'px')
    .style('top', (event.pageY - 28) + 'px')
    .style('opacity', 1);
}

export function hideTooltip() {
  d3.select('.tooltip').style('opacity', 0);
}

// Color scales
export const severityColors = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#fbbf24',
  low: '#22d3ee',
  info: '#64748b',
  critical_bg: '#ef4444',
  high_bg: '#f97316',
  medium_bg: '#fbbf24',
  low_bg: '#22d3ee',
  info_bg: '#64748b',
};

export const kindColors = {
  recon: '#22d3ee',
  exploit: '#ef4444',
  lateral: '#f97316',
  persist: '#e879f9',
  impact: '#f87171',
  cred: '#34d399',
  web: '#e879f9',
  api: '#f97316',
  infra: '#fbbf24',
  db: '#ef4444',
  remote: '#f87171',
  ldap: '#e879f9',
  smb: '#fbbf24',
  snmp: '#fbbf24',
  target: '#d946ef',
  default: '#64748b',
};

export const kindLabels: Record<string, string> = {
  recon: 'Reconnaissance',
  exploit: 'Exploitation',
  lateral: 'Lateral Movement',
  persist: 'Persistence',
  impact: 'Impact',
  cred: 'Credentials',
  web: 'Web',
  api: 'API',
  infra: 'Infrastructure',
  db: 'Database',
  remote: 'Remote Access',
  ldap: 'LDAP',
  smb: 'SMB',
  snmp: 'SNMP',
  target: 'Target',
  default: 'Other',
};

// Utility functions
export function htmlEscape(s: string): string {
  return (s || '')
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, ''');
}

export function formatElapsed(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${h > 0 ? `${h}h ` : ''}${m}m ${s}s`;
}

// Severity colors
export function sevColor(severity: string): string {
  switch (severity) {
    case 'Critical': return '#ef4444';
    case 'High': return '#f97316';
    case 'Medium': return '#fbbf24';
    case 'Low': return '#22d3ee';
    case 'Info': return '#64748b';
    default: return '#64748b';
  }
}

export function sevLabel(severity: string): string {
  switch (severity) {
    case 'Critical': return 'CRITICAL';
    case 'High': return 'HIGH';
    case 'Medium': return 'MEDIUM';
    case 'Low': return 'LOW';
    case 'Info': return 'INFO';
    default: return severity.toUpperCase();
  }
}

// Global tooltip
let tooltip: d3.Selection<HTMLDivElement, unknown, null, undefined> | null = null;

export function initTooltip() {
  if (!tooltip) {
    tooltip = d3.select('body').append('div')
      .attr('class', 'tooltip')
      .style('opacity', 0);
  }
}

export function showTooltip(event: MouseEvent, html: string) {
  const tooltip = d3.select('.tooltip');
  tooltip.html(html)
    .style('left', (event.pageX + 10) + 'px')
    .style('top', (event.pageY - 28) + 'px')
    .style('opacity', 1);
}

export function hideTooltip() {
  d3.select('.tooltip').style('opacity', 0);
}

// Filter state management
export interface FilterState {
  severity: string;
  type: string;
  tactic: string;
  phase: string;
  severity_ap: string;
  search: string;
}

export const filterState = {
  severity: 'all',
  type: 'all',
  tactic: 'all',
  phase: 'all',
  severity_ap: 'all',
  search: '',
};

// Filter event handlers
export function setupFilters() {
  // Vulnerability heatmap filters
  document.querySelectorAll('.vuln-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      // Update filter state and re-render
      const event = new CustomEvent('vuln-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  document.querySelectorAll('.vuln-filter-type').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('vuln-filter-change', { detail: { type: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  document.querySelectorAll('.mitre-filter-tactic').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('mitre-filter-change', { detail: { tactic: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  document.querySelectorAll('.timeline-filter-phase').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('timeline-filter-change', { detail: { phase: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  document.querySelectorAll('.attack-path-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('attack-path-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // Evidence search
  const searchInput = document.getElementById('evidence-search');
  if (searchInput) {
    (searchInput as HTMLInputElement).addEventListener('input', function() {
      const event = new CustomEvent('evidence-search', { detail: { search: (this as HTMLInputElement).value.toLowerCase() } });
      window.dispatchEvent(event);
    });
  }
}

// Global data accessor
export function getData(): any {
  return (window as any).REPORT_DATA;
}

// Common color scales
export const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#fbbf24',
  low: '#22d3ee',
  info: '#64748b',
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#fbbf24',
  LOW: '#22d3ee',
  INFO: '#64748b',
};

export const kindColors: Record<string, string> = {
  recon: '#22d3ee',
  exploit: '#ef4444',
  lateral: '#f97316',
  persist: '#e879f9',
  impact: '#f87171',
  cred: '#34d399',
  web: '#e879f9',
  api: '#f97316',
  infra: '#fbbf24',
  db: '#ef4444',
  remote: '#f87171',
  ldap: '#e879f9',
  smb: '#fbbf24',
  snmp: '#fbbf24',
  target: '#d946ef',
  default: '#64748b',
};

export const kindLabels: Record<string, string> = {
  recon: 'Reconnaissance',
  exploit: 'Exploitation',
  lateral: 'Lateral Movement',
  persist: 'Persistence',
  impact: 'Impact',
  cred: 'Credentials',
  web: 'Web',
  api: 'API',
  infra: 'Infrastructure',
  db: 'Database',
  remote: 'Remote Access',
  ldap: 'LDAP',
  smb: 'SMB',
  snmp: 'SNMP',
  target: 'Target',
  default: 'Other',
};

export function sevColor(severity: string): string {
  switch (severity) {
    case 'Critical': return '#ef4444';
    case 'High': return '#f97316';
    case 'Medium': return '#fbbf24';
    case 'Low': return '#22d3ee';
    case 'Info': return '#64748b';
    default: return '#64748b';
  }
}

export function sevLabel(severity: string): string {
  switch (severity) {
    case 'Critical': return 'CRITICAL';
    case 'High': return 'HIGH';
    case 'Medium': return 'MEDIUM';
    case 'Low': return 'LOW';
    case 'Info': return 'INFO';
    default: return severity.toUpperCase();
  }
}

// Tooltip functions
let tooltip: d3.Selection<HTMLDivElement, unknown, null, undefined> | null = null;

export function initTooltip() {
  if (!tooltip) {
    tooltip = d3.select('body').append('div')
      .attr('class', 'tooltip')
      .style('opacity', 0);
  }
}

export function showTooltip(event: MouseEvent, html: string) {
  const tooltip = d3.select('.tooltip');
  tooltip.html(html)
    .style('left', (event.pageX + 10) + 'px')
    .style('top', (event.pageY - 28) + 'px')
    .style('opacity', 1);
}

export function hideTooltip() {
  d3.select('.tooltip').style('opacity', 0);
}

// Global filter state
export let vulnFilter = { severity: 'all', type: 'all' };
export let mitreFilter = { tactic: 'all' };
export let timelineFilter = { phase: 'all' };
export let attackPathFilter = { severity: 'all' };
export let vulnSearch = '';

// Filter event handlers
export function setupFilters() {
  // Vulnerability heatmap filters
  document.querySelectorAll('.vuln-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('vuln-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  document.querySelectorAll('.vuln-filter-type').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('vuln-filter-change', { detail: { type: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // MITRE heatmap filter
  document.querySelectorAll('.mitre-filter-tactic').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('mitre-filter-change', { detail: { tactic: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // Timeline filter
  document.querySelectorAll('.timeline-filter-phase').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('timeline-filter-change', { detail: { phase: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // Attack path filter
  document.querySelectorAll('.attack-path-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('attack-path-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // Evidence search
  const searchInput = document.getElementById('evidence-search');
  if (searchInput) {
    (searchInput as HTMLInputElement).addEventListener('input', function() {
      const event = new CustomEvent('evidence-search', { detail: { search: (this as HTMLInputElement).value.toLowerCase() } });
      window.dispatchEvent(event);
    });
  }
}

// Data accessor
export function getData(): any {
  return (window as any).REPORT_DATA;
}

// Common color scales
export const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#fbbf24',
  low: '#22d3ee',
  info: '#64748b',
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#fbbf24',
  LOW: '#22d3ee',
  INFO: '#64748b',
};

export const kindColors: Record<string, string> = {
  recon: '#22d3ee',
  exploit: '#ef4444',
  lateral: '#f97316',
  persist: '#e879f9',
  impact: '#f87171',
  cred: '#34d399',
  web: '#e879f9',
  api: '#f97316',
  infra: '#fbbf24',
  db: '#ef4444',
  remote: '#f87171',
  ldap: '#e879f9',
  smb: '#fbbf24',
  snmp: '#fbbf24',
  target: '#d946ef',
  default: '#64748b',
};

export const kindLabels: Record<string, string> = {
  recon: 'Reconnaissance',
  exploit: 'Exploitation',
  lateral: 'Lateral Movement',
  persist: 'Persistence',
  impact: 'Impact',
  cred: 'Credentials',
  web: 'Web',
  api: 'API',
  infra: 'Infrastructure',
  db: 'Database',
  remote: 'Remote Access',
  ldap: 'LDAP',
  smb: 'SMB',
  snmp: 'SNMP',
  target: 'Target',
  default: 'Other',
};

export function sevColor(severity: string): string {
  switch (severity) {
    case 'Critical': return '#ef4444';
    case 'High': return '#f97316';
    case 'Medium': return '#fbbf24';
    case 'Low': return '#22d3ee';
    case 'Info': return '#64748b';
    default: return '#64748b';
  }
}

export function sevLabel(severity: string): string {
  switch (severity) {
    case 'Critical': return 'CRITICAL';
    case 'High': return 'HIGH';
    case 'Medium': return 'MEDIUM';
    case 'Low': return 'LOW';
    case 'Info': return 'INFO';
    default: return severity.toUpperCase();
  }
}

// Global tooltip
let tooltip: d3.Selection<HTMLDivElement, unknown, null, undefined> | null = null;

export function initTooltip() {
  if (!tooltip) {
    tooltip = d3.select('body').append('div')
      .attr('class', 'tooltip')
      .style('opacity', 0);
  }
}

export function showTooltip(event: MouseEvent, html: string) {
  const tooltip = d3.select('.tooltip');
  tooltip.html(html)
    .style('left', (event.pageX + 10) + 'px')
    .style('top', (event.pageY - 28) + 'px')
    .style('opacity', 1);
}

export function hideTooltip() {
  d3.select('.tooltip').style('opacity', 0);
}

// Global filter state
export let vulnFilter = { severity: 'all', type: 'all' };
export let mitreFilter = { tactic: 'all' };
export let timelineFilter = { phase: 'all' };
export let attackPathFilter = { severity: 'all' };
export let vulnSearch = '';

// Filter event handlers
export function setupFilters() {
  // Vulnerability heatmap filters
  document.querySelectorAll('.vuln-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('vuln-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  document.querySelectorAll('.vuln-filter-type').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('vuln-filter-change', { detail: { type: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // MITRE heatmap filter
  document.querySelectorAll('.mitre-filter-tactic').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('mitre-filter-change', { detail: { tactic: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // Timeline filter
  document.querySelectorAll('.timeline-filter-phase').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('timeline-filter-change', { detail: { phase: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  }

  // Attack path filter
  document.querySelectorAll('.attack-path-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('attack-path-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // Evidence search
  const searchInput = document.getElementById('evidence-search');
  if (searchInput) {
    (searchInput as HTMLInputElement).addEventListener('input', function() {
      const event = new CustomEvent('evidence-search', { detail: { search: (this as HTMLInputElement).value.toLowerCase() } });
      window.dispatchEvent(event);
    });
  }
}

// Data accessor
export function getData(): any {
  return (window as any).REPORT_DATA;
}

// Common color scales
export const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#fbbf24',
  low: '#22d3ee',
  info: '#64748b',
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#fbbf24',
  LOW: '#22d3ee',
  INFO: '#64748b',
};

export const kindColors: Record<string, string> = {
  recon: '#22d3ee',
  exploit: '#ef4444',
  lateral: '#f97316',
  persist: '#e879f9',
  impact: '#f87171',
  cred: '#34d399',
  web: '#e879f9',
  api: '#f97316',
  infra: '#fbbf24',
  db: '#ef4444',
  remote: '#f87171',
  ldap: '#e879f9',
  smb: '#fbbf24',
  snmp: '#fbbf24',
  target: '#d946ef',
  default: '#64748b',
};

export const kindLabels: Record<string, string> = {
  recon: 'Reconnaissance',
  exploit: 'Exploitation',
  lateral: 'Lateral Movement',
  persist: 'Persistence',
  impact: 'Impact',
  cred: 'Credentials',
  web: 'Web',
  api: 'API',
  infra: 'Infrastructure',
  db: 'Database',
  remote: 'Remote Access',
  ldap: 'LDAP',
  smb: 'SMB',
  snmp: 'SNMP',
  target: 'Target',
  default: 'Other',
};

export function sevColor(severity: string): string {
  switch (severity) {
    case 'Critical': return '#ef4444';
    case 'High': return '#f97316';
    case 'Medium': return '#fbbf24';
    case 'Low': return '#22d3ee';
    case 'Info': return '#64748b';
    default: return '#64748b';
  }
}

export function sevLabel(severity: string): string {
  switch (severity) {
    case 'Critical': return 'CRITICAL';
    case 'High': return 'HIGH';
    case 'Medium': return 'MEDIUM';
    case 'Low': return 'LOW';
    case 'Info': return 'INFO';
    default: return severity.toUpperCase();
  }
}

// Global tooltip
let tooltip: any = null;

export function initTooltip() {
  if (!tooltip) {
    tooltip = d3.select('body').append('div')
      .attr('class', 'tooltip')
      .style('opacity', 0);
  }
}

export function showTooltip(event: MouseEvent, html: string) {
  const tooltip = d3.select('.tooltip');
  tooltip.html(html)
    .style('left', (event.pageX + 10) + 'px')
    .style('top', (event.pageY - 28) + 'px')
    .style('opacity', 1);
}

export function hideTooltip() {
  d3.select('.tooltip').style('opacity', 0);
}

// Global filter state
export let vulnFilter = { severity: 'all', type: 'all' };
export let mitreFilter = { tactic: 'all' };
export let timelineFilter = { phase: 'all' };
export let attackPathFilter = { severity: 'all' };
export let vulnSearch = '';

// Filter event handlers
export function setupFilters() {
  // Vulnerability heatmap filters
  document.querySelectorAll('.vuln-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('vuln-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  document.querySelectorAll('.vuln-filter-type').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('vuln-filter-change', { detail: { type: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // MITRE heatmap filter
  document.querySelectorAll('.mitre-filter-tactic').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('mitre-filter-change', { detail: { tactic: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  });

  // Timeline filter
  document.querySelectorAll('.timeline-filter-phase').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('timeline-filter-change', { detail: { phase: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  }

  // Attack path filter
  document.querySelectorAll('.attack-path-filter-sev').forEach(el => {
    (el as HTMLSelectElement).addEventListener('change', function() {
      const event = new CustomEvent('attack-path-filter-change', { detail: { severity: (this as HTMLSelectElement).value } });
      window.dispatchEvent(event);
    });
  }

  // Evidence search
  const searchInput = document.getElementById('evidence-search');
  if (searchInput) {
    (searchInput as HTMLInputElement).addEventListener('input', function() {
      const event = new CustomEvent('evidence-search', { detail: { search: (this as HTMLInputElement).value.toLowerCase() } });
      window.dispatchEvent(event);
    });
  }
}

// Data accessor
export function getData(): any {
  return (window as any).REPORT_DATA;
}