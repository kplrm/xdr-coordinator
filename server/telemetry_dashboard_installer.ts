/*
 * Installs pre-built index-patterns, visualizations, and thirteen dashboards
 * for XDR Agent Telemetry, organised into tab-like views:
 *   - Host        — system CPU & memory metrics
 *   - Process     — per-process CPU usage and lifecycle
 *   - Network     — connection events, protocol/state distribution
 *   - Files       — File Integrity Monitoring (FIM) events, actions, top paths
 *   - File Access — credential / SSH file access alerts (T1003.008, T1552.004)
 *   - DNS         — query types, response codes, top queried domains
 *   - Sessions    — authentication, SSH, sudo, privilege escalation
 *   - Libraries   — shared library (SO) load events, unusual paths
 *   - Kernel      — kernel module load/unload events, module states
 *   - TTY         — terminal (TTY/PTY) session start/end events
 *   - Scheduled   — cron/anacron/at/systemd-timer change events
 *   - Injection   — process injection / ptrace alert events
 *   - IPC         — Unix domain socket and named pipe creation (T1559)
 *
 * Each dashboard carries a markdown "navigation bar" panel at the top whose
 * links point at the other dashboards, giving users a tab-switching UX
 * inside native OpenSearch Dashboards.
 *
 * Called once from plugin.start().
 */

import { ISavedObjectsRepository, Logger } from '../../../src/core/server';

// ── Stable IDs ──────────────────────────────────────────────────────────────
const INDEX_PATTERN_ID = 'xdr-agent-telemetry';

// Dashboards
const DASH_HOST = 'xdr-agent-telemetry-dashboard';        // reuse original ID
const DASH_PROCESS = 'xdr-agent-telemetry-processes';
const DASH_NETWORK = 'xdr-agent-telemetry-network';
const DASH_FILE    = 'xdr-agent-telemetry-file';

// Markdown navigation visualizations (one per dashboard)
const NAV_HOST    = 'xdr-tel-nav-host';
const NAV_PROCESS = 'xdr-tel-nav-process';
const NAV_NETWORK = 'xdr-tel-nav-network';
const NAV_FILE    = 'xdr-tel-nav-file';

// Host visualizations
const VIS_HOST_EVENTS = 'xdr-tel-vis-host-events';
const VIS_ACTIVE_AGENTS = 'xdr-tel-vis-active-agents';
const VIS_AVG_MEMORY = 'xdr-tel-vis-avg-memory';
const VIS_AVG_CPU = 'xdr-tel-vis-avg-cpu';
const VIS_SWAP_GAUGE = 'xdr-tel-vis-swap-gauge';
const VIS_DISK_GAUGE = 'xdr-tel-vis-disk-gauge';
const VIS_HOSTNAME_FILTER = 'xdr-tel-vis-hostname-filter';
const VIS_CPU_PER_AGENT = 'xdr-tel-vis-cpu-per-agent';
const VIS_MEMORY_TIMELINE = 'xdr-tel-vis-memory-timeline';
const VIS_CPU_BREAKDOWN = 'xdr-tel-vis-cpu-breakdown';
const VIS_DISKIO = 'xdr-tel-vis-diskio';
const VIS_NETIO = 'xdr-tel-vis-netio';

// Process visualizations
const VIS_PROCESS_EVENTS    = 'xdr-tel-vis-process-events';
const VIS_UNIQUE_PROCESSES  = 'xdr-tel-vis-unique-processes';
const VIS_CPU_PER_PROCESS   = 'xdr-tel-vis-cpu-per-process';
const VIS_PROCESS_TIMELINE  = 'xdr-tel-vis-process-timeline';
// Process visualizations — enriched lifecycle fields
const VIS_PROC_STARTS       = 'xdr-tel-vis-proc-starts';
const VIS_PROC_ENDS         = 'xdr-tel-vis-proc-ends';
const VIS_PROC_MEM_RSS      = 'xdr-tel-vis-proc-mem-rss';
const VIS_PROC_IO_RW        = 'xdr-tel-vis-proc-io-rw';
const VIS_PROC_THREADS      = 'xdr-tel-vis-proc-threads';
const VIS_PROC_STATE_PIE    = 'xdr-tel-vis-proc-state-pie';
const VIS_PROC_USER_PIE     = 'xdr-tel-vis-proc-user-pie';

// Network visualizations
const VIS_NETWORK_EVENTS = 'xdr-tel-vis-network-events';
const VIS_NET_INBOUND    = 'xdr-tel-vis-net-inbound';
const VIS_NET_OUTBOUND   = 'xdr-tel-vis-net-outbound';
const VIS_NET_PROTOCOL   = 'xdr-tel-vis-net-protocol';
const VIS_NET_STATE      = 'xdr-tel-vis-net-state';
const VIS_NET_DIRECTION  = 'xdr-tel-vis-net-direction';
const VIS_NET_TIMELINE   = 'xdr-tel-vis-net-timeline';

// File / FIM visualizations
const VIS_FIM_EVENTS     = 'xdr-tel-vis-fim-events';
const VIS_FIM_CREATED    = 'xdr-tel-vis-fim-created';
const VIS_FIM_MODIFIED   = 'xdr-tel-vis-fim-modified';
const VIS_FIM_DELETED    = 'xdr-tel-vis-fim-deleted';
const VIS_FIM_ACTION_PIE = 'xdr-tel-vis-fim-action-pie';
const VIS_FIM_FILE_TYPES = 'xdr-tel-vis-fim-file-types';
const VIS_FIM_BY_OWNER   = 'xdr-tel-vis-fim-owner';
const VIS_FIM_TIMELINE   = 'xdr-tel-vis-fim-timeline';
const VIS_FIM_TOP_DIRS   = 'xdr-tel-vis-fim-top-dirs';
const VIS_FIM_TOP_FILES  = 'xdr-tel-vis-fim-top-files';

// DNS visualizations
const DASH_DNS             = 'xdr-agent-telemetry-dns';
const NAV_DNS              = 'xdr-tel-nav-dns';
const VIS_DNS_EVENTS       = 'xdr-tel-vis-dns-events';
const VIS_DNS_QUERIES      = 'xdr-tel-vis-dns-queries';
const VIS_DNS_ANSWERS      = 'xdr-tel-vis-dns-answers';
const VIS_DNS_NXDOMAIN     = 'xdr-tel-vis-dns-nxdomain';
const VIS_DNS_QTYPE_PIE    = 'xdr-tel-vis-dns-qtype-pie';
const VIS_DNS_RCODE_PIE    = 'xdr-tel-vis-dns-rcode-pie';
const VIS_DNS_TOP_PROCS    = 'xdr-tel-vis-dns-top-procs';
const VIS_DNS_TIMELINE     = 'xdr-tel-vis-dns-timeline';
const VIS_DNS_TOP_DOMAINS  = 'xdr-tel-vis-dns-top-domains';
const VIS_DNS_TOP_RESOLVERS = 'xdr-tel-vis-dns-top-resolvers';

// Session / authentication visualizations
const DASH_SESSION             = 'xdr-agent-telemetry-session';
const NAV_SESSION              = 'xdr-tel-nav-session';
const VIS_SESSION_EVENTS       = 'xdr-tel-vis-session-events';
const VIS_SESSION_LOGINS       = 'xdr-tel-vis-session-logins';
const VIS_SESSION_LOGOFFS      = 'xdr-tel-vis-session-logoffs';
const VIS_SESSION_SSH_FAILED   = 'xdr-tel-vis-session-ssh-failed';
const VIS_SESSION_ACTION_PIE   = 'xdr-tel-vis-session-action-pie';
const VIS_SESSION_USERS_PIE    = 'xdr-tel-vis-session-users-pie';
const VIS_SESSION_SUDO         = 'xdr-tel-vis-session-sudo';
const VIS_SESSION_TIMELINE     = 'xdr-tel-vis-session-timeline';
const VIS_SESSION_SRC_IPS      = 'xdr-tel-vis-session-src-ips';
const VIS_SESSION_SUDO_TARGETS = 'xdr-tel-vis-session-sudo-targets';

// Library / SO-load visualizations
const DASH_LIBRARY              = 'xdr-agent-telemetry-library';
const NAV_LIBRARY               = 'xdr-tel-nav-library';
const VIS_LIB_EVENTS            = 'xdr-tel-vis-lib-events';
const VIS_LIB_UNIQUE            = 'xdr-tel-vis-lib-unique';
const VIS_LIB_UNIQUE_PROCS      = 'xdr-tel-vis-lib-unique-procs';
const VIS_LIB_NAME_PIE          = 'xdr-tel-vis-lib-name-pie';
const VIS_LIB_PROC_PIE          = 'xdr-tel-vis-lib-proc-pie';
const VIS_LIB_TIMELINE          = 'xdr-tel-vis-lib-timeline';
const VIS_LIB_TOP_PATHS         = 'xdr-tel-vis-lib-top-paths';

// Kernel module visualizations
const DASH_KERNEL               = 'xdr-agent-telemetry-kernel';
const NAV_KERNEL                = 'xdr-tel-nav-kernel';
const VIS_KERN_EVENTS           = 'xdr-tel-vis-kern-events';
const VIS_KERN_UNIQUE           = 'xdr-tel-vis-kern-unique';
const VIS_KERN_STATE_PIE        = 'xdr-tel-vis-kern-state-pie';
const VIS_KERN_ACTION_PIE       = 'xdr-tel-vis-kern-action-pie';
const VIS_KERN_TOP_MODULES      = 'xdr-tel-vis-kern-top-modules';
const VIS_KERN_TIMELINE         = 'xdr-tel-vis-kern-timeline';

// TTY session visualizations
const DASH_TTY                  = 'xdr-agent-telemetry-tty';
const NAV_TTY                   = 'xdr-tel-nav-tty';
const VIS_TTY_EVENTS            = 'xdr-tel-vis-tty-events';
const VIS_TTY_SESSIONS          = 'xdr-tel-vis-tty-sessions';
const VIS_TTY_PROC_PIE          = 'xdr-tel-vis-tty-proc-pie';
const VIS_TTY_NAME_PIE          = 'xdr-tel-vis-tty-name-pie';
const VIS_TTY_TOP_PROCS         = 'xdr-tel-vis-tty-top-procs';
const VIS_TTY_TIMELINE          = 'xdr-tel-vis-tty-timeline';

// Scheduled task visualizations
const DASH_SCHEDULED            = 'xdr-agent-telemetry-scheduled';
const NAV_SCHEDULED             = 'xdr-tel-nav-scheduled';
const VIS_SCHED_EVENTS          = 'xdr-tel-vis-sched-events';
const VIS_SCHED_UNIQUE_FILES    = 'xdr-tel-vis-sched-unique-files';
const VIS_SCHED_TYPE_PIE        = 'xdr-tel-vis-sched-type-pie';
const VIS_SCHED_ACTION_PIE      = 'xdr-tel-vis-sched-action-pie';
const VIS_SCHED_TOP_FILES       = 'xdr-tel-vis-sched-top-files';
const VIS_SCHED_TIMELINE        = 'xdr-tel-vis-sched-timeline';

// Injection / ptrace alert visualizations
const DASH_INJECTION            = 'xdr-agent-telemetry-injection';
const NAV_INJECTION             = 'xdr-tel-nav-injection';
const VIS_INJ_ALERTS            = 'xdr-tel-vis-inj-alerts';
const VIS_INJ_UNIQUE_TARGETS    = 'xdr-tel-vis-inj-unique-targets';
const VIS_INJ_UNIQUE_INDICATORS = 'xdr-tel-vis-inj-unique-indicators';
const VIS_INJ_INDICATOR_PIE     = 'xdr-tel-vis-inj-indicator-pie';
const VIS_INJ_TOP_TARGETS       = 'xdr-tel-vis-inj-top-targets';
const VIS_INJ_TOP_TRACERS       = 'xdr-tel-vis-inj-top-tracers';
const VIS_INJ_TIMELINE          = 'xdr-tel-vis-inj-timeline';

// File Access visualizations (telemetry.file.access — credential / SSH file reads)
const DASH_FILEACCESS           = 'xdr-agent-telemetry-fileaccess';
const NAV_FILEACCESS            = 'xdr-tel-nav-fileaccess';
const VIS_FA_EVENTS             = 'xdr-tel-vis-fa-events';
const VIS_FA_UNIQUE_FILES       = 'xdr-tel-vis-fa-unique-files';
const VIS_FA_TOP_FILES          = 'xdr-tel-vis-fa-top-files';
const VIS_FA_TOP_DIRS           = 'xdr-tel-vis-fa-top-dirs';
const VIS_FA_TECHNIQUE_PIE      = 'xdr-tel-vis-fa-technique-pie';
const VIS_FA_AGENTS_PIE         = 'xdr-tel-vis-fa-agents-pie';
const VIS_FA_TIMELINE           = 'xdr-tel-vis-fa-timeline';

// IPC visualizations (telemetry.ipc — Unix sockets + named pipes)
const DASH_IPC                  = 'xdr-agent-telemetry-ipc';
const NAV_IPC                   = 'xdr-tel-nav-ipc';
const VIS_IPC_EVENTS            = 'xdr-tel-vis-ipc-events';
const VIS_IPC_SOCKETS           = 'xdr-tel-vis-ipc-sockets';
const VIS_IPC_PIPES             = 'xdr-tel-vis-ipc-pipes';
const VIS_IPC_TYPE_PIE          = 'xdr-tel-vis-ipc-type-pie';
const VIS_IPC_TOP_SOCKETS       = 'xdr-tel-vis-ipc-top-sockets';
const VIS_IPC_TOP_PIPES         = 'xdr-tel-vis-ipc-top-pipes';
const VIS_IPC_TIMELINE          = 'xdr-tel-vis-ipc-timeline';

// ── Helpers ─────────────────────────────────────────────────────────────────
const ss = (query = '') =>
  JSON.stringify({
    index: INDEX_PATTERN_ID,
    query: { query, language: 'kuery' },
    filter: [],
  });

// Generic Arc gauge (green→yellow→red at standard thresholds)
const gaugeVis = (title: string, field: string, label: string, ranges: Array<{ from: number; to: number }>) =>
  JSON.stringify({
    title,
    type: 'gauge',
    params: {
      type: 'gauge', addTooltip: true, addLegend: false, isDisplayWarning: false,
      gauge: {
        verticalSplit: false, extendRange: true, percentageMode: false,
        gaugeType: 'Arc', gaugeColorMode: 'Labels',
        colorsRange: ranges,
        invertColors: false,
        labels: { show: true, color: 'black' },
        scale: { show: true, labels: false, color: '#333' },
        type: 'meter',
        style: { bgWidth: 0.9, width: 0.9, mask: false, bgMask: false, maskBars: 50, bgFill: '#eee', bgColor: false, subText: '', fontSize: 60 },
        minAngle: 0, maxAngle: 6.283, alignment: 'automatic',
      },
    },
    aggs: [{ id: '1', enabled: true, type: 'avg', schema: 'metric', params: { field, customLabel: label } }],
  });

// Dual-series area chart (two average metrics over time, no group-by split)
const dualAreaVis = (title: string, f1: string, l1: string, f2: string, l2: string, yTitle: string) =>
  JSON.stringify({
    title,
    type: 'area',
    params: {
      type: 'area',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [{ id: 'CategoryAxis-1', type: 'category', position: 'bottom', show: true, style: {}, scale: { type: 'linear' }, labels: { show: true, truncate: 100, filter: true }, title: {} }],
      valueAxes: [{ id: 'ValueAxis-1', name: 'LeftAxis-1', type: 'value', position: 'left', show: true, style: {}, scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 }, title: { text: yTitle } }],
      seriesParams: [
        { show: true, type: 'area', mode: 'normal', data: { label: l1, id: '1' }, valueAxis: 'ValueAxis-1', drawLinesBetweenPoints: true, showCircles: true, interpolate: 'linear', lineWidth: 2 },
        { show: true, type: 'area', mode: 'normal', data: { label: l2, id: '2' }, valueAxis: 'ValueAxis-1', drawLinesBetweenPoints: true, showCircles: true, interpolate: 'linear', lineWidth: 2 },
      ],
      addTooltip: true, addLegend: true, legendPosition: 'top',
      times: [], addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: 'avg', schema: 'metric', params: { field: f1, customLabel: l1 } },
      { id: '2', enabled: true, type: 'avg', schema: 'metric', params: { field: f2, customLabel: l2 } },
      { id: '3', enabled: true, type: 'date_histogram', schema: 'segment', params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} } },
    ],
  });

const metricVis = (
  title: string,
  aggField: string | null,
  aggType: 'count' | 'cardinality' | 'avg',
  customLabel: string
) => {
  const agg: any =
    aggType === 'count'
      ? { id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel } }
      : { id: '1', enabled: true, type: aggType, schema: 'metric', params: { field: aggField, customLabel } };

  return JSON.stringify({
    title,
    type: 'metric',
    params: {
      addTooltip: true,
      addLegend: false,
      type: 'metric',
      metric: {
        percentageMode: false,
        useRanges: false,
        colorSchema: 'Green to Red',
        metricColorMode: 'None',
        colorsRange: [{ from: 0, to: 10000 }],
        labels: { show: true },
        style: { bgFill: '#000', bgColor: false, labelColor: false, subText: '', fontSize: 60 },
      },
    },
    aggs: [agg],
  });
};

const markdownVis = (title: string, md: string) =>
  JSON.stringify({
    title,
    type: 'markdown',
    params: { markdown: md, openLinksInNewTab: false, fontSize: 14 },
    aggs: [],
  });

const areaVis = (title: string, metricField: string, metricLabel: string, groupField: string, yTitle: string) =>
  JSON.stringify({
    title,
    type: 'area',
    params: {
      type: 'area',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [{
        id: 'CategoryAxis-1', type: 'category', position: 'bottom', show: true, style: {},
        scale: { type: 'linear' }, labels: { show: true, truncate: 100, filter: true }, title: {},
      }],
      valueAxes: [{
        id: 'ValueAxis-1', name: 'LeftAxis-1', type: 'value', position: 'left', show: true, style: {},
        scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 },
        title: { text: yTitle },
      }],
      seriesParams: [{
        show: true, type: 'area', mode: 'normal',
        data: { label: metricLabel, id: '1' },
        drawLinesBetweenPoints: true, showCircles: true, interpolate: 'linear', lineWidth: 2,
        valueAxis: 'ValueAxis-1',
      }],
      addTooltip: true, addLegend: true, legendPosition: 'top',
      times: [], addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: 'avg', schema: 'metric', params: { field: metricField, customLabel: metricLabel } },
      { id: '2', enabled: true, type: 'date_histogram', schema: 'segment', params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} } },
      { id: '3', enabled: true, type: 'terms', schema: 'group', params: { field: groupField, size: 20, order: 'desc', orderBy: '1', otherBucket: false, missingBucket: false } },
    ],
  });

const pieVis = (title: string, termField: string, termLabel: string, topN = 10) =>
  JSON.stringify({
    title,
    type: 'pie',
    params: {
      type: 'pie', addTooltip: true, addLegend: true, legendPosition: 'right',
      isDonut: true, labels: { show: true, values: true, last_level: true, truncate: 100 },
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
      { id: '2', enabled: true, type: 'terms', schema: 'segment', params: {
        field: termField, size: topN, order: 'desc', orderBy: '1',
        otherBucket: true, otherBucketLabel: 'Other', missingBucket: false, missingBucketLabel: 'Missing',
        customLabel: termLabel,
      }},
    ],
  });

// Top-N horizontal bar — single metric field aggregated by process name
const topNBarVis = (
  title: string,
  metricField: string,
  metricLabel: string,
  yTitle: string,
  aggType: 'avg' | 'sum' = 'avg'
) =>
  JSON.stringify({
    title,
    type: 'horizontal_bar',
    params: {
      type: 'horizontal_bar',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [{
        id: 'CategoryAxis-1', type: 'category', position: 'left', show: true, style: {},
        scale: { type: 'linear' }, labels: { show: true, truncate: 200, filter: true }, title: {},
      }],
      valueAxes: [{
        id: 'ValueAxis-1', name: 'BottomAxis-1', type: 'value', position: 'bottom', show: true, style: {},
        scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 },
        title: { text: yTitle },
      }],
      seriesParams: [{ show: true, type: 'histogram', mode: 'normal',
        data: { label: metricLabel, id: '1' }, valueAxis: 'ValueAxis-1' }],
      addTooltip: true, addLegend: true, legendPosition: 'right',
      times: [], addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: aggType, schema: 'metric',
        params: { field: metricField, customLabel: metricLabel } },
      { id: '2', enabled: true, type: 'terms', schema: 'segment',
        params: { field: 'payload.process.name', size: 20, order: 'desc', orderBy: '1',
          otherBucket: false, missingBucket: false, customLabel: 'Process' } },
    ],
  });

// Dual-series horizontal bar (two sum metrics stacked, bucketed by process name)
const dualTopNBarVis = (
  title: string,
  f1: string, l1: string,
  f2: string, l2: string,
  yTitle: string
) =>
  JSON.stringify({
    title,
    type: 'horizontal_bar',
    params: {
      type: 'horizontal_bar',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [{
        id: 'CategoryAxis-1', type: 'category', position: 'left', show: true, style: {},
        scale: { type: 'linear' }, labels: { show: true, truncate: 200, filter: true }, title: {},
      }],
      valueAxes: [{
        id: 'ValueAxis-1', name: 'BottomAxis-1', type: 'value', position: 'bottom', show: true, style: {},
        scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 },
        title: { text: yTitle },
      }],
      seriesParams: [
        { show: true, type: 'histogram', mode: 'stacked', data: { label: l1, id: '1' }, valueAxis: 'ValueAxis-1' },
        { show: true, type: 'histogram', mode: 'stacked', data: { label: l2, id: '2' }, valueAxis: 'ValueAxis-1' },
      ],
      addTooltip: true, addLegend: true, legendPosition: 'right',
      times: [], addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: 'sum', schema: 'metric', params: { field: f1, customLabel: l1 } },
      { id: '2', enabled: true, type: 'sum', schema: 'metric', params: { field: f2, customLabel: l2 } },
      { id: '3', enabled: true, type: 'terms', schema: 'segment',
        params: { field: 'payload.process.name', size: 20, order: 'desc', orderBy: '1',
          otherBucket: false, missingBucket: false, customLabel: 'Process' } },
    ],
  });

const countAreaVis = (title: string, yTitle: string) =>
  JSON.stringify({
    title,
    type: 'area',
    params: {
      type: 'area',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [{
        id: 'CategoryAxis-1', type: 'category', position: 'bottom', show: true, style: {},
        scale: { type: 'linear' }, labels: { show: true, truncate: 100, filter: true }, title: {},
      }],
      valueAxes: [{
        id: 'ValueAxis-1', name: 'LeftAxis-1', type: 'value', position: 'left', show: true, style: {},
        scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 },
        title: { text: yTitle },
      }],
      seriesParams: [{
        show: true, type: 'area', mode: 'normal',
        data: { label: 'Count', id: '1' },
        drawLinesBetweenPoints: true, showCircles: true, interpolate: 'linear', lineWidth: 2,
        valueAxis: 'ValueAxis-1',
      }],
      addTooltip: true, addLegend: false, legendPosition: 'top',
      times: [], addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel: 'Count' } },
      { id: '2', enabled: true, type: 'date_histogram', schema: 'segment', params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} } },
    ],
  });

// Count-over-time area chart with a terms group-by split (e.g. FIM action)
const countAreaGroupVis = (title: string, groupField: string, groupLabel: string, yTitle: string) =>
  JSON.stringify({
    title,
    type: 'area',
    params: {
      type: 'area',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [{
        id: 'CategoryAxis-1', type: 'category', position: 'bottom', show: true, style: {},
        scale: { type: 'linear' }, labels: { show: true, truncate: 100, filter: true }, title: {},
      }],
      valueAxes: [{
        id: 'ValueAxis-1', name: 'LeftAxis-1', type: 'value', position: 'left', show: true, style: {},
        scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 },
        title: { text: yTitle },
      }],
      seriesParams: [{
        show: true, type: 'area', mode: 'stacked',
        data: { label: 'Count', id: '1' },
        drawLinesBetweenPoints: true, showCircles: true, interpolate: 'linear', lineWidth: 2,
        valueAxis: 'ValueAxis-1',
      }],
      addTooltip: true, addLegend: true, legendPosition: 'top',
      times: [], addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel: 'Count' } },
      { id: '2', enabled: true, type: 'date_histogram', schema: 'segment',
        params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} } },
      { id: '3', enabled: true, type: 'terms', schema: 'group',
        params: { field: groupField, size: 10, order: 'desc', orderBy: '1',
          otherBucket: false, missingBucket: false, customLabel: groupLabel } },
    ],
  });

// Top-N horizontal bar: count of events per term value (for directories, file paths, etc.)
const topNTermsCountBarVis = (title: string, termField: string, termLabel: string, topN = 15) =>
  JSON.stringify({
    title,
    type: 'horizontal_bar',
    params: {
      type: 'horizontal_bar',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [{
        id: 'CategoryAxis-1', type: 'category', position: 'left', show: true, style: {},
        scale: { type: 'linear' }, labels: { show: true, truncate: 300, filter: true }, title: {},
      }],
      valueAxes: [{
        id: 'ValueAxis-1', name: 'BottomAxis-1', type: 'value', position: 'bottom', show: true, style: {},
        scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 },
        title: { text: 'Events' },
      }],
      seriesParams: [{ show: true, type: 'histogram', mode: 'normal',
        data: { label: 'Events', id: '1' }, valueAxis: 'ValueAxis-1' }],
      addTooltip: true, addLegend: false, legendPosition: 'right',
      times: [], addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel: 'Events' } },
      { id: '2', enabled: true, type: 'terms', schema: 'segment',
        params: { field: termField, size: topN, order: 'desc', orderBy: '1',
          otherBucket: true, otherBucketLabel: 'Other', missingBucket: false,
          missingBucketLabel: 'Missing', customLabel: termLabel } },
    ],
  });

// ── Saved Objects ───────────────────────────────────────────────────────────

function vis(id: string, title: string, description: string, visState: string, query = '') {
  return {
    type: 'visualization',
    id,
    attributes: {
      title,
      visState,
      uiStateJSON: '{}',
      description,
      version: 1,
      kibanaSavedObjectMeta: { searchSourceJSON: ss(query) },
    },
    references: [],
  };
}

function dashboard(
  id: string,
  title: string,
  description: string,
  panels: Array<{ x: number; y: number; w: number; h: number; ref: string }>,
  refs: Array<{ name: string; id: string }>
) {
  let idx = 1;
  const panelsJSON = panels.map((p) => {
    const i = String(idx++);
    return {
      embeddableConfig: {},
      gridData: { x: p.x, y: p.y, w: p.w, h: p.h, i },
      panelIndex: i,
      version: '2.19.0',
      panelRefName: p.ref,
    };
  });

  return {
    type: 'dashboard',
    id,
    attributes: {
      title,
      hits: 0,
      description,
      panelsJSON: JSON.stringify(panelsJSON),
      optionsJSON: JSON.stringify({ hidePanelTitles: false, useMargins: true }),
      version: 1,
      timeRestore: true,
      timeTo: 'now',
      timeFrom: 'now-24h',
      refreshInterval: { pause: false, value: 30000 },
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          query: { language: 'kuery', query: '' },
          filter: [],
        }),
      },
    },
    references: refs.map((r) => ({ name: r.name, type: 'visualization', id: r.id })),
  };
}

// ── Markdown tab navigation ─────────────────────────────────────────────────
const navMd = (active: 'host' | 'process' | 'network' | 'file' | 'fileaccess' | 'dns' | 'session' | 'library' | 'kernel' | 'tty' | 'scheduled' | 'injection' | 'ipc') => {
  const hostLabel        = active === 'host'        ? '**▸ Host**'         : `[Host](/app/dashboards#/view/${DASH_HOST})`;
  const procLabel        = active === 'process'     ? '**▸ Processes**'    : `[Processes](/app/dashboards#/view/${DASH_PROCESS})`;
  const netLabel         = active === 'network'     ? '**▸ Network**'      : `[Network](/app/dashboards#/view/${DASH_NETWORK})`;
  const fileLabel        = active === 'file'        ? '**▸ Files**'        : `[Files](/app/dashboards#/view/${DASH_FILE})`;
  const fileaccessLabel  = active === 'fileaccess'  ? '**▸ File Access**'  : `[File Access](/app/dashboards#/view/${DASH_FILEACCESS})`;
  const dnsLabel         = active === 'dns'         ? '**▸ DNS**'          : `[DNS](/app/dashboards#/view/${DASH_DNS})`;
  const sessionLabel     = active === 'session'     ? '**▸ Sessions**'     : `[Sessions](/app/dashboards#/view/${DASH_SESSION})`;
  const libraryLabel     = active === 'library'     ? '**▸ Libraries**'    : `[Libraries](/app/dashboards#/view/${DASH_LIBRARY})`;
  const kernelLabel      = active === 'kernel'      ? '**▸ Kernel**'       : `[Kernel](/app/dashboards#/view/${DASH_KERNEL})`;
  const ttyLabel         = active === 'tty'         ? '**▸ TTY**'          : `[TTY](/app/dashboards#/view/${DASH_TTY})`;
  const scheduledLabel   = active === 'scheduled'   ? '**▸ Scheduled**'    : `[Scheduled](/app/dashboards#/view/${DASH_SCHEDULED})`;
  const injectionLabel   = active === 'injection'   ? '**▸ Injection**'    : `[Injection](/app/dashboards#/view/${DASH_INJECTION})`;
  const ipcLabel         = active === 'ipc'         ? '**▸ IPC**'          : `[IPC](/app/dashboards#/view/${DASH_IPC})`;
  return `### XDR Agent Telemetry\n${hostLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${procLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${netLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${fileLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${fileaccessLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${dnsLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${sessionLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${libraryLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${kernelLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${ttyLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${scheduledLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${injectionLabel} &nbsp;&nbsp;|&nbsp;&nbsp; ${ipcLabel}`;
};

function buildSavedObjects() {
  // ── Index pattern (shared) ──────────────────────────────────────────────
  const indexPattern = {
    type: 'index-pattern',
    id: INDEX_PATTERN_ID,
    attributes: {
      title: '.xdr-agent-telemetry-*',
      timeFieldName: '@timestamp',
      fields: '[]',
    },
    references: [],
  };

  // ── Navigation markdown visualizations ──────────────────────────────────
  const navHost = vis(NAV_HOST, '[XDR] Nav — Host',
    'Tab navigation (Host active)',
    markdownVis('[XDR] Nav — Host', navMd('host')));

  const navProcess = vis(NAV_PROCESS, '[XDR] Nav — Processes',
    'Tab navigation (Processes active)',
    markdownVis('[XDR] Nav — Processes', navMd('process')));

  const navNetwork = vis(NAV_NETWORK, '[XDR] Nav — Network',
    'Tab navigation (Network active)',
    markdownVis('[XDR] Nav — Network', navMd('network')));

  const navFile = vis(NAV_FILE, '[XDR] Nav — Files',
    'Tab navigation (Files active)',
    markdownVis('[XDR] Nav — Files', navMd('file')));

  const navDns = vis(NAV_DNS, '[XDR] Nav — DNS',
    'Tab navigation (DNS active)',
    markdownVis('[XDR] Nav — DNS', navMd('dns')));

  const navSession = vis(NAV_SESSION, '[XDR] Nav — Sessions',
    'Tab navigation (Sessions active)',
    markdownVis('[XDR] Nav — Sessions', navMd('session')));

  const navLibrary = vis(NAV_LIBRARY, '[XDR] Nav — Libraries',
    'Tab navigation (Libraries active)',
    markdownVis('[XDR] Nav — Libraries', navMd('library')));

  const navKernel = vis(NAV_KERNEL, '[XDR] Nav — Kernel',
    'Tab navigation (Kernel active)',
    markdownVis('[XDR] Nav — Kernel', navMd('kernel')));

  const navTty = vis(NAV_TTY, '[XDR] Nav — TTY',
    'Tab navigation (TTY active)',
    markdownVis('[XDR] Nav — TTY', navMd('tty')));

  const navScheduled = vis(NAV_SCHEDULED, '[XDR] Nav — Scheduled',
    'Tab navigation (Scheduled active)',
    markdownVis('[XDR] Nav — Scheduled', navMd('scheduled')));

  const navInjection = vis(NAV_INJECTION, '[XDR] Nav — Injection',
    'Tab navigation (Injection active)',
    markdownVis('[XDR] Nav — Injection', navMd('injection')));

  const navFileaccess = vis(NAV_FILEACCESS, '[XDR] Nav — File Access',
    'Tab navigation (File Access active)',
    markdownVis('[XDR] Nav — File Access', navMd('fileaccess')));

  const navIpc = vis(NAV_IPC, '[XDR] Nav — IPC',
    'Tab navigation (IPC active)',
    markdownVis('[XDR] Nav — IPC', navMd('ipc')));

  // ═══════════════════════════════════════════════════════════════════════════
  // HOST visualizations
  // ═══════════════════════════════════════════════════════════════════════════
  const visHostEvents = vis(VIS_HOST_EVENTS,
    '[XDR] Host Events', 'Count of host-category telemetry events',
    metricVis('[XDR] Host Events', null, 'count', 'Host Events'),
    'event.category: "host"');

  const visActiveAgents = vis(VIS_ACTIVE_AGENTS,
    '[XDR] Active Agents', 'Unique agent count in the selected time range',
    metricVis('[XDR] Active Agents', 'agent.id', 'cardinality', 'Active Agents'),
    'event.category: "host"');

  const visAvgMemory = vis(VIS_AVG_MEMORY,
    '[XDR] Avg Memory Used %',
    'Average memory used percentage across all agents',
    gaugeVis('[XDR] Avg Memory Used %', 'payload.system.memory.used.pct', 'Avg Memory %',
      [{ from: 0, to: 50 }, { from: 50, to: 75 }, { from: 75, to: 100 }]),
    'event.category: "host"');

  const visAvgCpu = vis(VIS_AVG_CPU,
    '[XDR] Avg CPU Used %',
    'Average CPU used percentage across all agents',
    gaugeVis('[XDR] Avg CPU Used %', 'payload.system.cpu.total.pct', 'Avg CPU %',
      [{ from: 0, to: 50 }, { from: 50, to: 75 }, { from: 75, to: 100 }]),
    'event.category: "host"');

  const visSwapGauge = vis(VIS_SWAP_GAUGE,
    '[XDR] Swap Used %',
    'Average swap used percentage across all agents',
    gaugeVis('[XDR] Swap Used %', 'payload.system.memory.swap.used.pct', 'Avg Swap %',
      [{ from: 0, to: 50 }, { from: 50, to: 80 }, { from: 80, to: 100 }]),
    'event.category: "host"');

  const visDiskGauge = vis(VIS_DISK_GAUGE,
    '[XDR] Disk Used % (root)',
    'Average root filesystem used percentage across all agents',
    gaugeVis('[XDR] Disk Used % (root)', 'payload.system.disk.root.used.pct', 'Disk %',
      [{ from: 0, to: 70 }, { from: 70, to: 85 }, { from: 85, to: 100 }]),
    'event.category: "host"');

  const visHostnameFilter = {
    type: 'visualization',
    id: VIS_HOSTNAME_FILTER,
    attributes: {
      title: '[XDR] Filter by Hostname',
      visState: JSON.stringify({
        title: '[XDR] Filter by Hostname',
        type: 'input_control_vis',
        params: {
          controls: [{
            id: '1',
            fieldName: 'host.hostname',
            indexPatternRefName: 'indexPattern_0',
            label: 'Host',
            type: 'list',
            options: {
              type: 'terms',
              multiselect: true,
              size: 100,
              order: 'desc',
              dynamicOptions: true,
            },
          }],
          updateFiltersOnChange: true,
          useTimeFilter: true,
          pinFilters: false,
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: 'Filter host telemetry by host.hostname',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({ filter: [], query: { query: '', language: 'kuery' } }),
      },
    },
    references: [{ name: 'indexPattern_0', type: 'index-pattern', id: INDEX_PATTERN_ID }],
  };

  const visCpuPerAgent = vis(VIS_CPU_PER_AGENT,
    '[XDR] CPU Usage per Agent',
    'CPU usage % over time, split by agent',
    areaVis('[XDR] CPU Usage per Agent', 'payload.system.cpu.total.pct', 'Avg CPU %', 'agent.id', 'CPU Usage %'),
    'event.category: "host"');

  const visMemTimeline = vis(VIS_MEMORY_TIMELINE,
    '[XDR] Memory Usage Over Time',
    'Memory used % over time, broken down by agent',
    areaVis('[XDR] Memory Usage Over Time', 'payload.system.memory.used.pct', 'Avg Memory %', 'agent.id', 'Memory Used %'),
    'event.category: "host"');

  const visCpuBreakdown = vis(VIS_CPU_BREAKDOWN,
    '[XDR] CPU Breakdown',
    'CPU time breakdown by mode: user, system, iowait, steal',
    JSON.stringify({
      title: '[XDR] CPU Breakdown',
      type: 'area',
      params: {
        type: 'area',
        grid: { categoryLines: false, style: { color: '#eee' } },
        categoryAxes: [{ id: 'CategoryAxis-1', type: 'category', position: 'bottom', show: true, style: {}, scale: { type: 'linear' }, labels: { show: true, truncate: 100, filter: true }, title: {} }],
        valueAxes: [{ id: 'ValueAxis-1', name: 'LeftAxis-1', type: 'value', position: 'left', show: true, style: {}, scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 }, title: { text: 'CPU %' } }],
        seriesParams: [
          { show: true, type: 'area', mode: 'stacked', data: { label: 'User %', id: '1' }, valueAxis: 'ValueAxis-1', drawLinesBetweenPoints: true, showCircles: false, interpolate: 'linear', lineWidth: 1 },
          { show: true, type: 'area', mode: 'stacked', data: { label: 'System %', id: '2' }, valueAxis: 'ValueAxis-1', drawLinesBetweenPoints: true, showCircles: false, interpolate: 'linear', lineWidth: 1 },
          { show: true, type: 'area', mode: 'stacked', data: { label: 'IOWait %', id: '3' }, valueAxis: 'ValueAxis-1', drawLinesBetweenPoints: true, showCircles: false, interpolate: 'linear', lineWidth: 1 },
          { show: true, type: 'area', mode: 'stacked', data: { label: 'Steal %', id: '4' }, valueAxis: 'ValueAxis-1', drawLinesBetweenPoints: true, showCircles: false, interpolate: 'linear', lineWidth: 1 },
        ],
        addTooltip: true, addLegend: true, legendPosition: 'top',
        times: [], addTimeMarker: false,
      },
      aggs: [
        { id: '1', enabled: true, type: 'avg', schema: 'metric', params: { field: 'payload.system.cpu.user.pct', customLabel: 'User %' } },
        { id: '2', enabled: true, type: 'avg', schema: 'metric', params: { field: 'payload.system.cpu.system.pct', customLabel: 'System %' } },
        { id: '3', enabled: true, type: 'avg', schema: 'metric', params: { field: 'payload.system.cpu.iowait.pct', customLabel: 'IOWait %' } },
        { id: '4', enabled: true, type: 'avg', schema: 'metric', params: { field: 'payload.system.cpu.steal.pct', customLabel: 'Steal %' } },
        { id: '5', enabled: true, type: 'date_histogram', schema: 'segment', params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} } },
      ],
    }),
    'event.category: "host"');

  const visDiskIO = vis(VIS_DISKIO,
    '[XDR] Disk I/O',
    'Disk read vs write bytes per collection interval',
    dualAreaVis('[XDR] Disk I/O', 'payload.system.diskio.read.bytes', 'Read bytes', 'payload.system.diskio.write.bytes', 'Write bytes', 'Bytes / interval'),
    'event.category: "host"');

  const visNetIO = vis(VIS_NETIO,
    '[XDR] Network I/O',
    'Network inbound vs outbound bytes per collection interval',
    dualAreaVis('[XDR] Network I/O', 'payload.system.netio.in.bytes', 'In bytes', 'payload.system.netio.out.bytes', 'Out bytes', 'Bytes / interval'),
    'event.category: "host"');

  // ═══════════════════════════════════════════════════════════════════════════
  // PROCESS visualizations
  // ═══════════════════════════════════════════════════════════════════════════
  const visProcessEvents = vis(VIS_PROCESS_EVENTS,
    '[XDR] Process Events', 'Count of process-category telemetry events',
    metricVis('[XDR] Process Events', null, 'count', 'Process Events'),
    'event.category: "process"');

  const visUniqueProcs = vis(VIS_UNIQUE_PROCESSES,
    '[XDR] Unique Processes', 'Distinct process names observed',
    metricVis('[XDR] Unique Processes', 'payload.process.name', 'cardinality', 'Unique Processes'),
    'event.category: "process"');

  const visCpuPerProcess = vis(VIS_CPU_PER_PROCESS,
    '[XDR] CPU per Process',
    'Top processes by average CPU usage',
    JSON.stringify({
      title: '[XDR] CPU per Process',
      type: 'horizontal_bar',
      params: {
        type: 'horizontal_bar',
        grid: { categoryLines: false, style: { color: '#eee' } },
        categoryAxes: [{ id: 'CategoryAxis-1', type: 'category', position: 'left', show: true, style: {},
          scale: { type: 'linear' }, labels: { show: true, truncate: 200, filter: true }, title: {} }],
        valueAxes: [{ id: 'ValueAxis-1', name: 'BottomAxis-1', type: 'value', position: 'bottom', show: true, style: {},
          scale: { type: 'linear', mode: 'normal' }, labels: { show: true, rotate: 0, filter: false, truncate: 100 },
          title: { text: 'Avg CPU %' } }],
        seriesParams: [{ show: true, type: 'histogram', mode: 'normal',
          data: { label: 'Avg CPU %', id: '1' }, valueAxis: 'ValueAxis-1' }],
        addTooltip: true, addLegend: true, legendPosition: 'right',
        times: [], addTimeMarker: false,
      },
      aggs: [
        { id: '1', enabled: true, type: 'avg', schema: 'metric',
          params: { field: 'payload.process.cpu.pct', customLabel: 'Avg CPU %' } },
        { id: '2', enabled: true, type: 'terms', schema: 'segment',
          params: { field: 'payload.process.name', size: 20, order: 'desc', orderBy: '1',
            otherBucket: false, missingBucket: false, customLabel: 'Process' } },
      ],
    }),
    'event.category: "process"');

  const visProcTimeline = vis(VIS_PROCESS_TIMELINE,
    '[XDR] Process Events Over Time',
    'Process event count over time',
    countAreaVis('[XDR] Process Events Over Time', 'Events'),
    'event.category: "process"');

  // ── PROCESS visualizations — enriched lifecycle fields ──────────────────
  const visProcStarts = vis(VIS_PROC_STARTS,
    '[XDR] Process Starts',
    'Count of process.start events in the selected time range',
    metricVis('[XDR] Process Starts', null, 'count', 'Process Starts'),
    'event.category: "process" and event.type: "process.start"');

  const visProcEnds = vis(VIS_PROC_ENDS,
    '[XDR] Process Exits',
    'Count of process.end events in the selected time range',
    metricVis('[XDR] Process Exits', null, 'count', 'Process Exits'),
    'event.category: "process" and event.type: "process.end"');

  const visProcMemRss = vis(VIS_PROC_MEM_RSS,
    '[XDR] RSS Memory per Process',
    'Average resident-set-size (RSS) memory per process — top 20',
    topNBarVis('[XDR] RSS Memory per Process',
      'payload.process.memory.rss', 'Avg RSS (bytes)', 'Bytes', 'avg'),
    'event.category: "process" and event.type: "process.start"');

  const visProcIoRw = vis(VIS_PROC_IO_RW,
    '[XDR] I/O Bytes per Process (Read + Write)',
    'Cumulative I/O read and write bytes to disk per process — top 20 by read',
    dualTopNBarVis('[XDR] I/O Bytes per Process',
      'payload.process.io.read_bytes',  'Read Bytes',
      'payload.process.io.write_bytes', 'Write Bytes',
      'Bytes'),
    'event.category: "process" and event.type: "process.start"');

  const visProcThreads = vis(VIS_PROC_THREADS,
    '[XDR] Thread Count per Process',
    'Average thread count per process — top 20',
    topNBarVis('[XDR] Thread Count per Process',
      'payload.process.threads.count', 'Avg Threads', 'Threads', 'avg'),
    'event.category: "process" and event.type: "process.start"');

  const visProcStatePie = vis(VIS_PROC_STATE_PIE,
    '[XDR] Process State Distribution',
    'Breakdown of process states: R (Running), S (Sleeping), D (Disk Wait), Z (Zombie), T (Stopped)',
    pieVis('[XDR] Process State Distribution', 'payload.process.state', 'State', 10),
    'event.category: "process" and event.type: "process.start"');

  const visProcUserPie = vis(VIS_PROC_USER_PIE,
    '[XDR] Processes by User',
    'Which users are running the most processes',
    pieVis('[XDR] Processes by User', 'payload.process.user.id', 'User', 15),
    'event.category: "process" and event.type: "process.start"');

  // ═══════════════════════════════════════════════════════════════════════════
  // NETWORK visualizations
  // ═══════════════════════════════════════════════════════════════════════════
  const visNetEvents = vis(VIS_NETWORK_EVENTS,
    '[XDR] Network Events', 'Count of network-category telemetry events',
    metricVis('[XDR] Network Events', null, 'count', 'Network Events'),
    'event.category: "network"');

  const visNetInbound = vis(VIS_NET_INBOUND,
    '[XDR] Inbound Connections', 'Count of inbound network events',
    metricVis('[XDR] Inbound Connections', null, 'count', '↓ Inbound'),
    'event.category: "network" and payload.network.direction: "inbound"');

  const visNetOutbound = vis(VIS_NET_OUTBOUND,
    '[XDR] Outbound Connections', 'Count of outbound network events',
    metricVis('[XDR] Outbound Connections', null, 'count', '↑ Outbound'),
    'event.category: "network" and payload.network.direction: "outbound"');

  const visNetProtocol = vis(VIS_NET_PROTOCOL,
    '[XDR] Protocol Distribution', 'Network events by protocol',
    pieVis('[XDR] Protocol Distribution', 'payload.network.protocol', 'Protocol'),
    'event.category: "network"');

  const visNetState = vis(VIS_NET_STATE,
    '[XDR] Connection States', 'Network events by TCP state',
    pieVis('[XDR] Connection States', 'payload.network.state', 'State'),
    'event.category: "network"');

  const visNetDirection = vis(VIS_NET_DIRECTION,
    '[XDR] Traffic Direction', 'Network events by direction',
    pieVis('[XDR] Traffic Direction', 'payload.network.direction', 'Direction'),
    'event.category: "network"');

  const visNetTimeline = vis(VIS_NET_TIMELINE,
    '[XDR] Network Events Over Time', 'Network event count over time',
    countAreaVis('[XDR] Network Events Over Time', 'Events'),
    'event.category: "network"');

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE / FIM visualizations
  // Fields: event.category="file", payload.fim.action, payload.file.*
  // Actions: created | modified | attributes_modified | deleted
  // ═══════════════════════════════════════════════════════════════════════════
  const visFimEvents = vis(VIS_FIM_EVENTS,
    '[XDR] FIM Events', 'Total count of file integrity monitoring events',
    metricVis('[XDR] FIM Events', null, 'count', 'FIM Events'),
    'event.category: "file"');

  const visFimCreated = vis(VIS_FIM_CREATED,
    '[XDR] Files Created', 'Count of file creation events',
    metricVis('[XDR] Files Created', null, 'count', 'Created'),
    'event.category: "file" and payload.fim.action: "created"');

  const visFimModified = vis(VIS_FIM_MODIFIED,
    '[XDR] Files Modified', 'Count of file modification events',
    metricVis('[XDR] Files Modified', null, 'count', 'Modified'),
    'event.category: "file" and payload.fim.action: "modified"');

  const visFimDeleted = vis(VIS_FIM_DELETED,
    '[XDR] Files Deleted', 'Count of file deletion events',
    metricVis('[XDR] Files Deleted', null, 'count', 'Deleted'),
    'event.category: "file" and payload.fim.action: "deleted"');

  const visFimActionPie = vis(VIS_FIM_ACTION_PIE,
    '[XDR] FIM Action Distribution', 'File events broken down by action type',
    pieVis('[XDR] FIM Action Distribution', 'payload.fim.action', 'Action', 10),
    'event.category: "file"');

  const visFimFileTypes = vis(VIS_FIM_FILE_TYPES,
    '[XDR] File Types', 'File events broken down by file type (file / dir / symlink)',
    pieVis('[XDR] File Types', 'payload.file.type', 'File Type', 10),
    'event.category: "file"');

  const visFimByOwner = vis(VIS_FIM_BY_OWNER,
    '[XDR] FIM Events by Owner', 'File events broken down by file owner (username)',
    pieVis('[XDR] FIM Events by Owner', 'payload.file.owner', 'Owner', 15),
    'event.category: "file"');

  const visFimTimeline = vis(VIS_FIM_TIMELINE,
    '[XDR] FIM Events Over Time', 'File integrity events over time, stacked by action',
    countAreaGroupVis('[XDR] FIM Events Over Time', 'payload.fim.action', 'Action', 'Events'),
    'event.category: "file"');

  const visFimTopDirs = vis(VIS_FIM_TOP_DIRS,
    '[XDR] Most Active Directories', 'Top 15 directories by FIM event count',
    topNTermsCountBarVis('[XDR] Most Active Directories', 'payload.file.directory', 'Directory', 15),
    'event.category: "file"');

  const visFimTopFiles = vis(VIS_FIM_TOP_FILES,
    '[XDR] Most Active Files', 'Top 15 files by FIM event count',
    topNTermsCountBarVis('[XDR] Most Active Files', 'payload.file.path', 'File Path', 15),
    'event.category: "file"');

  // ═══════════════════════════════════════════════════════════════════════════
  // DASHBOARDS
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Host Dashboard ────────────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row 0:  nav (48, h=5)
  //   Row 5:  filter (24, h=8) | host-events (12, h=8) | active-agents (12, h=8)
  //   Row 13: avg-memory (12, h=15) | avg-cpu (12, h=15) | swap (12, h=15) | disk (12, h=15)
  //   Row 28: cpu-per-agent (24, h=15) | memory-timeline (24, h=15)
  //   Row 43: cpu-breakdown (24, h=14) | disk-io (24, h=14)
  //   Row 57: network-io (48, h=14)

  const dashHost = dashboard(DASH_HOST, 'XDR Telemetry — Host',
    'Host-level system metrics: CPU, memory, disk and network I/O.', [
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      { x: 0,  y: 5,  w: 24, h: 8,  ref: 'panel_6' },
      { x: 24, y: 5,  w: 12, h: 8,  ref: 'panel_1' },
      { x: 36, y: 5,  w: 12, h: 8,  ref: 'panel_2' },
      { x: 0,  y: 13, w: 12, h: 10, ref: 'panel_3' },
      { x: 12, y: 13, w: 12, h: 10, ref: 'panel_7' },
      { x: 24, y: 13, w: 12, h: 10, ref: 'panel_8' },
      { x: 36, y: 13, w: 12, h: 10, ref: 'panel_9' },
      { x: 0,  y: 28, w: 24, h: 14, ref: 'panel_4' },
      { x: 24, y: 28, w: 24, h: 14, ref: 'panel_5' },
      { x: 0,  y: 43, w: 24, h: 14, ref: 'panel_10' },
      { x: 24, y: 43, w: 24, h: 14, ref: 'panel_11' },
      { x: 0,  y: 57, w: 48, h: 14, ref: 'panel_12' },
    ], [
      { name: 'panel_0',  id: NAV_HOST },
      { name: 'panel_1',  id: VIS_HOST_EVENTS },
      { name: 'panel_2',  id: VIS_ACTIVE_AGENTS },
      { name: 'panel_3',  id: VIS_AVG_MEMORY },
      { name: 'panel_4',  id: VIS_CPU_PER_AGENT },
      { name: 'panel_5',  id: VIS_MEMORY_TIMELINE },
      { name: 'panel_6',  id: VIS_HOSTNAME_FILTER },
      { name: 'panel_7',  id: VIS_AVG_CPU },
      { name: 'panel_8',  id: VIS_SWAP_GAUGE },
      { name: 'panel_9',  id: VIS_DISK_GAUGE },
      { name: 'panel_10', id: VIS_CPU_BREAKDOWN },
      { name: 'panel_11', id: VIS_DISKIO },
      { name: 'panel_12', id: VIS_NETIO },
    ]);

  // ── Process Dashboard ─────────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: proc-events (12,8) | unique-procs (12,8) | proc-starts (12,8) | proc-ends (12,8)
  //   Row 13: cpu-per-process (24,16) | process-timeline (24,16)
  //   Row 29: mem-rss-per-proc (24,16) | io-per-proc (24,16)
  //   Row 45: threads-per-proc (16,14) | user-pie (16,14) | state-pie (16,14)

  const dashProcess = dashboard(DASH_PROCESS, 'XDR Telemetry — Processes',
    'Per-process telemetry: CPU, memory, I/O, threads, users, and state distribution.', [
      // Row 0 — navigation
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0'  },
      // Row 5 — summary metrics
      { x: 0,  y: 5,  w: 12, h: 8,  ref: 'panel_1'  },
      { x: 12, y: 5,  w: 12, h: 8,  ref: 'panel_2'  },
      { x: 24, y: 5,  w: 12, h: 8,  ref: 'panel_3'  },
      { x: 36, y: 5,  w: 12, h: 8,  ref: 'panel_4'  },
      // Row 13 — CPU bar + event timeline
      { x: 0,  y: 13, w: 24, h: 16, ref: 'panel_5'  },
      { x: 24, y: 13, w: 24, h: 16, ref: 'panel_6'  },
      // Row 29 — memory RSS + I/O
      { x: 0,  y: 29, w: 24, h: 16, ref: 'panel_7'  },
      { x: 24, y: 29, w: 24, h: 16, ref: 'panel_8'  },
      // Row 45 — threads + user pie + state pie
      { x: 0,  y: 45, w: 16, h: 14, ref: 'panel_9'  },
      { x: 16, y: 45, w: 16, h: 14, ref: 'panel_10' },
      { x: 32, y: 45, w: 16, h: 14, ref: 'panel_11' },
    ], [
      { name: 'panel_0',  id: NAV_PROCESS          },
      { name: 'panel_1',  id: VIS_PROCESS_EVENTS   },
      { name: 'panel_2',  id: VIS_UNIQUE_PROCESSES },
      { name: 'panel_3',  id: VIS_PROC_STARTS      },
      { name: 'panel_4',  id: VIS_PROC_ENDS        },
      { name: 'panel_5',  id: VIS_CPU_PER_PROCESS  },
      { name: 'panel_6',  id: VIS_PROCESS_TIMELINE },
      { name: 'panel_7',  id: VIS_PROC_MEM_RSS     },
      { name: 'panel_8',  id: VIS_PROC_IO_RW       },
      { name: 'panel_9',  id: VIS_PROC_THREADS     },
      { name: 'panel_10', id: VIS_PROC_USER_PIE    },
      { name: 'panel_11', id: VIS_PROC_STATE_PIE   },
    ]);

  // ── Network Dashboard ─────────────────────────────────────────────────────
  // Layout:
  //   Row 0:  nav (48, 5)
  //   Row 5:  net-events (16, 8) | inbound (16, 8) | outbound (16, 8)
  //   Row 13: protocol pie (16, 14) | state pie (16, 14) | direction pie (16, 14)
  //   Row 27: net-timeline (48, 14)

  const dashNetwork = dashboard(DASH_NETWORK, 'XDR Telemetry — Network',
    'Network connection events: protocol, state, and direction distribution.', [
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      { x: 0,  y: 5,  w: 16, h: 8,  ref: 'panel_1' },
      { x: 16, y: 5,  w: 16, h: 8,  ref: 'panel_2' },
      { x: 32, y: 5,  w: 16, h: 8,  ref: 'panel_3' },
      { x: 0,  y: 13, w: 16, h: 14, ref: 'panel_4' },
      { x: 16, y: 13, w: 16, h: 14, ref: 'panel_5' },
      { x: 32, y: 13, w: 16, h: 14, ref: 'panel_6' },
      { x: 0,  y: 27, w: 48, h: 14, ref: 'panel_7' },
    ], [
      { name: 'panel_0', id: NAV_NETWORK },
      { name: 'panel_1', id: VIS_NETWORK_EVENTS },
      { name: 'panel_2', id: VIS_NET_INBOUND },
      { name: 'panel_3', id: VIS_NET_OUTBOUND },
      { name: 'panel_4', id: VIS_NET_PROTOCOL },
      { name: 'panel_5', id: VIS_NET_STATE },
      { name: 'panel_6', id: VIS_NET_DIRECTION },
      { name: 'panel_7', id: VIS_NET_TIMELINE },
    ]);

  // ── File / FIM Dashboard ──────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: fim-events (12, 8) | created (12, 8) | modified (12, 8) | deleted (12, 8)
  //   Row 13: action-pie (16, 14) | file-types (16, 14) | by-owner (16, 14)
  //   Row 27: fim-timeline (48, 14)
  //   Row 41: top-dirs (24, 16) | top-files (24, 16)

  const dashFile = dashboard(DASH_FILE, 'XDR Telemetry — Files',
    'File Integrity Monitoring: change events, action breakdown, top paths, and owner analysis.', [
      // Row 0 — navigation
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0'  },
      // Row 5 — summary metrics
      { x: 0,  y: 5,  w: 12, h: 8,  ref: 'panel_1'  },
      { x: 12, y: 5,  w: 12, h: 8,  ref: 'panel_2'  },
      { x: 24, y: 5,  w: 12, h: 8,  ref: 'panel_3'  },
      { x: 36, y: 5,  w: 12, h: 8,  ref: 'panel_4'  },
      // Row 13 — pies
      { x: 0,  y: 13, w: 16, h: 14, ref: 'panel_5'  },
      { x: 16, y: 13, w: 16, h: 14, ref: 'panel_6'  },
      { x: 32, y: 13, w: 16, h: 14, ref: 'panel_7'  },
      // Row 27 — timeline
      { x: 0,  y: 27, w: 48, h: 14, ref: 'panel_8'  },
      // Row 41 — top dirs + top files
      { x: 0,  y: 41, w: 24, h: 16, ref: 'panel_9'  },
      { x: 24, y: 41, w: 24, h: 16, ref: 'panel_10' },
    ], [
      { name: 'panel_0',  id: NAV_FILE          },
      { name: 'panel_1',  id: VIS_FIM_EVENTS    },
      { name: 'panel_2',  id: VIS_FIM_CREATED   },
      { name: 'panel_3',  id: VIS_FIM_MODIFIED  },
      { name: 'panel_4',  id: VIS_FIM_DELETED   },
      { name: 'panel_5',  id: VIS_FIM_ACTION_PIE },
      { name: 'panel_6',  id: VIS_FIM_FILE_TYPES },
      { name: 'panel_7',  id: VIS_FIM_BY_OWNER  },
      { name: 'panel_8',  id: VIS_FIM_TIMELINE  },
      { name: 'panel_9',  id: VIS_FIM_TOP_DIRS  },
      { name: 'panel_10', id: VIS_FIM_TOP_FILES },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // DNS visualizations
  // event.module: "telemetry.dns"
  // payload.dns.type: "query" | "answer"
  // payload.dns.question.{name,type,class}, payload.dns.response_code
  // payload.process.name, payload.source.ip, payload.destination.ip
  // ═══════════════════════════════════════════════════════════════════════════

  const visDnsEvents = vis(VIS_DNS_EVENTS,
    '[XDR] DNS Events', 'Total count of DNS query and answer events captured by the DNS collector',
    metricVis('[XDR] DNS Events', null, 'count', 'DNS Events'),
    'event.module: "telemetry.dns"');

  const visDnsQueries = vis(VIS_DNS_QUERIES,
    '[XDR] DNS Queries', 'Count of outgoing DNS query events (QR=0)',
    metricVis('[XDR] DNS Queries', null, 'count', 'Queries'),
    'event.module: "telemetry.dns" and payload.dns.type: "query"');

  const visDnsAnswers = vis(VIS_DNS_ANSWERS,
    '[XDR] DNS Answers', 'Count of received DNS answer events (QR=1)',
    metricVis('[XDR] DNS Answers', null, 'count', 'Answers'),
    'event.module: "telemetry.dns" and payload.dns.type: "answer"');

  const visDnsNxdomain = vis(VIS_DNS_NXDOMAIN,
    '[XDR] NXDOMAIN Responses', 'Count of NXDOMAIN responses — elevated counts may indicate DGA or C2 beacon traffic',
    metricVis('[XDR] NXDOMAIN Responses', null, 'count', 'NXDOMAIN'),
    'event.module: "telemetry.dns" and payload.dns.response_code: "NXDOMAIN"');

  const visDnsQtypePie = vis(VIS_DNS_QTYPE_PIE,
    '[XDR] Query Type Distribution', 'DNS query type breakdown: A, AAAA, CNAME, MX, TXT, SRV, PTR …',
    pieVis('[XDR] Query Type Distribution', 'payload.dns.question.type', 'Query Type', 15),
    'event.module: "telemetry.dns"');

  const visDnsRcodePie = vis(VIS_DNS_RCODE_PIE,
    '[XDR] Response Code Distribution', 'DNS response code breakdown: NOERROR, NXDOMAIN, SERVFAIL, REFUSED …',
    pieVis('[XDR] Response Code Distribution', 'payload.dns.response_code', 'Response Code', 10),
    'event.module: "telemetry.dns" and payload.dns.type: "answer"');

  const visDnsTopProcs = vis(VIS_DNS_TOP_PROCS,
    '[XDR] Top Requesting Processes', 'Which processes are generating the most DNS queries',
    pieVis('[XDR] Top Requesting Processes', 'payload.process.name', 'Process', 15),
    'event.module: "telemetry.dns" and payload.dns.type: "query"');

  const visDnsTimeline = vis(VIS_DNS_TIMELINE,
    '[XDR] DNS Events Over Time', 'DNS query and answer volume over time, stacked by type',
    countAreaGroupVis('[XDR] DNS Events Over Time', 'payload.dns.type', 'Type', 'Events'),
    'event.module: "telemetry.dns"');

  const visDnsTopDomains = vis(VIS_DNS_TOP_DOMAINS,
    '[XDR] Top Queried Domains', 'Top 20 queried domain names — high frequency or unusual names may indicate C2, DGA, or exfiltration',
    topNTermsCountBarVis('[XDR] Top Queried Domains', 'payload.dns.question.name', 'Domain', 20),
    'event.module: "telemetry.dns" and payload.dns.type: "query"');

  const visDnsTopResolvers = vis(VIS_DNS_TOP_RESOLVERS,
    '[XDR] Top DNS Resolvers', 'Top resolver destination IPs receiving queries from this host — unexpected IPs may indicate DNS hijacking',
    topNTermsCountBarVis('[XDR] Top DNS Resolvers', 'payload.destination.ip', 'Resolver IP', 15),
    'event.module: "telemetry.dns" and payload.dns.type: "query"');

  // ── DNS Dashboard ─────────────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: dns-events (12, 8) | dns-queries (12, 8) | dns-answers (12, 8) | nxdomain (12, 8)
  //   Row 13: qtype-pie (16, 14) | rcode-pie (16, 14) | top-procs-pie (16, 14)
  //   Row 27: dns-timeline (48, 14)
  //   Row 41: top-domains (24, 16) | top-resolvers (24, 16)

  const dashDns = dashboard(DASH_DNS, 'XDR Telemetry — DNS',
    'DNS query monitoring: query types, response codes, top queried domains, DNS resolvers, and requesting processes.', [
      // Row 0 — navigation
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0'  },
      // Row 5 — summary metrics
      { x: 0,  y: 5,  w: 12, h: 8,  ref: 'panel_1'  },
      { x: 12, y: 5,  w: 12, h: 8,  ref: 'panel_2'  },
      { x: 24, y: 5,  w: 12, h: 8,  ref: 'panel_3'  },
      { x: 36, y: 5,  w: 12, h: 8,  ref: 'panel_4'  },
      // Row 13 — pies
      { x: 0,  y: 13, w: 16, h: 14, ref: 'panel_5'  },
      { x: 16, y: 13, w: 16, h: 14, ref: 'panel_6'  },
      { x: 32, y: 13, w: 16, h: 14, ref: 'panel_7'  },
      // Row 27 — timeline
      { x: 0,  y: 27, w: 48, h: 14, ref: 'panel_8'  },
      // Row 41 — top-N bars
      { x: 0,  y: 41, w: 24, h: 16, ref: 'panel_9'  },
      { x: 24, y: 41, w: 24, h: 16, ref: 'panel_10' },
    ], [
      { name: 'panel_0',  id: NAV_DNS               },
      { name: 'panel_1',  id: VIS_DNS_EVENTS         },
      { name: 'panel_2',  id: VIS_DNS_QUERIES        },
      { name: 'panel_3',  id: VIS_DNS_ANSWERS        },
      { name: 'panel_4',  id: VIS_DNS_NXDOMAIN       },
      { name: 'panel_5',  id: VIS_DNS_QTYPE_PIE      },
      { name: 'panel_6',  id: VIS_DNS_RCODE_PIE      },
      { name: 'panel_7',  id: VIS_DNS_TOP_PROCS      },
      { name: 'panel_8',  id: VIS_DNS_TIMELINE       },
      { name: 'panel_9',  id: VIS_DNS_TOP_DOMAINS    },
      { name: 'panel_10', id: VIS_DNS_TOP_RESOLVERS  },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // SESSION / AUTHENTICATION visualizations
  // event.category: "authentication"
  // payload.event.{action,outcome}, payload.user.{name,effective.name}
  // payload.source.ip, payload.session.type
  // ═══════════════════════════════════════════════════════════════════════════

  const visSessionEvents = vis(VIS_SESSION_EVENTS,
    '[XDR] Session Events', 'Total count of authentication and session events',
    metricVis('[XDR] Session Events', null, 'count', 'Session Events'),
    'event.category: "authentication"');

  const visSessionLogins = vis(VIS_SESSION_LOGINS,
    '[XDR] Logons', 'Count of successful user logon events detected via utmp (USER_PROCESS records)',
    metricVis('[XDR] Logons', null, 'count', 'Logons'),
    'event.category: "authentication" and payload.event.action: "logged-in"');

  const visSessionLogoffs = vis(VIS_SESSION_LOGOFFS,
    '[XDR] Logoffs', 'Count of user session end events detected via utmp (DEAD_PROCESS records)',
    metricVis('[XDR] Logoffs', null, 'count', 'Logoffs'),
    'event.category: "authentication" and payload.event.action: "logged-out"');

  const visSessionSshFailed = vis(VIS_SESSION_SSH_FAILED,
    '[XDR] SSH Failed Logins', 'Count of failed SSH authentication attempts — elevated counts indicate brute-force activity',
    metricVis('[XDR] SSH Failed Logins', null, 'count', 'SSH Failed'),
    'event.category: "authentication" and payload.event.action: "ssh-failed"');

  const visSessionActionPie = vis(VIS_SESSION_ACTION_PIE,
    '[XDR] Action Distribution', 'Session events broken down by action: logged-in, ssh-accepted, ssh-failed, sudo, su, logged-out',
    pieVis('[XDR] Action Distribution', 'payload.event.action', 'Action', 10),
    'event.category: "authentication"');

  const visSessionUsersPie = vis(VIS_SESSION_USERS_PIE,
    '[XDR] Sessions by User', 'Which users are generating the most authentication events',
    pieVis('[XDR] Sessions by User', 'payload.user.name', 'User', 15),
    'event.category: "authentication"');

  const visSessionSudo = vis(VIS_SESSION_SUDO,
    '[XDR] Sudo Executions', 'Count of sudo command executions captured from the auth log',
    metricVis('[XDR] Sudo Executions', null, 'count', 'Sudo'),
    'event.category: "authentication" and payload.event.action: "sudo"');

  const visSessionTimeline = vis(VIS_SESSION_TIMELINE,
    '[XDR] Session Events Over Time', 'Authentication and session events over time, stacked by action type',
    countAreaGroupVis('[XDR] Session Events Over Time', 'payload.event.action', 'Action', 'Events'),
    'event.category: "authentication"');

  const visSessionSrcIps = vis(VIS_SESSION_SRC_IPS,
    '[XDR] Top SSH Source IPs', 'Top remote IPs connecting via SSH — useful for identifying external access patterns and brute-force sources',
    topNTermsCountBarVis('[XDR] Top SSH Source IPs', 'payload.source.ip', 'Source IP', 20),
    'event.category: "authentication" and (payload.event.action: "ssh-accepted" or payload.event.action: "ssh-failed")');

  const visSessionSudoTargets = vis(VIS_SESSION_SUDO_TARGETS,
    '[XDR] Sudo Target Users', 'Top target users elevated to via sudo — root should dominate; unexpected users warrant investigation',
    topNTermsCountBarVis('[XDR] Sudo Target Users', 'payload.user.effective.name', 'Target User', 15),
    'event.category: "authentication" and payload.event.action: "sudo"');

  // ── Session Dashboard ─────────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: session-events (12, 8) | logins (12, 8) | logoffs (12, 8) | ssh-failed (12, 8)
  //   Row 13: action-pie (16, 14) | users-pie (16, 14) | sudo-count (16, 14)
  //   Row 27: session-timeline (48, 14)
  //   Row 41: top-src-ips (24, 16) | sudo-targets (24, 16)

  const dashSession = dashboard(DASH_SESSION, 'XDR Telemetry — Sessions',
    'User session and authentication monitoring: logons / logoffs, SSH activity, sudo commands, and privilege escalation.', [
      // Row 0 — navigation
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0'  },
      // Row 5 — summary metrics
      { x: 0,  y: 5,  w: 12, h: 8,  ref: 'panel_1'  },
      { x: 12, y: 5,  w: 12, h: 8,  ref: 'panel_2'  },
      { x: 24, y: 5,  w: 12, h: 8,  ref: 'panel_3'  },
      { x: 36, y: 5,  w: 12, h: 8,  ref: 'panel_4'  },
      // Row 13 — pies + sudo metric
      { x: 0,  y: 13, w: 16, h: 14, ref: 'panel_5'  },
      { x: 16, y: 13, w: 16, h: 14, ref: 'panel_6'  },
      { x: 32, y: 13, w: 16, h: 14, ref: 'panel_7'  },
      // Row 27 — timeline
      { x: 0,  y: 27, w: 48, h: 14, ref: 'panel_8'  },
      // Row 41 — top-N bars
      { x: 0,  y: 41, w: 24, h: 16, ref: 'panel_9'  },
      { x: 24, y: 41, w: 24, h: 16, ref: 'panel_10' },
    ], [
      { name: 'panel_0',  id: NAV_SESSION               },
      { name: 'panel_1',  id: VIS_SESSION_EVENTS         },
      { name: 'panel_2',  id: VIS_SESSION_LOGINS         },
      { name: 'panel_3',  id: VIS_SESSION_LOGOFFS        },
      { name: 'panel_4',  id: VIS_SESSION_SSH_FAILED     },
      { name: 'panel_5',  id: VIS_SESSION_ACTION_PIE     },
      { name: 'panel_6',  id: VIS_SESSION_USERS_PIE      },
      { name: 'panel_7',  id: VIS_SESSION_SUDO           },
      { name: 'panel_8',  id: VIS_SESSION_TIMELINE       },
      { name: 'panel_9',  id: VIS_SESSION_SRC_IPS        },
      { name: 'panel_10', id: VIS_SESSION_SUDO_TARGETS   },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // LIBRARY / SO-LOAD visualizations
  // event.category: "library"
  // payload.dll.{name, path, hash.sha256, size}, payload.process.name
  // ═══════════════════════════════════════════════════════════════════════════

  const visLibEvents = vis(VIS_LIB_EVENTS,
    '[XDR] Library Load Events', 'Total count of shared library / SO load events',
    metricVis('[XDR] Library Load Events', null, 'count', 'Load Events'),
    'event.category: "library"');

  const visLibUnique = vis(VIS_LIB_UNIQUE,
    '[XDR] Unique Libraries', 'Distinct shared libraries loaded in the selected time range',
    metricVis('[XDR] Unique Libraries', 'payload.dll.name', 'cardinality', 'Unique Libraries'),
    'event.category: "library"');

  const visLibUniqueProcs = vis(VIS_LIB_UNIQUE_PROCS,
    '[XDR] Unique Loader Processes', 'Distinct processes that loaded at least one shared library',
    metricVis('[XDR] Unique Loader Processes', 'payload.process.name', 'cardinality', 'Unique Processes'),
    'event.category: "library"');

  const visLibNamePie = vis(VIS_LIB_NAME_PIE,
    '[XDR] Top Loaded Libraries', 'Most frequently loaded shared libraries by name — unusual or unsigned libraries warrant investigation',
    pieVis('[XDR] Top Loaded Libraries', 'payload.dll.name', 'Library', 15),
    'event.category: "library"');

  const visLibProcPie = vis(VIS_LIB_PROC_PIE,
    '[XDR] Top Loader Processes', 'Which processes are loading the most shared libraries',
    pieVis('[XDR] Top Loader Processes', 'payload.process.name', 'Process', 15),
    'event.category: "library"');

  const visLibTimeline = vis(VIS_LIB_TIMELINE,
    '[XDR] Library Load Events Over Time', 'Shared library load events over time',
    countAreaVis('[XDR] Library Load Events Over Time', 'Load Events'),
    'event.category: "library"');

  const visLibTopPaths = vis(VIS_LIB_TOP_PATHS,
    '[XDR] Top Library Paths', 'Top 20 library file paths — paths outside /usr/lib or /lib may indicate side-loading or injection',
    topNTermsCountBarVis('[XDR] Top Library Paths', 'payload.dll.path', 'Path', 20),
    'event.category: "library"');

  // ── Library Dashboard ─────────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: lib-events (16, 8) | unique-libs (16, 8) | unique-procs (16, 8)
  //   Row 13: name-pie (24, 16) | proc-pie (24, 16)
  //   Row 29: timeline (48, 14)
  //   Row 43: top-paths (48, 16)

  const dashLibrary = dashboard(DASH_LIBRARY, 'XDR Telemetry — Libraries',
    'Shared library and SO load monitoring: top loaded libraries, loader processes, unusual paths, and load event timeline.', [
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      { x: 0,  y: 5,  w: 16, h: 8,  ref: 'panel_1' },
      { x: 16, y: 5,  w: 16, h: 8,  ref: 'panel_2' },
      { x: 32, y: 5,  w: 16, h: 8,  ref: 'panel_3' },
      { x: 0,  y: 13, w: 24, h: 16, ref: 'panel_4' },
      { x: 24, y: 13, w: 24, h: 16, ref: 'panel_5' },
      { x: 0,  y: 29, w: 48, h: 14, ref: 'panel_6' },
      { x: 0,  y: 43, w: 48, h: 16, ref: 'panel_7' },
    ], [
      { name: 'panel_0', id: NAV_LIBRARY        },
      { name: 'panel_1', id: VIS_LIB_EVENTS     },
      { name: 'panel_2', id: VIS_LIB_UNIQUE      },
      { name: 'panel_3', id: VIS_LIB_UNIQUE_PROCS },
      { name: 'panel_4', id: VIS_LIB_NAME_PIE   },
      { name: 'panel_5', id: VIS_LIB_PROC_PIE   },
      { name: 'panel_6', id: VIS_LIB_TIMELINE   },
      { name: 'panel_7', id: VIS_LIB_TOP_PATHS  },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // KERNEL MODULE visualizations
  // event.category: "driver"
  // payload.driver.name, payload.xdr.kernel_module.{name,state,size,ref_count,deps,address}
  // ═══════════════════════════════════════════════════════════════════════════

  const visKernEvents = vis(VIS_KERN_EVENTS,
    '[XDR] Kernel Module Events', 'Total count of kernel module load / unload events',
    metricVis('[XDR] Kernel Module Events', null, 'count', 'Module Events'),
    'event.category: "driver"');

  const visKernUnique = vis(VIS_KERN_UNIQUE,
    '[XDR] Unique Modules', 'Distinct kernel module names observed in the selected time range',
    metricVis('[XDR] Unique Modules', 'payload.xdr.kernel_module.name', 'cardinality', 'Unique Modules'),
    'event.category: "driver"');

  const visKernStatePie = vis(VIS_KERN_STATE_PIE,
    '[XDR] Module State Distribution', 'Kernel module state breakdown: Live, Loading, Unloading',
    pieVis('[XDR] Module State Distribution', 'payload.xdr.kernel_module.state', 'State', 5),
    'event.category: "driver"');

  const visKernActionPie = vis(VIS_KERN_ACTION_PIE,
    '[XDR] Module Event Actions', 'Distribution of kernel module event actions: insmod vs rmmod',
    pieVis('[XDR] Module Event Actions', 'event.action', 'Action', 5),
    'event.category: "driver"');

  const visKernTopModules = vis(VIS_KERN_TOP_MODULES,
    '[XDR] Top Kernel Modules', 'Most frequently observed kernel modules — unexpected or unsigned modules warrant investigation',
    topNTermsCountBarVis('[XDR] Top Kernel Modules', 'payload.xdr.kernel_module.name', 'Module', 20),
    'event.category: "driver"');

  const visKernTimeline = vis(VIS_KERN_TIMELINE,
    '[XDR] Kernel Module Events Over Time', 'Kernel module load and unload event volume over time, stacked by action',
    countAreaGroupVis('[XDR] Kernel Module Events Over Time', 'event.action', 'Action', 'Events'),
    'event.category: "driver"');

  // ── Kernel Module Dashboard ───────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: kern-events (24, 8) | unique-modules (24, 8)
  //   Row 13: state-pie (24, 16) | action-pie (24, 16)
  //   Row 29: timeline (48, 14)
  //   Row 43: top-modules (48, 16)

  const dashKernel = dashboard(DASH_KERNEL, 'XDR Telemetry — Kernel Modules',
    'Kernel module load / unload monitoring: module states, event actions, top modules, and event timeline.', [
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      { x: 0,  y: 5,  w: 24, h: 8,  ref: 'panel_1' },
      { x: 24, y: 5,  w: 24, h: 8,  ref: 'panel_2' },
      { x: 0,  y: 13, w: 24, h: 16, ref: 'panel_3' },
      { x: 24, y: 13, w: 24, h: 16, ref: 'panel_4' },
      { x: 0,  y: 29, w: 48, h: 14, ref: 'panel_5' },
      { x: 0,  y: 43, w: 48, h: 16, ref: 'panel_6' },
    ], [
      { name: 'panel_0', id: NAV_KERNEL           },
      { name: 'panel_1', id: VIS_KERN_EVENTS       },
      { name: 'panel_2', id: VIS_KERN_UNIQUE        },
      { name: 'panel_3', id: VIS_KERN_STATE_PIE    },
      { name: 'panel_4', id: VIS_KERN_ACTION_PIE   },
      { name: 'panel_5', id: VIS_KERN_TIMELINE     },
      { name: 'panel_6', id: VIS_KERN_TOP_MODULES  },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // TTY SESSION visualizations
  // event.module: "telemetry.tty" (event.category: "process")
  // payload.process.{pid, name, executable, tty.{nr,name}, session_id}
  // ═══════════════════════════════════════════════════════════════════════════

  const visTtyEvents = vis(VIS_TTY_EVENTS,
    '[XDR] TTY Events', 'Total count of TTY session start and end events',
    metricVis('[XDR] TTY Events', null, 'count', 'TTY Events'),
    'event.module: "telemetry.tty"');

  const visTtySessions = vis(VIS_TTY_SESSIONS,
    '[XDR] Unique TTY Sessions', 'Distinct processes observed with a controlling terminal',
    metricVis('[XDR] Unique TTY Sessions', 'payload.process.pid', 'cardinality', 'Unique Sessions'),
    'event.module: "telemetry.tty"');

  const visTtyProcPie = vis(VIS_TTY_PROC_PIE,
    '[XDR] Top TTY Processes', 'Which processes are most commonly associated with terminal sessions',
    pieVis('[XDR] Top TTY Processes', 'payload.process.name', 'Process', 15),
    'event.module: "telemetry.tty"');

  const visTtyNamePie = vis(VIS_TTY_NAME_PIE,
    '[XDR] TTY Name Distribution', 'Distribution of terminal device names (pts/0, pts/1 …)',
    pieVis('[XDR] TTY Name Distribution', 'payload.process.tty.name', 'TTY Name', 15),
    'event.module: "telemetry.tty"');

  const visTtyTopProcs = vis(VIS_TTY_TOP_PROCS,
    '[XDR] Top Processes Starting TTY Sessions', 'Top 20 processes that most frequently start terminal sessions',
    topNTermsCountBarVis('[XDR] Top Processes Starting TTY Sessions', 'payload.process.name', 'Process', 20),
    'event.module: "telemetry.tty" and event.action: "tty.session_start"');

  const visTtyTimeline = vis(VIS_TTY_TIMELINE,
    '[XDR] TTY Events Over Time', 'TTY session start and end events over time, stacked by action',
    countAreaGroupVis('[XDR] TTY Events Over Time', 'event.action', 'Action', 'Events'),
    'event.module: "telemetry.tty"');

  // ── TTY Dashboard ─────────────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: tty-events (24, 8) | unique-sessions (24, 8)
  //   Row 13: proc-pie (24, 16) | name-pie (24, 16)
  //   Row 29: timeline (48, 14)
  //   Row 43: top-procs (48, 16)

  const dashTty = dashboard(DASH_TTY, 'XDR Telemetry — TTY Sessions',
    'Terminal (TTY/PTY) session monitoring: processes with terminals, TTY device distribution, session start/end timeline.', [
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      { x: 0,  y: 5,  w: 24, h: 8,  ref: 'panel_1' },
      { x: 24, y: 5,  w: 24, h: 8,  ref: 'panel_2' },
      { x: 0,  y: 13, w: 24, h: 16, ref: 'panel_3' },
      { x: 24, y: 13, w: 24, h: 16, ref: 'panel_4' },
      { x: 0,  y: 29, w: 48, h: 14, ref: 'panel_5' },
      { x: 0,  y: 43, w: 48, h: 16, ref: 'panel_6' },
    ], [
      { name: 'panel_0', id: NAV_TTY          },
      { name: 'panel_1', id: VIS_TTY_EVENTS   },
      { name: 'panel_2', id: VIS_TTY_SESSIONS },
      { name: 'panel_3', id: VIS_TTY_PROC_PIE },
      { name: 'panel_4', id: VIS_TTY_NAME_PIE },
      { name: 'panel_5', id: VIS_TTY_TIMELINE },
      { name: 'panel_6', id: VIS_TTY_TOP_PROCS },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // SCHEDULED TASK visualizations
  // event.category: "configuration"
  // payload.file.path, payload.xdr.scheduled_task.{path,type,entries}
  // ═══════════════════════════════════════════════════════════════════════════

  const visSchedEvents = vis(VIS_SCHED_EVENTS,
    '[XDR] Scheduled Task Events', 'Total count of scheduled task change events (cron, anacron, at, systemd-timer)',
    metricVis('[XDR] Scheduled Task Events', null, 'count', 'Task Events'),
    'event.category: "configuration"');

  const visSchedUniqueFiles = vis(VIS_SCHED_UNIQUE_FILES,
    '[XDR] Unique Task Files', 'Distinct scheduled task configuration files observed changing',
    metricVis('[XDR] Unique Task Files', 'payload.xdr.scheduled_task.path', 'cardinality', 'Unique Files'),
    'event.category: "configuration"');

  const visSchedTypePie = vis(VIS_SCHED_TYPE_PIE,
    '[XDR] Task Type Distribution', 'Breakdown of scheduled task types: cron, anacron, at, systemd-timer',
    pieVis('[XDR] Task Type Distribution', 'payload.xdr.scheduled_task.type', 'Task Type', 10),
    'event.category: "configuration"');

  const visSchedActionPie = vis(VIS_SCHED_ACTION_PIE,
    '[XDR] Task Event Actions', 'Distribution of task change actions: created, modified, deleted',
    pieVis('[XDR] Task Event Actions', 'event.action', 'Action', 5),
    'event.category: "configuration"');

  const visSchedTopFiles = vis(VIS_SCHED_TOP_FILES,
    '[XDR] Top Modified Task Files', 'Top 20 most frequently changed scheduled task files — high-frequency changes may indicate persistence activity',
    topNTermsCountBarVis('[XDR] Top Modified Task Files', 'payload.xdr.scheduled_task.path', 'File', 20),
    'event.category: "configuration"');

  const visSchedTimeline = vis(VIS_SCHED_TIMELINE,
    '[XDR] Scheduled Task Events Over Time', 'Scheduled task change events over time, stacked by action',
    countAreaGroupVis('[XDR] Scheduled Task Events Over Time', 'event.action', 'Action', 'Events'),
    'event.category: "configuration"');

  // ── Scheduled Task Dashboard ──────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: sched-events (24, 8) | unique-files (24, 8)
  //   Row 13: type-pie (24, 16) | action-pie (24, 16)
  //   Row 29: timeline (48, 14)
  //   Row 43: top-files (48, 16)

  const dashScheduled = dashboard(DASH_SCHEDULED, 'XDR Telemetry — Scheduled Tasks',
    'Scheduled task / cron change monitoring: task types, change actions, most frequently modified files, and event timeline.', [
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      { x: 0,  y: 5,  w: 24, h: 8,  ref: 'panel_1' },
      { x: 24, y: 5,  w: 24, h: 8,  ref: 'panel_2' },
      { x: 0,  y: 13, w: 24, h: 16, ref: 'panel_3' },
      { x: 24, y: 13, w: 24, h: 16, ref: 'panel_4' },
      { x: 0,  y: 29, w: 48, h: 14, ref: 'panel_5' },
      { x: 0,  y: 43, w: 48, h: 16, ref: 'panel_6' },
    ], [
      { name: 'panel_0', id: NAV_SCHEDULED          },
      { name: 'panel_1', id: VIS_SCHED_EVENTS        },
      { name: 'panel_2', id: VIS_SCHED_UNIQUE_FILES  },
      { name: 'panel_3', id: VIS_SCHED_TYPE_PIE      },
      { name: 'panel_4', id: VIS_SCHED_ACTION_PIE    },
      { name: 'panel_5', id: VIS_SCHED_TIMELINE      },
      { name: 'panel_6', id: VIS_SCHED_TOP_FILES     },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // INJECTION / PTRACE ALERT visualizations
  // event.category: "intrusion_detection", event.kind: "alert"
  // payload.xdr.injection.{indicator, detail, target.*, tracer.*}
  // ═══════════════════════════════════════════════════════════════════════════

  const visInjAlerts = vis(VIS_INJ_ALERTS,
    '[XDR] Injection Alerts', 'Total count of process injection / ptrace alerts raised by the agent',
    metricVis('[XDR] Injection Alerts', null, 'count', 'Injection Alerts'),
    'event.category: "intrusion_detection"');

  const visInjUniqueTargets = vis(VIS_INJ_UNIQUE_TARGETS,
    '[XDR] Unique Target Processes', 'Distinct target process names observed as injection targets',
    metricVis('[XDR] Unique Target Processes', 'payload.xdr.injection.target.name', 'cardinality', 'Unique Targets'),
    'event.category: "intrusion_detection"');

  const visInjUniqueIndicators = vis(VIS_INJ_UNIQUE_INDICATORS,
    '[XDR] Unique Injection Indicators', 'Distinct injection indicator types observed (e.g. ptrace-attach, ptrace-traceme)',
    metricVis('[XDR] Unique Injection Indicators', 'payload.xdr.injection.indicator', 'cardinality', 'Unique Indicators'),
    'event.category: "intrusion_detection"');

  const visInjIndicatorPie = vis(VIS_INJ_INDICATOR_PIE,
    '[XDR] Injection Indicator Types', 'Breakdown of injection indicator types — each type maps to a MITRE ATT&CK sub-technique',
    pieVis('[XDR] Injection Indicator Types', 'payload.xdr.injection.indicator', 'Indicator', 10),
    'event.category: "intrusion_detection"');

  const visInjTopTargets = vis(VIS_INJ_TOP_TARGETS,
    '[XDR] Top Injection Target Processes', 'Top 20 target processes most frequently observed as injection targets',
    topNTermsCountBarVis('[XDR] Top Injection Target Processes', 'payload.xdr.injection.target.name', 'Target Process', 20),
    'event.category: "intrusion_detection"');

  const visInjTopTracers = vis(VIS_INJ_TOP_TRACERS,
    '[XDR] Top Tracer Processes', 'Top 20 tracer (injector) processes — unexpected system utilities acting as tracers warrant investigation',
    topNTermsCountBarVis('[XDR] Top Tracer Processes', 'payload.xdr.injection.tracer.name', 'Tracer Process', 20),
    'event.category: "intrusion_detection"');

  const visInjTimeline = vis(VIS_INJ_TIMELINE,
    '[XDR] Injection Alerts Over Time', 'Process injection alert volume over time, stacked by indicator type',
    countAreaGroupVis('[XDR] Injection Alerts Over Time', 'payload.xdr.injection.indicator', 'Indicator', 'Alerts'),
    'event.category: "intrusion_detection"');

  // ── Injection Dashboard ───────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: inj-alerts (16, 8) | unique-targets (16, 8) | unique-indicators (16, 8)
  //   Row 13: indicator-pie (48, 16)
  //   Row 29: timeline (48, 14)
  //   Row 43: top-targets (24, 16) | top-tracers (24, 16)

  const dashInjection = dashboard(DASH_INJECTION, 'XDR Telemetry — Injection Alerts',
    'Process injection and ptrace monitoring: indicator types, target and tracer processes, and alert timeline. MITRE T1055.', [
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      { x: 0,  y: 5,  w: 16, h: 8,  ref: 'panel_1' },
      { x: 16, y: 5,  w: 16, h: 8,  ref: 'panel_2' },
      { x: 32, y: 5,  w: 16, h: 8,  ref: 'panel_3' },
      { x: 0,  y: 13, w: 48, h: 16, ref: 'panel_4' },
      { x: 0,  y: 29, w: 48, h: 14, ref: 'panel_5' },
      { x: 0,  y: 43, w: 24, h: 16, ref: 'panel_6' },
      { x: 24, y: 43, w: 24, h: 16, ref: 'panel_7' },
    ], [
      { name: 'panel_0', id: NAV_INJECTION              },
      { name: 'panel_1', id: VIS_INJ_ALERTS             },
      { name: 'panel_2', id: VIS_INJ_UNIQUE_TARGETS     },
      { name: 'panel_3', id: VIS_INJ_UNIQUE_INDICATORS  },
      { name: 'panel_4', id: VIS_INJ_INDICATOR_PIE      },
      { name: 'panel_5', id: VIS_INJ_TIMELINE           },
      { name: 'panel_6', id: VIS_INJ_TOP_TARGETS        },
      { name: 'panel_7', id: VIS_INJ_TOP_TRACERS        },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE ACCESS visualizations
  // event.module: "telemetry.file.access"  (event.severity: 3 — high)
  // payload.file.{path,name,directory}, threat.technique.id, host.hostname
  // Monitors: /etc/shadow, /etc/gshadow, /root/.ssh, /etc/ssh, …
  // MITRE: T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)
  //        T1552.004 (Unsecured Credentials: Private Keys)
  // ═══════════════════════════════════════════════════════════════════════════

  const visFileAccessEvents = vis(VIS_FA_EVENTS,
    '[XDR] File Access Events',
    'Total count of sensitive file access events raised by the file-access collector',
    metricVis('[XDR] File Access Events', null, 'count', 'Access Events'),
    'event.module: "telemetry.file.access"');

  const visFileAccessUniqueFiles = vis(VIS_FA_UNIQUE_FILES,
    '[XDR] Unique Accessed Files',
    'Distinct sensitive file paths accessed in the selected time range',
    metricVis('[XDR] Unique Accessed Files', 'payload.file.path', 'cardinality', 'Unique Files'),
    'event.module: "telemetry.file.access"');

  const visFileAccessTopFiles = vis(VIS_FA_TOP_FILES,
    '[XDR] Top Accessed Sensitive Files',
    'Top 20 sensitive file paths most frequently accessed — /etc/shadow and SSH key access are high-severity indicators',
    topNTermsCountBarVis('[XDR] Top Accessed Sensitive Files', 'payload.file.path', 'File Path', 20),
    'event.module: "telemetry.file.access"');

  const visFileAccessTopDirs = vis(VIS_FA_TOP_DIRS,
    '[XDR] Top Accessed Sensitive Directories',
    'Top 15 sensitive directories by access event count — /etc/ssh and /root/.ssh dominate in credential-access attacks',
    topNTermsCountBarVis('[XDR] Top Accessed Sensitive Directories', 'payload.file.directory', 'Directory', 15),
    'event.module: "telemetry.file.access"');

  const visFileAccessTechniquePie = vis(VIS_FA_TECHNIQUE_PIE,
    '[XDR] MITRE Technique Distribution',
    'File access events broken down by MITRE ATT&CK technique: T1003.008 (shadow) vs T1552.004 (SSH keys)',
    pieVis('[XDR] MITRE Technique Distribution', 'threat.technique.id', 'Technique', 10),
    'event.module: "telemetry.file.access"');

  const visFileAccessAgentsPie = vis(VIS_FA_AGENTS_PIE,
    '[XDR] File Access by Host',
    'Which endpoints are generating sensitive file access events — high counts on a single host may indicate active attack',
    pieVis('[XDR] File Access by Host', 'host.hostname', 'Host', 15),
    'event.module: "telemetry.file.access"');

  const visFileAccessTimeline = vis(VIS_FA_TIMELINE,
    '[XDR] File Access Events Over Time',
    'Sensitive file access events over time, stacked by accessed file name',
    countAreaGroupVis('[XDR] File Access Events Over Time', 'payload.file.name', 'File Name', 'Events'),
    'event.module: "telemetry.file.access"');

  // ── File Access Dashboard ─────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: fa-events (16, 8) | unique-files (16, 8) | agents-pie (16, 8)
  //   Row 13: technique-pie (24, 16) | top-dirs (24, 16)
  //   Row 29: timeline (48, 14)
  //   Row 43: top-files (48, 16)

  const dashFileAccess = dashboard(DASH_FILEACCESS, 'XDR Telemetry — File Access',
    'Credential and SSH file access monitoring: sensitive file reads, MITRE technique breakdown, top accessed paths. MITRE T1003.008, T1552.004.', [
      // Row 0 — navigation
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      // Row 5 — summary metrics
      { x: 0,  y: 5,  w: 16, h: 8,  ref: 'panel_1' },
      { x: 16, y: 5,  w: 16, h: 8,  ref: 'panel_2' },
      { x: 32, y: 5,  w: 16, h: 8,  ref: 'panel_3' },
      // Row 13 — technique + top-dirs
      { x: 0,  y: 13, w: 24, h: 16, ref: 'panel_4' },
      { x: 24, y: 13, w: 24, h: 16, ref: 'panel_5' },
      // Row 29 — timeline
      { x: 0,  y: 29, w: 48, h: 14, ref: 'panel_6' },
      // Row 43 — top files
      { x: 0,  y: 43, w: 48, h: 16, ref: 'panel_7' },
    ], [
      { name: 'panel_0', id: NAV_FILEACCESS              },
      { name: 'panel_1', id: VIS_FA_EVENTS               },
      { name: 'panel_2', id: VIS_FA_UNIQUE_FILES         },
      { name: 'panel_3', id: VIS_FA_AGENTS_PIE           },
      { name: 'panel_4', id: VIS_FA_TECHNIQUE_PIE        },
      { name: 'panel_5', id: VIS_FA_TOP_DIRS             },
      { name: 'panel_6', id: VIS_FA_TIMELINE             },
      { name: 'panel_7', id: VIS_FA_TOP_FILES            },
    ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // IPC visualizations
  // event.module: "telemetry.ipc"
  //   Unix socket: event.type="ipc.unix_socket.created", event.category="network"
  //     payload.network.unix_socket.path, network.type/transport="unix"
  //   Named pipe:  event.type="ipc.pipe.created",        event.category="file"
  //     payload.file.path, payload.file.name, payload.file.directory
  // MITRE: T1559 (Inter-Process Communication)
  // ═══════════════════════════════════════════════════════════════════════════

  const visIpcEvents = vis(VIS_IPC_EVENTS,
    '[XDR] IPC Events',
    'Total count of IPC events: Unix domain socket creations and named pipe (FIFO) creations',
    metricVis('[XDR] IPC Events', null, 'count', 'IPC Events'),
    'event.module: "telemetry.ipc"');

  const visIpcSockets = vis(VIS_IPC_SOCKETS,
    '[XDR] Unix Socket Events',
    'Count of Unix domain socket creation events — unexpected abstract or path-based sockets may indicate covert C2 channels',
    metricVis('[XDR] Unix Socket Events', null, 'count', 'Unix Sockets'),
    'event.module: "telemetry.ipc" and event.type: "ipc.unix_socket.created"');

  const visIpcPipes = vis(VIS_IPC_PIPES,
    '[XDR] Named Pipe Events',
    'Count of named pipe (FIFO) creation events — pipes in unusual directories or with suspicious names warrant investigation',
    metricVis('[XDR] Named Pipe Events', null, 'count', 'Named Pipes'),
    'event.module: "telemetry.ipc" and event.type: "ipc.pipe.created"');

  const visIpcTypePie = vis(VIS_IPC_TYPE_PIE,
    '[XDR] IPC Event Type Distribution',
    'Breakdown of IPC event types: Unix socket vs named pipe creation',
    pieVis('[XDR] IPC Event Type Distribution', 'event.type', 'IPC Type', 5),
    'event.module: "telemetry.ipc"');

  const visIpcTopSockets = vis(VIS_IPC_TOP_SOCKETS,
    '[XDR] Top Unix Socket Paths',
    'Top 20 Unix domain socket paths — abstract sockets (prefix @) or paths outside /run / /tmp may indicate malicious IPC',
    topNTermsCountBarVis('[XDR] Top Unix Socket Paths', 'payload.network.unix_socket.path', 'Socket Path', 20),
    'event.module: "telemetry.ipc" and event.type: "ipc.unix_socket.created"');

  const visIpcTopPipes = vis(VIS_IPC_TOP_PIPES,
    '[XDR] Top Named Pipe Paths',
    'Top 20 named pipe (FIFO) file paths — pipes in /tmp, /dev/shm, or writable dirs may be used for covert data staging',
    topNTermsCountBarVis('[XDR] Top Named Pipe Paths', 'payload.file.path', 'Pipe Path', 20),
    'event.module: "telemetry.ipc" and event.type: "ipc.pipe.created"');

  const visIpcTimeline = vis(VIS_IPC_TIMELINE,
    '[XDR] IPC Events Over Time',
    'IPC event volume over time, stacked by event type (unix_socket vs pipe)',
    countAreaGroupVis('[XDR] IPC Events Over Time', 'event.type', 'IPC Type', 'Events'),
    'event.module: "telemetry.ipc"');

  // ── IPC Dashboard ──────────────────────────────────────────────────────────
  // Layout (48 cols):
  //   Row  0: nav (48, 5)
  //   Row  5: ipc-events (16, 8) | unix-sockets (16, 8) | named-pipes (16, 8)
  //   Row 13: type-pie (48, 16)
  //   Row 29: timeline (48, 14)
  //   Row 43: top-sockets (24, 16) | top-pipes (24, 16)

  const dashIpc = dashboard(DASH_IPC, 'XDR Telemetry — IPC',
    'Inter-Process Communication monitoring: Unix domain socket and named pipe creation events, top IPC paths and timeline. MITRE T1559.', [
      // Row 0 — navigation
      { x: 0,  y: 0,  w: 48, h: 5,  ref: 'panel_0' },
      // Row 5 — summary metrics
      { x: 0,  y: 5,  w: 16, h: 8,  ref: 'panel_1' },
      { x: 16, y: 5,  w: 16, h: 8,  ref: 'panel_2' },
      { x: 32, y: 5,  w: 16, h: 8,  ref: 'panel_3' },
      // Row 13 — type pie (full width)
      { x: 0,  y: 13, w: 48, h: 16, ref: 'panel_4' },
      // Row 29 — timeline
      { x: 0,  y: 29, w: 48, h: 14, ref: 'panel_5' },
      // Row 43 — top sockets + top pipes
      { x: 0,  y: 43, w: 24, h: 16, ref: 'panel_6' },
      { x: 24, y: 43, w: 24, h: 16, ref: 'panel_7' },
    ], [
      { name: 'panel_0', id: NAV_IPC              },
      { name: 'panel_1', id: VIS_IPC_EVENTS       },
      { name: 'panel_2', id: VIS_IPC_SOCKETS      },
      { name: 'panel_3', id: VIS_IPC_PIPES        },
      { name: 'panel_4', id: VIS_IPC_TYPE_PIE     },
      { name: 'panel_5', id: VIS_IPC_TIMELINE     },
      { name: 'panel_6', id: VIS_IPC_TOP_SOCKETS  },
      { name: 'panel_7', id: VIS_IPC_TOP_PIPES    },
    ]);

  return {
    indexPatterns: [indexPattern],
    dashboardObjects: [
      // Navigation markdown
      navHost, navProcess, navNetwork, navFile, navDns, navSession,
      navLibrary, navKernel, navTty, navScheduled, navInjection,
      navFileaccess, navIpc,
      // Host
      visHostEvents, visActiveAgents, visAvgMemory, visAvgCpu, visSwapGauge, visDiskGauge,
      visHostnameFilter, visCpuPerAgent, visMemTimeline, visCpuBreakdown, visDiskIO, visNetIO,
      // Process
      visProcessEvents, visUniqueProcs, visCpuPerProcess, visProcTimeline,
      visProcStarts, visProcEnds, visProcMemRss, visProcIoRw,
      visProcThreads, visProcStatePie, visProcUserPie,
      // Network
      visNetEvents, visNetInbound, visNetOutbound, visNetProtocol, visNetState, visNetDirection, visNetTimeline,
      // File / FIM
      visFimEvents, visFimCreated, visFimModified, visFimDeleted,
      visFimActionPie, visFimFileTypes, visFimByOwner,
      visFimTimeline, visFimTopDirs, visFimTopFiles,
      // File Access
      visFileAccessEvents, visFileAccessUniqueFiles, visFileAccessTopFiles,
      visFileAccessTopDirs, visFileAccessTechniquePie, visFileAccessAgentsPie,
      visFileAccessTimeline,
      // DNS
      visDnsEvents, visDnsQueries, visDnsAnswers, visDnsNxdomain,
      visDnsQtypePie, visDnsRcodePie, visDnsTopProcs,
      visDnsTimeline, visDnsTopDomains, visDnsTopResolvers,
      // Session / Authentication
      visSessionEvents, visSessionLogins, visSessionLogoffs, visSessionSshFailed,
      visSessionActionPie, visSessionUsersPie, visSessionSudo,
      visSessionTimeline, visSessionSrcIps, visSessionSudoTargets,
      // Library / SO-load
      visLibEvents, visLibUnique, visLibUniqueProcs, visLibNamePie, visLibProcPie,
      visLibTimeline, visLibTopPaths,
      // Kernel modules
      visKernEvents, visKernUnique, visKernStatePie, visKernActionPie,
      visKernTopModules, visKernTimeline,
      // TTY sessions
      visTtyEvents, visTtySessions, visTtyProcPie, visTtyNamePie,
      visTtyTopProcs, visTtyTimeline,
      // Scheduled tasks
      visSchedEvents, visSchedUniqueFiles, visSchedTypePie, visSchedActionPie,
      visSchedTopFiles, visSchedTimeline,
      // Injection alerts
      visInjAlerts, visInjUniqueTargets, visInjUniqueIndicators, visInjIndicatorPie,
      visInjTopTargets, visInjTopTracers, visInjTimeline,
      // IPC
      visIpcEvents, visIpcSockets, visIpcPipes, visIpcTypePie,
      visIpcTopSockets, visIpcTopPipes, visIpcTimeline,
      // Dashboards
      dashHost, dashProcess, dashNetwork, dashFile, dashDns, dashSession,
      dashLibrary, dashKernel, dashTty, dashScheduled, dashInjection,
      dashFileAccess, dashIpc,
    ],
  };
}

// ── Public API ──────────────────────────────────────────────────────────────

export async function installTelemetryDashboard(
  repo: ISavedObjectsRepository,
  logger: Logger
): Promise<void> {
  const { indexPatterns, dashboardObjects } = buildSavedObjects();

  try {
    // 1. Index pattern — overwrite:false to avoid racing with OSD field-refresh
    const ipResult = await repo.bulkCreate(indexPatterns as any[], { overwrite: false });
    const ipErrors = ipResult.saved_objects.filter(
      (o: any) => o.error && o.error.statusCode !== 409
    );
    if (ipErrors.length > 0) {
      logger.warn(
        `xdr_manager: index-pattern install error: ` +
          ipErrors.map((e: any) => `${e.type}/${e.id}: ${e.error.message}`).join('; ')
      );
    }

    // 2. Visualizations + dashboards — overwrite:true to always push latest definitions
    const dbResult = await repo.bulkCreate(dashboardObjects as any[], { overwrite: true });
    const dbErrors = dbResult.saved_objects.filter((o: any) => o.error);
    const created = dbResult.saved_objects.filter((o: any) => !o.error).length;

    if (dbErrors.length > 0) {
      logger.warn(
        `xdr_manager: dashboard install had ${dbErrors.length} error(s): ` +
          dbErrors.map((e: any) => `${e.type}/${e.id}: ${e.error?.message}`).join('; ')
      );
    }

    logger.info(
      `xdr_manager: installed telemetry dashboards (Host, Process, Network, Files, File Access, DNS, Sessions, Libraries, Kernel, TTY, Scheduled, Injection, IPC) — ${created} objects written`
    );
  } catch (err) {
    logger.error(`xdr_manager: failed to install telemetry dashboards: ${err}`);
  }
}
