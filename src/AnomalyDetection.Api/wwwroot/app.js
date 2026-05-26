const state = {
  lookbackHours: 0,
  bucketMinutes: 1,
  staticThreshold: null,
  timeline: [],
  detectionsPage: null,
  networkStats: null,
  detectionTopSources: [],
  originView: "sources",
  showAllAlerts: false,
  alertTotal: 0
};

const els = {
  lookback: document.querySelector("#lookback"),
  bucket: document.querySelector("#bucket"),
  refresh: document.querySelector("#refresh"),
  storageStatus: document.querySelector("#storageStatus"),
  modelVersion: document.querySelector("#modelVersion"),
  lastUpdated: document.querySelector("#lastUpdated"),
  totalDetections: document.querySelector("#totalDetections"),
  anomalyCount: document.querySelector("#anomalyCount"),
  anomalyRate: document.querySelector("#anomalyRate"),
  maxError: document.querySelector("#maxError"),
  currentThreshold: document.querySelector("#currentThreshold"),
  staticThreshold: document.querySelector("#staticThreshold"),
  sourceCount: document.querySelector("#sourceCount"),
  timelineRange: document.querySelector("#timelineRange"),
  timelineChart: document.querySelector("#timelineChart"),
  scoreRange: document.querySelector("#scoreRange"),
  scoreChart: document.querySelector("#scoreChart"),
  avgThroughput: document.querySelector("#avgThroughput"),
  peakThroughput: document.querySelector("#peakThroughput"),
  flowRate: document.querySelector("#flowRate"),
  packetRate: document.querySelector("#packetRate"),
  networkSourceCount: document.querySelector("#networkSourceCount"),
  destinationCount: document.querySelector("#destinationCount"),
  trafficOriginTitle: document.querySelector("#trafficOriginTitle"),
  originSources: document.querySelector("#originSources"),
  originDestinations: document.querySelector("#originDestinations"),
  originProtocols: document.querySelector("#originProtocols"),
  topSources: document.querySelector("#topSources"),
  alertCount: document.querySelector("#alertCount"),
  alertViewToggle: document.querySelector("#alertViewToggle"),
  alertsList: document.querySelector("#alertsList"),
  loadCpu: document.querySelector("#loadCpu"),
  loadMemory: document.querySelector("#loadMemory"),
  loadThreads: document.querySelector("#loadThreads"),
  loadUptime: document.querySelector("#loadUptime"),
  detectionCount: document.querySelector("#detectionCount"),
  detectionsBody: document.querySelector("#detectionsBody")
};

const numberFormat = new Intl.NumberFormat(undefined);
const compactFormat = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const percentFormat = new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 });
const decimalFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 4 });
const loadFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

els.lookback.addEventListener("change", () => {
  state.lookbackHours = Number(els.lookback.value);
  loadDashboard();
});

els.bucket.addEventListener("change", () => {
  state.bucketMinutes = Number(els.bucket.value);
  loadDashboard();
});

els.refresh.addEventListener("click", () => loadDashboard());

els.alertViewToggle.addEventListener("click", () => {
  state.showAllAlerts = !state.showAllAlerts;
  loadDashboard();
});

for (const button of [els.originSources, els.originDestinations, els.originProtocols]) {
  button.addEventListener("click", () => {
    state.originView = button.dataset.originView;
    renderTrafficOrigin();
  });
}

loadDashboard();
setInterval(loadDashboard, 30000);

async function loadDashboard() {
  setBusy(true);
  const overviewQuery = new URLSearchParams({
    lookbackHours: String(state.lookbackHours),
    bucketMinutes: String(state.bucketMinutes)
  });
  const detectionQuery = new URLSearchParams({
    limit: "100",
    offset: "0",
    anomaliesOnly: "false",
    lookbackHours: String(state.lookbackHours)
  });
  const alertQuery = new URLSearchParams({
    limit: String(state.showAllAlerts ? Math.max(state.alertTotal, 5000) : 8),
    offset: "0",
    lookbackHours: String(state.lookbackHours),
    unacknowledgedOnly: "false"
  });
  const networkQuery = new URLSearchParams({
    lookbackHours: String(state.lookbackHours),
    bucketMinutes: String(state.bucketMinutes)
  });

  const [overviewResult, detectionResult, alertResult, networkResult, runtimeResult, loadResult] = await Promise.allSettled([
    fetchJson(`/api/overview?${overviewQuery}`),
    fetchJson(`/api/detections?${detectionQuery}`),
    fetchJson(`/api/alerts?${alertQuery}`),
    fetchJson(`/api/network/stats?${networkQuery}`),
    fetchJson("/api/model/status"),
    fetchJson("/api/system/load")
  ]);

  if (overviewResult.status === "fulfilled") {
    renderOverview(overviewResult.value);
  } else {
    renderOverviewError(overviewResult.reason);
  }

  if (detectionResult.status === "fulfilled") {
    renderDetections(detectionResult.value);
  } else {
    renderDetectionsError(detectionResult.reason);
  }

  if (alertResult.status === "fulfilled") {
    renderAlerts(alertResult.value);
  } else {
    renderAlertsError(alertResult.reason);
  }

  if (networkResult.status === "fulfilled") {
    renderNetworkStats(networkResult.value);
  } else {
    renderNetworkStatsError(networkResult.reason);
  }

  if (runtimeResult.status === "fulfilled") {
    renderRuntime(runtimeResult.value);
  } else {
    renderRuntimeError(runtimeResult.reason);
  }

  if (loadResult.status === "fulfilled") {
    renderSystemLoad(loadResult.value);
  } else {
    renderSystemLoadError();
  }

  els.lastUpdated.textContent = `Updated ${formatDateTime(new Date().toISOString())}`;
  setBusy(false);
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const problem = await response.json();
      message = problem.detail || problem.title || message;
    } catch {
      // The HTTP status is enough when the response is not JSON.
    }
    throw new Error(message);
  }

  return response.json();
}

function renderOverview(data) {
  const summary = data.summary;
  els.totalDetections.textContent = numberFormat.format(summary.totalDetections);
  els.anomalyCount.textContent = numberFormat.format(summary.anomalies);
  els.anomalyRate.textContent = percentFormat.format(summary.anomalyRate || 0);
  els.maxError.textContent = decimal(summary.maxError);
  els.currentThreshold.textContent = decimal(summary.latestThreshold);
  els.sourceCount.textContent = numberFormat.format(summary.distinctSources);
  els.timelineRange.textContent = summary.latestTimestamp
    ? `${formatDate(summary.earliestTimestamp)} - ${formatDate(summary.latestTimestamp)}`
    : "No detections";

  state.timeline = data.timeline || [];
  state.detectionTopSources = data.topSources || [];
  renderVolumeTimeline(state.timeline);
  renderScoreTimeline(state.timeline);
  renderTrafficOrigin();
}

function renderOverviewError(error) {
  els.totalDetections.textContent = "-";
  els.anomalyCount.textContent = "-";
  els.anomalyRate.textContent = "-";
  els.maxError.textContent = "-";
  els.currentThreshold.textContent = "-";
  els.sourceCount.textContent = "-";
  state.timeline = [];
  state.detectionTopSources = [];
  els.timelineRange.textContent = "Unavailable";
  els.timelineChart.className = "chart empty";
  els.timelineChart.textContent = error.message;
  els.scoreRange.textContent = "Unavailable";
  els.scoreChart.className = "chart empty";
  els.scoreChart.textContent = error.message;
  els.topSources.className = "rank-list empty";
  els.topSources.textContent = "No source data";
}

function renderVolumeTimeline(timeline) {
  if (!timeline || timeline.length === 0) {
    els.timelineChart.className = "chart empty";
    els.timelineChart.textContent = "No timeline data";
    return;
  }

  const width = 720;
  const height = 250;
  const pad = { top: 18, right: 18, bottom: 34, left: 46 };
  const innerWidth = width - pad.left - pad.right;
  const innerHeight = height - pad.top - pad.bottom;
  const maxTotal = Math.max(...timeline.map(item => item.total), 1);
  const band = innerWidth / timeline.length;
  const barWidth = Math.max(3, Math.min(18, band * 0.58));

  const bars = timeline.map((item, index) => {
    const x = pad.left + index * band + (band - barWidth) / 2;
    const normal = Math.max(0, (item.total || 0) - (item.anomalies || 0));
    const normalHeight = (normal / maxTotal) * innerHeight;
    const anomalyHeight = (item.anomalies / maxTotal) * innerHeight;
    const yNormal = pad.top + innerHeight - normalHeight;
    const yAnomaly = yNormal - anomalyHeight;
    return `
      <rect x="${x}" y="${yNormal}" width="${barWidth}" height="${normalHeight}" rx="3" fill="#b8d8d0"></rect>
      <rect x="${x}" y="${yAnomaly}" width="${barWidth}" height="${anomalyHeight}" rx="3" fill="#ba3b24"></rect>
    `;
  }).join("");

  const first = timeline[0];
  const last = timeline[timeline.length - 1];
  els.timelineChart.className = "chart";
  els.timelineChart.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Detection volume timeline">
      <line x1="${pad.left}" y1="${pad.top + innerHeight}" x2="${width - pad.right}" y2="${pad.top + innerHeight}" stroke="#cfd8d2"></line>
      <line x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${pad.top + innerHeight}" stroke="#cfd8d2"></line>
      ${bars}
      <g transform="translate(${pad.left + 4}, ${pad.top + 8})">
        <rect x="0" y="-7" width="16" height="10" rx="3" fill="#b8d8d0"></rect>
        <text x="22" y="4" fill="#697474" font-size="12">normal</text>
        <rect x="82" y="-7" width="16" height="10" rx="3" fill="#ba3b24"></rect>
        <text x="104" y="4" fill="#697474" font-size="12">anomaly</text>
      </g>
      <text x="${pad.left}" y="${height - 10}" fill="#697474" font-size="12">${escapeSvg(formatTime(first.timestamp))}</text>
      <text x="${width - pad.right}" y="${height - 10}" fill="#697474" font-size="12" text-anchor="end">${escapeSvg(formatTime(last.timestamp))}</text>
      <text x="${pad.left + 4}" y="${pad.top + 30}" fill="#697474" font-size="12">${compactFormat.format(maxTotal)} windows</text>
    </svg>
  `;
}

function renderScoreTimeline(timeline) {
  if (!timeline || timeline.length === 0) {
    els.scoreChart.className = "chart empty";
    els.scoreChart.textContent = "No score data";
    return;
  }

  const width = 720;
  const height = 250;
  const pad = { top: 18, right: 18, bottom: 34, left: 46 };
  const innerWidth = width - pad.left - pad.right;
  const innerHeight = height - pad.top - pad.bottom;
  const staticThreshold = positiveNumber(state.staticThreshold);
  const maxScore = Math.max(
    ...timeline.map(item => Math.max(item.averageError || 0, item.averageThreshold || 0)),
    staticThreshold ?? 0,
    1);
  const band = innerWidth / timeline.length;

  const errorPoints = timeline.map((item, index) => {
    const x = pad.left + index * band + band / 2;
    const y = pad.top + innerHeight - ((item.averageError || 0) / maxScore) * innerHeight;
    return `${x},${y}`;
  }).join(" ");

  const thresholdPoints = timeline.map((item, index) => {
    const x = pad.left + index * band + band / 2;
    const y = pad.top + innerHeight - ((item.averageThreshold || 0) / maxScore) * innerHeight;
    return `${x},${y}`;
  }).join(" ");
  const staticThresholdLine = staticThreshold === null
    ? ""
    : `<line x1="${pad.left}" y1="${scoreY(staticThreshold, maxScore, pad, innerHeight)}" x2="${width - pad.right}" y2="${scoreY(staticThreshold, maxScore, pad, innerHeight)}" stroke="#b7791f" stroke-width="2" stroke-dasharray="3 6" stroke-linecap="round"></line>`;

  const first = timeline[0];
  const last = timeline[timeline.length - 1];
  els.scoreRange.textContent = `${formatDate(first.timestamp)} - ${formatDate(last.timestamp)}`;
  els.scoreChart.className = "chart";
  els.scoreChart.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Reconstruction score timeline">
      <line x1="${pad.left}" y1="${pad.top + innerHeight}" x2="${width - pad.right}" y2="${pad.top + innerHeight}" stroke="#cfd8d2"></line>
      <line x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${pad.top + innerHeight}" stroke="#cfd8d2"></line>
      ${staticThresholdLine}
      <polyline points="${errorPoints}" fill="none" stroke="#2e6f9e" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></polyline>
      <polyline points="${thresholdPoints}" fill="none" stroke="#0f766e" stroke-width="3" stroke-dasharray="8 5" stroke-linecap="round" stroke-linejoin="round"></polyline>
      <g transform="translate(${pad.left + 4}, ${pad.top + 8})">
        <line x1="0" y1="0" x2="18" y2="0" stroke="#2e6f9e" stroke-width="3" stroke-linecap="round"></line>
        <text x="24" y="4" fill="#697474" font-size="12">avg error</text>
        <line x1="92" y1="0" x2="110" y2="0" stroke="#0f766e" stroke-width="3" stroke-dasharray="8 5" stroke-linecap="round"></line>
        <text x="116" y="4" fill="#697474" font-size="12">adaptive</text>
        <line x1="190" y1="0" x2="208" y2="0" stroke="#b7791f" stroke-width="2" stroke-dasharray="3 6" stroke-linecap="round"></line>
        <text x="214" y="4" fill="#697474" font-size="12">static</text>
      </g>
      <text x="${pad.left}" y="${height - 10}" fill="#697474" font-size="12">${escapeSvg(formatTime(first.timestamp))}</text>
      <text x="${width - pad.right}" y="${height - 10}" fill="#697474" font-size="12" text-anchor="end">${escapeSvg(formatTime(last.timestamp))}</text>
      <text x="${pad.left + 4}" y="${pad.top + 30}" fill="#697474" font-size="12">max ${decimal(maxScore)}</text>
    </svg>
  `;
}

function renderRankList(container, items) {
  if (!items || items.length === 0) {
    container.className = "rank-list empty";
    container.textContent = "No data";
    return;
  }

  container.className = "rank-list";
  container.innerHTML = items.map(item => {
    if ("bytes" in item) {
      return `
        <div class="rank-item">
          <div class="rank-row">
            <strong class="rank-name" title="${escapeAttr(item.name)}">${escapeHtml(item.name)}</strong>
            <span>${formatBytes(item.bytes)}</span>
            <div class="rank-meta">${numberFormat.format(item.flows || 0)} flows &middot; ${formatPackets(item.packets)} &middot; ${percentFormat.format(item.byteShare || 0)}</div>
          </div>
        </div>
      `;
    }

    return `
      <div class="rank-item">
        <div class="rank-row">
          <strong class="rank-name" title="${escapeAttr(item.name)}">${escapeHtml(item.name)}</strong>
          <span>${compactFormat.format(item.total)} total</span>
          <div class="rank-meta">${numberFormat.format(item.anomalies)} anomalies &middot; ${percentFormat.format(item.anomalyRate || 0)}</div>
        </div>
      </div>
    `;
  }).join("");
}

function renderNetworkStats(data) {
  state.networkStats = data;
  const summary = data.summary || {};
  const timeline = data.timeline || [];
  const peakThroughput = timeline.length > 0
    ? Math.max(...timeline.map(item => item.bytesPerSecond || 0))
    : null;

  els.avgThroughput.textContent = bandwidth(summary.bytesPerSecond);
  els.peakThroughput.textContent = bandwidth(peakThroughput);
  els.flowRate.textContent = flowRate(summary.flowsPerSecond);
  els.packetRate.textContent = packetRate(summary.packetsPerSecond);
  els.networkSourceCount.textContent = numberFormat.format(summary.distinctSources || 0);
  els.destinationCount.textContent = numberFormat.format(summary.distinctDestinations || 0);
  renderTrafficOrigin();
}

function renderNetworkStatsError(error) {
  state.networkStats = null;
  els.avgThroughput.textContent = "-";
  els.peakThroughput.textContent = "-";
  els.flowRate.textContent = "-";
  els.packetRate.textContent = "-";
  els.networkSourceCount.textContent = "-";
  els.destinationCount.textContent = "-";
  renderTrafficOrigin();
}

function renderTrafficOrigin() {
  const buttons = [els.originSources, els.originDestinations, els.originProtocols];
  for (const button of buttons) {
    button.classList.toggle("is-active", button.dataset.originView === state.originView);
  }

  if (state.originView === "destinations") {
    els.trafficOriginTitle.textContent = "Destinations";
    renderRankList(els.topSources, state.networkStats?.topDestinations || []);
    return;
  }

  if (state.originView === "protocols") {
    els.trafficOriginTitle.textContent = "Protocols";
    renderRankList(els.topSources, state.networkStats?.protocols || []);
    return;
  }

  els.trafficOriginTitle.textContent = "Sources";
  renderRankList(els.topSources, state.networkStats?.topSources || state.detectionTopSources);
}

function renderDetections(page) {
  state.detectionsPage = page;
  els.detectionCount.textContent = `${numberFormat.format(page.total)} matching`;
  if (!page.items || page.items.length === 0) {
    els.detectionsBody.innerHTML = `<tr><td colspan="8">No detections match the current filters</td></tr>`;
    return;
  }

  els.detectionsBody.innerHTML = page.items.map(item => {
    const ratio = item.scoreRatio ?? 0;
    const meterWidth = Math.max(2, Math.min(100, ratio * 50));
    const adaptiveDelta = delta(item.reconstructionError, item.threshold);
    const staticDelta = delta(item.reconstructionError, state.staticThreshold);
    const thresholdLabel = shortThresholdMethod(item.thresholdMethod);
    return `
      <tr>
        <td>${formatDateTime(item.timestamp)}</td>
        <td>${escapeHtml(item.sourceIp)}</td>
        <td>${escapeHtml(item.destinationIp)}:${item.destinationPort}</td>
        <td>${escapeHtml(item.protocol)}</td>
        <td class="error-cell">
          ${decimal(item.reconstructionError)}
          <div class="error-meter"><span style="width:${meterWidth}%"></span></div>
        </td>
        <td class="threshold-cell">
          ${decimal(item.threshold)}
          <div class="threshold-method" title="${escapeAttr(item.thresholdMethod)}">${escapeHtml(thresholdLabel)}</div>
        </td>
        <td class="delta-cell">
          <div><span>Adaptive</span><strong>${signedDecimal(adaptiveDelta)}</strong></div>
          <div><span>Static</span><strong>${signedDecimal(staticDelta)}</strong></div>
        </td>
        <td><span class="severity severity-${item.severity}">${item.severity}</span></td>
      </tr>
    `;
  }).join("");
}

function renderDetectionsError(error) {
  state.detectionsPage = null;
  els.detectionCount.textContent = "Unavailable";
  els.detectionsBody.innerHTML = `<tr><td colspan="8">${escapeHtml(error.message)}</td></tr>`;
}

function renderAlerts(page) {
  const summary = page.summary || { total: 0, unacknowledged: 0 };
  state.alertTotal = summary.total || 0;
  const shown = page.items?.length || 0;
  els.alertCount.textContent = state.showAllAlerts
    ? `${numberFormat.format(shown)} / ${numberFormat.format(state.alertTotal)} shown`
    : `${numberFormat.format(summary.unacknowledged)} open`;
  els.alertViewToggle.textContent = state.showAllAlerts
    ? "Show recent"
    : `Show all (${numberFormat.format(state.alertTotal)})`;
  els.alertViewToggle.disabled = state.alertTotal === 0;

  if (!page.items || page.items.length === 0) {
    els.alertsList.className = "alert-list empty";
    els.alertsList.textContent = "No alerts";
    return;
  }

  els.alertsList.className = "alert-list";
  els.alertsList.innerHTML = page.items.map(item => {
    const target = item.destinationIp === "*"
      ? "all destinations"
      : `${escapeHtml(item.destinationIp)}:${item.destinationPort}`;
    const source = item.sourceIp === "*" ? "all sources" : escapeHtml(item.sourceIp);
    return `
      <article class="alert-item">
        <div class="alert-head">
          <span class="severity severity-${item.severity}">${escapeHtml(item.severity)}</span>
          <span class="alert-meta">${formatDateTime(item.timestamp)}</span>
        </div>
        <div class="alert-message">${escapeHtml(alertMessage(item))}</div>
        <div class="alert-meta">${source} -&gt; ${target} - ${escapeHtml(item.protocol)}</div>
      </article>
    `;
  }).join("");
}

function renderAlertsError(error) {
  els.alertCount.textContent = "Unavailable";
  els.alertViewToggle.textContent = state.showAllAlerts ? "Show recent" : "Show all";
  els.alertViewToggle.disabled = true;
  els.alertsList.className = "alert-list empty";
  els.alertsList.textContent = error.message;
}

function renderRuntime(data) {
  const storageReachable = data.storage?.reachable === true;
  setStatus(els.storageStatus, storageReachable ? "Online" : "Offline", storageReachable ? "ok" : "bad");
  els.modelVersion.textContent = data.modelVersion ? `Model ${data.modelVersion}` : "Model version unavailable";
  state.staticThreshold = positiveNumber(data.threshold?.threshold);
  els.staticThreshold.textContent = decimal(state.staticThreshold);
  if (state.timeline.length > 0) {
    renderScoreTimeline(state.timeline);
  }
  if (state.detectionsPage) {
    renderDetections(state.detectionsPage);
  }
}

function renderRuntimeError(error) {
  setStatus(els.storageStatus, "Offline", "bad");
  els.modelVersion.textContent = error.message;
  state.staticThreshold = null;
  els.staticThreshold.textContent = "-";
  if (state.detectionsPage) {
    renderDetections(state.detectionsPage);
  }
}

function renderSystemLoad(data) {
  els.loadCpu.textContent = data.cpuPercent == null ? "-" : `${loadFormat.format(data.cpuPercent)}%`;
  els.loadMemory.textContent = `${loadFormat.format(data.workingSetMb || 0)} MB`;
  els.loadThreads.textContent = numberFormat.format(data.threadCount || 0);
  els.loadUptime.textContent = formatDuration(data.uptimeSeconds);
}

function renderSystemLoadError() {
  els.loadCpu.textContent = "-";
  els.loadMemory.textContent = "-";
  els.loadThreads.textContent = "-";
  els.loadUptime.textContent = "-";
}

function setStatus(element, text, tone) {
  element.textContent = text;
  element.className = `status-pill status-${tone}`;
}

function setBusy(isBusy) {
  els.refresh.disabled = isBusy;
  els.refresh.textContent = isBusy ? "Refreshing" : "Refresh";
}

function decimal(value) {
  return value == null || Number.isNaN(Number(value)) ? "-" : decimalFormat.format(value);
}

function signedDecimal(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "-";
  }

  return `${number >= 0 ? "+" : ""}${decimalFormat.format(number)}`;
}

function delta(score, threshold) {
  const scoreNumber = Number(score);
  const thresholdNumber = Number(threshold);
  return Number.isFinite(scoreNumber) && Number.isFinite(thresholdNumber)
    ? scoreNumber - thresholdNumber
    : null;
}

function positiveNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function bandwidth(value) {
  return value == null || Number.isNaN(Number(value)) ? "-" : `${formatBytes(value)}/s`;
}

function flowRate(value) {
  return value == null || Number.isNaN(Number(value)) ? "-" : `${loadFormat.format(value)}/s`;
}

function packetRate(value) {
  return value == null || Number.isNaN(Number(value)) ? "-" : `${loadFormat.format(value)} pkt/s`;
}

function formatPackets(value) {
  return `${compactFormat.format(value || 0)} pkts`;
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const scaled = bytes / Math.pow(1024, index);
  return `${loadFormat.format(scaled)} ${units[index]}`;
}

function scoreY(value, maxScore, pad, innerHeight) {
  return pad.top + innerHeight - (value / maxScore) * innerHeight;
}

function shortThresholdMethod(method) {
  const value = String(method || "").trim();
  if (!value) {
    return "-";
  }

  if (value.includes("rolling_quantile_mad")) {
    return "rq_mad";
  }

  return value
    .replace("target_recall+", "")
    .replace("rolling_quantile_mad", "rq_mad");
}

function alertMessage(item) {
  const message = String(item.message || "Anomalous traffic window")
    .replace(/\s*exceeded threshold by\s+[\d.,]+x\s*$/i, "")
    .trim();

  if (/^\d+\s+anomalous windows from .+ within \d+\s+minutes$/i.test(message)) {
    return "Source anomaly activity";
  }

  if (/^Anomaly rate .+ across \d+\s+windows within \d+\s+minutes$/i.test(message)) {
    return "Elevated anomaly rate";
  }

  return message === "Anomalous traffic window" || !message ? "Anomalous traffic" : message;
}

function formatDuration(seconds) {
  if (seconds == null || Number.isNaN(Number(seconds))) {
    return "-";
  }

  const totalSeconds = Math.max(0, Number(seconds));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }

  return `${minutes}m`;
}

function formatDateTime(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function formatDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleDateString();
}

function formatTime(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value);
}

function escapeSvg(value) {
  return escapeHtml(value);
}
