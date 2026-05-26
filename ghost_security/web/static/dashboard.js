/**
 * Ghost Security Platform — Dashboard JavaScript
 * Phase 8: Modular classes for charts, tables, WebSocket, graph, heatmap.
 * Pure vanilla JS — no CDN dependencies.
 */

'use strict';

/* ══════════════════════════════════════════════════════════════════
 * ScanEventBus — WebSocket client with SSE fallback
 * ══════════════════════════════════════════════════════════════════ */
class ScanEventBus {
  /**
   * @param {string} wsUrl  - WebSocket URL, e.g. ws://localhost:8000/ws/scan
   * @param {string} sseUrl - SSE fallback URL, e.g. /api/dashboard/live
   */
  constructor(wsUrl, sseUrl) {
    this._wsUrl   = wsUrl;
    this._sseUrl  = sseUrl;
    this._ws      = null;
    this._sse     = null;
    this._handlers = {};       // eventType → [fn, ...]
    this._status  = 'idle';    // idle | connecting | connected | sse | error | closed
    this._reconnectTimer = null;
    this._reconnectDelay = 2000;
    this._maxReconnectDelay = 30000;
    this._useSSE  = false;
  }

  /** Register an event handler. type='*' catches all. */
  on(type, fn) {
    if (!this._handlers[type]) this._handlers[type] = [];
    this._handlers[type].push(fn);
    return this;
  }

  /** Unregister an event handler. */
  off(type, fn) {
    if (this._handlers[type]) {
      this._handlers[type] = this._handlers[type].filter(h => h !== fn);
    }
    return this;
  }

  /** Dispatch internally. */
  _emit(type, data) {
    const handlers = [...(this._handlers[type] || []), ...(this._handlers['*'] || [])];
    handlers.forEach(fn => { try { fn(data, type); } catch (e) { console.error('[ScanEventBus] handler error', e); } });
  }

  /** Connect — tries WebSocket first, falls back to SSE. */
  connect() {
    this._clearReconnect();
    this._status = 'connecting';
    this._emit('status', { status: 'connecting' });
    try {
      this._ws = new WebSocket(this._wsUrl);
      this._ws.addEventListener('open', () => {
        this._status = 'connected';
        this._reconnectDelay = 2000;
        this._useSSE = false;
        this._emit('status', { status: 'connected', transport: 'websocket' });
      });
      this._ws.addEventListener('message', ev => {
        try {
          const msg = JSON.parse(ev.data);
          this._emit(msg.event || 'finding', msg.data || msg);
          this._emit('message', msg);
        } catch (_) {}
      });
      this._ws.addEventListener('error', () => {
        if (this._status === 'connecting') {
          // WebSocket failed — try SSE
          this._ws = null;
          this._connectSSE();
        }
      });
      this._ws.addEventListener('close', ev => {
        if (this._status === 'closed') return;
        this._ws = null;
        this._emit('status', { status: 'disconnected', code: ev.code });
        this._scheduleReconnect();
      });
    } catch (_) {
      this._connectSSE();
    }
  }

  _connectSSE() {
    if (!this._sseUrl) {
      this._status = 'error';
      this._emit('status', { status: 'error', reason: 'no_sse_url' });
      return;
    }
    this._useSSE = true;
    this._status = 'sse';
    this._emit('status', { status: 'sse', transport: 'sse' });
    try {
      this._sse = new EventSource(this._sseUrl);
      this._sse.addEventListener('message', ev => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.event === 'ping') return;
          this._emit(msg.event || 'finding', msg.data || msg);
          this._emit('message', msg);
        } catch (_) {}
      });
      this._sse.addEventListener('error', () => {
        this._sse.close();
        this._sse = null;
        this._status = 'error';
        this._emit('status', { status: 'error', reason: 'sse_error' });
        this._scheduleReconnect();
      });
    } catch (e) {
      this._status = 'error';
      this._emit('status', { status: 'error', reason: String(e) });
      this._scheduleReconnect();
    }
  }

  disconnect() {
    this._clearReconnect();
    this._status = 'closed';
    if (this._ws) { try { this._ws.close(); } catch (_) {} this._ws = null; }
    if (this._sse) { try { this._sse.close(); } catch (_) {} this._sse = null; }
    this._emit('status', { status: 'closed' });
  }

  _scheduleReconnect() {
    this._clearReconnect();
    this._reconnectTimer = setTimeout(() => {
      this._reconnectDelay = Math.min(this._reconnectDelay * 1.5, this._maxReconnectDelay);
      this.connect();
    }, this._reconnectDelay);
  }

  _clearReconnect() {
    if (this._reconnectTimer) { clearTimeout(this._reconnectTimer); this._reconnectTimer = null; }
  }

  get status() { return this._status; }
}


/* ══════════════════════════════════════════════════════════════════
 * FindingsTable — sortable / filterable findings explorer
 * ══════════════════════════════════════════════════════════════════ */
class FindingsTable {
  /**
   * @param {HTMLTableElement} tableEl
   * @param {HTMLElement}      tbodyEl
   * @param {object} opts
   */
  constructor(tableEl, tbodyEl, opts) {
    this._table   = tableEl;
    this._tbody   = tbodyEl;
    this._opts    = Object.assign({ onRowClick: null, escFn: null }, opts);
    this._esc     = this._opts.escFn || (s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
    this._all     = [];    // master copy
    this._filtered = [];   // after filter
    this._sortCol  = 'severity';
    this._sortDir  = 'asc';

    this._SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  }

  /** Load a fresh set of findings and render. */
  load(findings) {
    this._all = Array.isArray(findings) ? [...findings] : [];
    this.applyFilter();
  }

  /** Append new findings (live feed integration). */
  append(findings) {
    if (!Array.isArray(findings)) findings = [findings];
    this._all = [...this._all, ...findings];
    this.applyFilter();
  }

  /**
   * Apply severity / search / file filter.
   * @param {{severity?: string, search?: string, file?: string, rule?: string}} filters
   */
  applyFilter(filters) {
    this._filters = Object.assign(this._filters || {}, filters || {});
    const { severity = '', search = '', file = '' } = this._filters;
    const q = search.toLowerCase().trim();

    this._filtered = this._all.filter(f => {
      if (severity && f.severity !== severity) return false;
      if (file && !(f.file || '').includes(file)) return false;
      if (q && !(
        (f.message || '').toLowerCase().includes(q) ||
        (f.file || '').toLowerCase().includes(q) ||
        (f.rule_id || '').toLowerCase().includes(q) ||
        (f.cwe || '').toLowerCase().includes(q) ||
        (f.id || '').toLowerCase().includes(q)
      )) return false;
      return true;
    });

    this._sort();
    this._render();
  }

  /** Sort by column. Toggles direction if same column. */
  sortBy(col) {
    if (this._sortCol === col) {
      this._sortDir = this._sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      this._sortCol = col;
      this._sortDir = 'asc';
    }
    this._updateSortHeaders();
    this._sort();
    this._render();
  }

  get count() { return this._filtered.length; }
  get all()   { return this._all; }

  _sort() {
    const col = this._sortCol;
    const dir = this._sortDir;
    this._filtered = [...this._filtered].sort((a, b) => {
      let va = col === 'severity' ? (this._SEV_ORDER[a.severity] ?? 9) : (a[col] || '');
      let vb = col === 'severity' ? (this._SEV_ORDER[b.severity] ?? 9) : (b[col] || '');
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return dir === 'asc' ? -1 : 1;
      if (va > vb) return dir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  _render() {
    if (!this._filtered.length) {
      this._tbody.innerHTML = `<tr><td colspan="7">
        <div class="empty-state">
          <div class="empty-state-icon">&#128027;</div>
          <div class="empty-state-title">No findings match filters</div>
          <div class="empty-state-sub">Adjust filters or run a scan</div>
        </div></td></tr>`;
      return;
    }

    const esc = this._esc;
    this._tbody.innerHTML = this._filtered.map((f, i) => {
      const idx = this._all.indexOf(f);
      const cweNum = (f.cwe || '').replace(/[^0-9]/g, '');
      const cweLink = cweNum
        ? `<a href="https://cwe.mitre.org/data/definitions/${cweNum}.html" target="_blank" rel="noopener" style="color:var(--accent,#58a6ff)">${esc(f.cwe)}</a>`
        : '—';
      const shortFile = this._shortPath(f.file || '');
      const sev = f.severity || 'INFO';
      const dot = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢', INFO: '⚪' }[sev] || '';
      const badge = `<span class="sev-badge sev-${esc(sev)}">${dot} ${esc(sev)}</span>`;

      return `<tr data-idx="${idx}" onclick="dashFindingsTable && dashFindingsTable._onRowClick(${idx})">
        <td class="col-sev">${badge}</td>
        <td class="col-id" title="${esc(f.rule_id || f.id || '')}">${esc((f.rule_id || f.id || '').slice(0, 20))}</td>
        <td class="col-msg" title="${esc(f.message || '')}">${esc(f.message || '')}</td>
        <td class="col-file" title="${esc(f.file || '')}">${esc(shortFile)}</td>
        <td class="col-cwe">${cweLink}</td>
        <td class="col-line">${f.line || '—'}</td>
        <td class="col-act"><button class="btn btn-sm" onclick="event.stopPropagation();dashFindingsTable&&dashFindingsTable._onRowClick(${idx})" title="Details">&rarr;</button></td>
      </tr>`;
    }).join('');
  }

  _onRowClick(idx) {
    if (this._opts.onRowClick) this._opts.onRowClick(this._all[idx], idx);
  }

  _updateSortHeaders() {
    if (!this._table) return;
    this._table.querySelectorAll('thead th').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
    });
    const colMap = { severity: 0, rule_id: 1, message: 2, file: 3, cwe: 4, line: 5 };
    const idx = colMap[this._sortCol];
    const ths = this._table.querySelectorAll('thead th');
    if (idx !== undefined && ths[idx]) {
      ths[idx].classList.add(this._sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
    }
  }

  _shortPath(path) {
    const parts = path.split('/');
    if (parts.length <= 2) return path;
    return parts.slice(-2).join('/');
  }
}


/* ══════════════════════════════════════════════════════════════════
 * SeverityChart — canvas bar chart for severity distribution
 * ══════════════════════════════════════════════════════════════════ */
class SeverityChart {
  /**
   * @param {HTMLCanvasElement} canvas
   * @param {object} data - {CRITICAL:n, HIGH:n, MEDIUM:n, LOW:n, INFO:n}
   * @param {object} opts
   */
  constructor(canvas, data, opts) {
    this._canvas = canvas;
    this._opts = Object.assign({
      padding:     { top: 24, right: 16, bottom: 40, left: 48 },
      barGap:      0.35,
      animate:     true,
      animMs:      600,
      colors: {
        CRITICAL: '#ff7b72',
        HIGH:     '#ffa657',
        MEDIUM:   '#e3b341',
        LOW:      '#3fb950',
        INFO:     '#6e7681',
      },
      labelColor:  '#8b949e',
      gridColor:   'rgba(48,54,61,0.7)',
      valueColor:  '#e6edf3',
    }, opts || {});

    this._data  = data || {};
    this._frame = null;
    this._progress = 0; // 0..1 for animation
  }

  /** Render / re-render with optional new data. */
  render(data) {
    if (data) this._data = data;
    this._progress = this._opts.animate ? 0 : 1;
    this._startAnimation();
  }

  _startAnimation() {
    if (this._frame) cancelAnimationFrame(this._frame);
    const startTs = performance.now();
    const ms = this._opts.animMs;

    const tick = (ts) => {
      this._progress = Math.min((ts - startTs) / ms, 1);
      const eased = this._easeOut(this._progress);
      this._draw(eased);
      if (this._progress < 1) this._frame = requestAnimationFrame(tick);
    };

    this._frame = requestAnimationFrame(tick);
  }

  _easeOut(t) { return 1 - Math.pow(1 - t, 3); }

  _draw(progress) {
    const canvas = this._canvas;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width  = rect.width  * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const W = rect.width;
    const H = rect.height;
    const P = this._opts.padding;
    const chartW = W - P.left - P.right;
    const chartH = H - P.top  - P.bottom;

    const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const values = labels.map(l => this._data[l] || 0);
    const maxVal = Math.max(...values, 1);
    const n = labels.length;
    const barW = (chartW / n) * (1 - this._opts.barGap);
    const gap  = (chartW / n) * this._opts.barGap;

    ctx.clearRect(0, 0, W, H);

    // Grid lines
    const gridLines = 4;
    ctx.strokeStyle = this._opts.gridColor;
    ctx.lineWidth = 1;
    for (let i = 0; i <= gridLines; i++) {
      const y = P.top + chartH - (chartH / gridLines) * i;
      ctx.beginPath();
      ctx.moveTo(P.left, y);
      ctx.lineTo(P.left + chartW, y);
      ctx.stroke();

      // Y axis label
      const val = Math.round((maxVal / gridLines) * i);
      ctx.fillStyle = this._opts.labelColor;
      ctx.font = `11px -apple-system,sans-serif`;
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(val, P.left - 6, y);
    }

    // Bars
    labels.forEach((label, i) => {
      const barH = (values[i] / maxVal) * chartH * progress;
      const x = P.left + (chartW / n) * i + gap / 2;
      const y = P.top + chartH - barH;

      // Bar fill with gradient
      const grad = ctx.createLinearGradient(x, y, x, y + barH);
      const color = this._opts.colors[label] || '#8b949e';
      grad.addColorStop(0, color);
      grad.addColorStop(1, color + '88');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(x, y, barW, barH, [4, 4, 0, 0])
                    : this._roundRectPoly(ctx, x, y, barW, barH, 4);
      ctx.fill();

      // Value label on top
      if (values[i] > 0 && progress > 0.5) {
        ctx.fillStyle = this._opts.valueColor;
        ctx.font = `bold 11px -apple-system,sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(values[i], x + barW / 2, y - 3);
      }

      // X axis label
      ctx.fillStyle = this._opts.labelColor;
      ctx.font = `11px -apple-system,sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(label.charAt(0) + label.slice(1, 4).toLowerCase(), x + barW / 2, P.top + chartH + 6);
    });
  }

  _roundRectPoly(ctx, x, y, w, h, r) {
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h);
    ctx.lineTo(x, y + h);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  destroy() {
    if (this._frame) cancelAnimationFrame(this._frame);
  }
}


/* ══════════════════════════════════════════════════════════════════
 * HeatmapView — canvas-based file × severity heatmap
 * ══════════════════════════════════════════════════════════════════ */
class HeatmapView {
  /**
   * @param {HTMLCanvasElement} canvas
   * @param {Array} findings   - array of finding objects with .file, .severity
   * @param {object} opts
   */
  constructor(canvas, findings, opts) {
    this._canvas = canvas;
    this._opts = Object.assign({
      cellSize:   28,
      cellGap:    3,
      labelWidth: 180,
      headerH:    30,
      colors: {
        CRITICAL: [255, 123, 114],
        HIGH:     [255, 166,  87],
        MEDIUM:   [227, 179,  65],
        LOW:      [ 63, 185,  80],
        INFO:     [110, 118, 129],
      },
      bgColor:    '#161b22',
      emptyColor: 'rgba(48,54,61,0.4)',
      labelColor: '#8b949e',
      headerColor:'#8b949e',
    }, opts || {});

    this._findings = findings || [];
    this._severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    this._tooltip = null;
  }

  /** Re-render with new findings. */
  render(findings) {
    if (findings) this._findings = findings;
    this._build();
    this._draw();
    this._attachHover();
  }

  _build() {
    // Aggregate: file → severity → count
    const map = {};
    this._findings.forEach(f => {
      const file = f.file || 'unknown';
      if (!map[file]) map[file] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      if (map[file][f.severity] !== undefined) map[file][f.severity]++;
    });

    // Sort by risk score descending
    this._files = Object.entries(map)
      .map(([path, counts]) => ({
        path,
        name: path.split('/').slice(-1)[0] || path,
        counts,
        score: counts.CRITICAL * 10 + counts.HIGH * 5 + counts.MEDIUM * 2 + counts.LOW,
      }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 25);  // max 25 rows

    this._maxCount = Math.max(1, ...this._files.flatMap(f =>
      this._severities.map(s => f.counts[s])
    ));
  }

  _draw() {
    const opts = this._opts;
    const rows = this._files.length;
    const cols = this._severities.length;
    const W = opts.labelWidth + cols * (opts.cellSize + opts.cellGap) + opts.cellGap;
    const H = opts.headerH   + rows * (opts.cellSize + opts.cellGap) + opts.cellGap;

    const dpr = window.devicePixelRatio || 1;
    this._canvas.width  = W * dpr;
    this._canvas.height = H * dpr;
    this._canvas.style.width  = W + 'px';
    this._canvas.style.height = H + 'px';

    const ctx = this._canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);

    // Background
    ctx.fillStyle = opts.bgColor;
    ctx.fillRect(0, 0, W, H);

    // Column headers
    this._severities.forEach((sev, ci) => {
      const x = opts.labelWidth + ci * (opts.cellSize + opts.cellGap) + opts.cellGap;
      const [r, g, b] = opts.colors[sev];
      ctx.fillStyle = `rgb(${r},${g},${b})`;
      ctx.font = 'bold 10px -apple-system,sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(sev.slice(0, 4), x + opts.cellSize / 2, opts.headerH / 2);
    });

    // Rows
    this._files.forEach((file, ri) => {
      const y = opts.headerH + ri * (opts.cellSize + opts.cellGap) + opts.cellGap;

      // File label
      ctx.fillStyle = opts.labelColor;
      ctx.font = '11px -apple-system,sans-serif';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      const label = file.name.length > 22 ? '…' + file.name.slice(-20) : file.name;
      ctx.fillText(label, opts.labelWidth - 6, y + opts.cellSize / 2);

      // Cells
      this._severities.forEach((sev, ci) => {
        const x = opts.labelWidth + ci * (opts.cellSize + opts.cellGap) + opts.cellGap;
        const count = file.counts[sev];
        const [r, g, b] = opts.colors[sev];

        if (count === 0) {
          ctx.fillStyle = opts.emptyColor;
        } else {
          const intensity = Math.min(0.15 + (count / this._maxCount) * 0.85, 1);
          ctx.fillStyle = `rgba(${r},${g},${b},${intensity})`;
        }

        ctx.beginPath();
        if (ctx.roundRect) {
          ctx.roundRect(x, y, opts.cellSize, opts.cellSize, 3);
        } else {
          ctx.rect(x, y, opts.cellSize, opts.cellSize);
        }
        ctx.fill();

        // Count label in cell
        if (count > 0) {
          ctx.fillStyle = count > 2 ? '#ffffff' : `rgb(${r},${g},${b})`;
          ctx.font = `bold ${count > 9 ? 9 : 11}px -apple-system,sans-serif`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(count, x + opts.cellSize / 2, y + opts.cellSize / 2);
        }
      });
    });
  }

  _attachHover() {
    // Remove old listener if any
    if (this._hoverHandler) this._canvas.removeEventListener('mousemove', this._hoverHandler);

    this._hoverHandler = (ev) => {
      const rect = this._canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      const opts = this._opts;

      // Find which cell
      const colIdx = Math.floor((mx - opts.labelWidth - opts.cellGap) / (opts.cellSize + opts.cellGap));
      const rowIdx = Math.floor((my - opts.headerH - opts.cellGap) / (opts.cellSize + opts.cellGap));

      if (colIdx >= 0 && colIdx < this._severities.length && rowIdx >= 0 && rowIdx < this._files.length) {
        const file = this._files[rowIdx];
        const sev  = this._severities[colIdx];
        const count = file.counts[sev];
        this._canvas.title = `${file.path}\n${sev}: ${count}`;
      } else {
        this._canvas.title = '';
      }
    };
    this._canvas.addEventListener('mousemove', this._hoverHandler);
  }

  get files() { return this._files; }
}


/* ══════════════════════════════════════════════════════════════════
 * ContractGraph — canvas node-link graph for TON contract relationships
 * ══════════════════════════════════════════════════════════════════ */
class ContractGraph {
  /**
   * @param {HTMLCanvasElement} canvas
   * @param {Array} nodes  - [{id, type, label, risk?}]
   * @param {Array} edges  - [{source, target, label?}]
   * @param {object} opts
   */
  constructor(canvas, nodes, edges, opts) {
    this._canvas = canvas;
    this._nodes  = nodes || [];
    this._edges  = edges || [];
    this._opts   = Object.assign({
      nodeRadius:  26,
      arrowSize:   10,
      font:        '12px -apple-system,sans-serif',
      labelFont:   '10px -apple-system,sans-serif',
      bg:          '#0d1117',
      edgeColor:   'rgba(88,166,255,0.4)',
      textColor:   '#e6edf3',
      mutedColor:  '#8b949e',
      nodeColors: {
        wallet:    '#58a6ff',
        contract:  '#a371f7',
        token:     '#3fb950',
        jetton:    '#ffa657',
        nft:       '#e3b341',
        default:   '#6e7681',
      },
      riskColors: {
        CRITICAL: '#ff7b72',
        HIGH:     '#ffa657',
        MEDIUM:   '#e3b341',
        LOW:      '#3fb950',
        NONE:     null,
      },
      animate:     true,
    }, opts || {});

    this._positions = {};
    this._frame = null;
    this._dragging = null;
    this._dragOffset = { x: 0, y: 0 };
    this._pan = { x: 0, y: 0 };
    this._scale = 1;
    this._simTick = 0;
  }

  /** Render graph. Runs a simple force-directed layout. */
  render(nodes, edges) {
    if (nodes) this._nodes = nodes;
    if (edges) this._edges = edges;
    this._initLayout();
    this._attachInteraction();
    this._startLoop();
  }

  _initLayout() {
    const canvas = this._canvas;
    const W = canvas.clientWidth || 600;
    const H = canvas.clientHeight || 400;

    // Initialize positions in a circle
    const cx = W / 2, cy = H / 2;
    const r = Math.min(W, H) * 0.32;
    const n = this._nodes.length;

    this._nodes.forEach((node, i) => {
      if (!this._positions[node.id]) {
        const angle = (2 * Math.PI * i) / n - Math.PI / 2;
        this._positions[node.id] = {
          x: cx + r * Math.cos(angle),
          y: cy + r * Math.sin(angle),
          vx: 0, vy: 0,
        };
      }
    });
    this._simTick = 0;
  }

  _forceLayout() {
    if (this._simTick > 300) return; // stop after convergence
    this._simTick++;

    const k = 0.015;  // spring constant
    const repulsion = 2200;
    const damping = 0.85;

    const pos = this._positions;

    // Repulsion between all node pairs
    const nodeIds = this._nodes.map(n => n.id);
    for (let i = 0; i < nodeIds.length; i++) {
      for (let j = i + 1; j < nodeIds.length; j++) {
        const a = pos[nodeIds[i]], b = pos[nodeIds[j]];
        if (!a || !b) continue;
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = repulsion / (dist * dist);
        const fx = (dx / dist) * force, fy = (dy / dist) * force;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      }
    }

    // Spring attraction along edges
    this._edges.forEach(edge => {
      const a = pos[edge.source], b = pos[edge.target];
      if (!a || !b) return;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const idealLen = 140;
      const force = (dist - idealLen) * k;
      const fx = (dx / dist) * force, fy = (dy / dist) * force;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    });

    // Center gravity
    const canvas = this._canvas;
    const cx = (canvas.width / (window.devicePixelRatio || 1)) / 2;
    const cy = (canvas.height / (window.devicePixelRatio || 1)) / 2;
    nodeIds.forEach(id => {
      const p = pos[id];
      if (!p) return;
      p.vx += (cx - p.x) * 0.002;
      p.vy += (cy - p.y) * 0.002;
    });

    // Integrate
    nodeIds.forEach(id => {
      const p = pos[id];
      if (!p || this._dragging === id) return;
      p.vx *= damping; p.vy *= damping;
      p.x += p.vx; p.y += p.vy;
    });
  }

  _startLoop() {
    if (this._frame) cancelAnimationFrame(this._frame);
    const tick = () => {
      this._forceLayout();
      this._drawFrame();
      this._frame = requestAnimationFrame(tick);
    };
    this._frame = requestAnimationFrame(tick);
  }

  _drawFrame() {
    const canvas = this._canvas;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();

    if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
      canvas.width  = rect.width  * dpr;
      canvas.height = rect.height * dpr;
    }

    const ctx = canvas.getContext('2d');
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, rect.width, rect.height);

    // Background
    ctx.fillStyle = this._opts.bg;
    ctx.fillRect(0, 0, rect.width, rect.height);

    ctx.translate(this._pan.x, this._pan.y);
    ctx.scale(this._scale, this._scale);

    const pos = this._positions;

    // Draw edges
    this._edges.forEach(edge => {
      const a = pos[edge.source], b = pos[edge.target];
      if (!a || !b) return;
      ctx.save();
      ctx.strokeStyle = this._opts.edgeColor;
      ctx.lineWidth = 1.5;
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      // Bezier curve
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const curvature = 25;
      const dx = b.x - a.x, dy = b.y - a.y;
      const len = Math.sqrt(dx * dx + dy * dy) || 1;
      const cx2 = mx - (dy / len) * curvature;
      const cy2 = my + (dx / len) * curvature;
      ctx.quadraticCurveTo(cx2, cy2, b.x, b.y);
      ctx.stroke();

      // Arrow
      const angle = Math.atan2(b.y - cy2, b.x - cx2);
      const ar = this._opts.arrowSize;
      const nr = this._opts.nodeRadius;
      const tx = b.x - Math.cos(angle) * nr, ty = b.y - Math.sin(angle) * nr;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(tx - ar * Math.cos(angle - 0.4), ty - ar * Math.sin(angle - 0.4));
      ctx.lineTo(tx - ar * Math.cos(angle + 0.4), ty - ar * Math.sin(angle + 0.4));
      ctx.closePath();
      ctx.fillStyle = this._opts.edgeColor;
      ctx.fill();

      // Edge label
      if (edge.label) {
        ctx.fillStyle = this._opts.mutedColor;
        ctx.font = this._opts.labelFont;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(edge.label, cx2, cy2 - 8);
      }
      ctx.restore();
    });

    // Draw nodes
    this._nodes.forEach(node => {
      const p = pos[node.id];
      if (!p) return;
      const nr = this._opts.nodeRadius;
      const nodeType = (node.type || 'default').toLowerCase();
      const nodeColor = this._opts.nodeColors[nodeType] || this._opts.nodeColors.default;
      const riskColor = this._opts.riskColors[node.risk || 'NONE'];

      ctx.save();

      // Risk ring
      if (riskColor) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, nr + 5, 0, Math.PI * 2);
        ctx.strokeStyle = riskColor;
        ctx.lineWidth = 2.5;
        ctx.setLineDash([4, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // Node circle with gradient
      const grad = ctx.createRadialGradient(p.x - nr * 0.3, p.y - nr * 0.3, 0, p.x, p.y, nr);
      grad.addColorStop(0, nodeColor + 'dd');
      grad.addColorStop(1, nodeColor + '66');
      ctx.beginPath();
      ctx.arc(p.x, p.y, nr, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.strokeStyle = nodeColor;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Type icon / label
      const shortType = (nodeType.slice(0, 2)).toUpperCase();
      ctx.fillStyle = '#ffffff';
      ctx.font = `bold 10px -apple-system,sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(shortType, p.x, p.y);

      // Node label below
      ctx.fillStyle = this._opts.textColor;
      ctx.font = this._opts.labelFont;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      const lbl = (node.label || node.id || '').slice(0, 16);
      ctx.fillText(lbl, p.x, p.y + nr + 5);

      ctx.restore();
    });

    ctx.restore();
  }

  _attachInteraction() {
    const canvas = this._canvas;
    if (this._interactionAttached) return;
    this._interactionAttached = true;

    let panStart = null;
    let panOrigin = { x: 0, y: 0 };

    const getPos = (ev) => {
      const rect = canvas.getBoundingClientRect();
      return {
        x: (ev.clientX - rect.left - this._pan.x) / this._scale,
        y: (ev.clientY - rect.top  - this._pan.y) / this._scale,
      };
    };

    const hitNode = (pos) => {
      const nr = this._opts.nodeRadius;
      return this._nodes.find(node => {
        const p = this._positions[node.id];
        if (!p) return false;
        const dx = p.x - pos.x, dy = p.y - pos.y;
        return Math.sqrt(dx * dx + dy * dy) < nr + 4;
      });
    };

    canvas.addEventListener('mousedown', ev => {
      const pos = getPos(ev);
      const node = hitNode(pos);
      if (node) {
        this._dragging = node.id;
        const p = this._positions[node.id];
        this._dragOffset = { x: pos.x - p.x, y: pos.y - p.y };
      } else {
        panStart = { x: ev.clientX, y: ev.clientY };
        panOrigin = { x: this._pan.x, y: this._pan.y };
      }
    });

    canvas.addEventListener('mousemove', ev => {
      if (this._dragging) {
        const pos = getPos(ev);
        const p = this._positions[this._dragging];
        if (p) { p.x = pos.x - this._dragOffset.x; p.y = pos.y - this._dragOffset.y; }
      } else if (panStart) {
        this._pan.x = panOrigin.x + (ev.clientX - panStart.x);
        this._pan.y = panOrigin.y + (ev.clientY - panStart.y);
      }
    });

    window.addEventListener('mouseup', () => {
      this._dragging = null;
      panStart = null;
    });

    canvas.addEventListener('wheel', ev => {
      ev.preventDefault();
      const factor = ev.deltaY < 0 ? 1.1 : 0.9;
      this._scale = Math.max(0.3, Math.min(3, this._scale * factor));
    }, { passive: false });
  }

  destroy() {
    if (this._frame) cancelAnimationFrame(this._frame);
  }
}


/* ══════════════════════════════════════════════════════════════════
 * LiveFeedView — live scan event feed with WebSocket
 * ══════════════════════════════════════════════════════════════════ */
class LiveFeedView {
  /**
   * @param {HTMLElement} containerEl - the .live-feed-body element
   * @param {HTMLElement} statusEl   - the .live-status element
   * @param {HTMLElement} countEl    - count badge
   * @param {object} opts
   */
  constructor(containerEl, statusEl, countEl, opts) {
    this._container = containerEl;
    this._statusEl  = statusEl;
    this._countEl   = countEl;
    this._opts = Object.assign({ maxRows: 200, autoScroll: true }, opts || {});
    this._count = 0;
    this._bus   = null;
    this._paused = false;
  }

  /** Connect to the scan event bus. */
  connect(wsUrl, sseUrl) {
    this._bus = new ScanEventBus(wsUrl, sseUrl);
    this._bus.on('status',  data => this._updateStatus(data));
    this._bus.on('finding', data => { if (!this._paused) this._appendFinding(data); });
    this._bus.on('message', msg  => {
      if (msg.event === 'scan_start')    this._appendInfo('Scan started');
      if (msg.event === 'scan_complete') this._appendInfo('Scan complete (' + (msg.data?.total || 0) + ' findings)');
      if (msg.event === 'scan_error')    this._appendInfo('Error: ' + (msg.data?.message || 'unknown'));
    });
    this._bus.connect();
    this._renderEmpty();
  }

  disconnect() {
    if (this._bus) { this._bus.disconnect(); this._bus = null; }
  }

  clear() {
    this._count = 0;
    this._container.innerHTML = '';
    this._renderEmpty();
    this._updateCount();
  }

  togglePause() { this._paused = !this._paused; }

  _appendFinding(finding) {
    this._removeEmpty();
    this._count++;
    this._updateCount();

    const sev = finding.severity || 'INFO';
    const dot = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢', INFO: '⚪' }[sev] || '';
    const badge = `<span class="sev-badge sev-${this._esc(sev)}">${dot} ${this._esc(sev)}</span>`;
    const ts = new Date().toTimeString().slice(0, 8);
    const msg = this._esc(finding.message || finding.description || finding.id || 'Finding');
    const file = this._esc((finding.file || '').split('/').slice(-1)[0] || '');

    const row = document.createElement('div');
    row.className = 'live-feed-row';
    row.innerHTML = `
      <span class="live-row-ts">${ts}</span>
      <span class="live-row-badge">${badge}</span>
      <span class="live-row-msg" title="${this._esc(finding.message || '')}">${msg}</span>
      ${file ? `<span class="live-row-file">${file}</span>` : ''}`;
    this._container.appendChild(row);

    // Trim old rows
    const rows = this._container.querySelectorAll('.live-feed-row');
    if (rows.length > this._opts.maxRows) rows[0].remove();

    if (this._opts.autoScroll) row.scrollIntoView({ behavior: 'smooth' });
  }

  _appendInfo(text) {
    this._removeEmpty();
    const row = document.createElement('div');
    row.className = 'live-feed-row';
    row.style.color = 'var(--muted, #8b949e)';
    row.innerHTML = `<span class="live-row-ts">${new Date().toTimeString().slice(0, 8)}</span>
      <span class="live-row-msg">ℹ️ ${this._esc(text)}</span>`;
    this._container.appendChild(row);
    if (this._opts.autoScroll) row.scrollIntoView({ behavior: 'smooth' });
  }

  _renderEmpty() {
    if (!this._container.querySelector('.live-feed-empty')) {
      const el = document.createElement('div');
      el.className = 'live-feed-empty';
      el.innerHTML = `<div class="live-feed-empty-icon">&#128247;</div>
        <div class="live-feed-empty-text">Waiting for scan events&hellip;</div>`;
      this._container.appendChild(el);
    }
  }

  _removeEmpty() {
    const el = this._container.querySelector('.live-feed-empty');
    if (el) el.remove();
  }

  _updateStatus(data) {
    if (!this._statusEl) return;
    const dot   = this._statusEl.querySelector('.live-status-dot');
    const label = this._statusEl.querySelector('.live-status-label');

    const map = {
      idle:         { cls: '',           text: 'Idle' },
      connecting:   { cls: 'connecting', text: 'Connecting…' },
      connected:    { cls: 'connected',  text: 'Connected (WS)' },
      sse:          { cls: 'sse',        text: 'Connected (SSE)' },
      disconnected: { cls: 'error',      text: 'Disconnected' },
      error:        { cls: 'error',      text: 'Error' },
      closed:       { cls: '',           text: 'Closed' },
    };

    const info = map[data.status] || { cls: '', text: data.status };
    if (dot)   dot.className   = 'live-status-dot ' + info.cls;
    if (label) label.textContent = info.text;
  }

  _updateCount() {
    if (this._countEl) this._countEl.textContent = this._count + ' events';
  }

  _esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}


/* ══════════════════════════════════════════════════════════════════
 * DashboardAPI — fetch helpers for the REST endpoints
 * ══════════════════════════════════════════════════════════════════ */
const DashboardAPI = {
  _base: '',

  setBase(url) { this._base = url.replace(/\/$/, ''); },

  async summary() {
    return this._get('/api/dashboard/summary');
  },

  async findings(severity, limit) {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (limit)    params.set('limit', String(limit));
    const q = params.toString();
    return this._get('/api/dashboard/findings' + (q ? '?' + q : ''));
  },

  async heatmap() {
    return this._get('/api/dashboard/heatmap');
  },

  async graph() {
    return this._get('/api/dashboard/graph');
  },

  async _get(path) {
    const resp = await fetch(this._base + path);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${path}`);
    return resp.json();
  },
};


/* ══════════════════════════════════════════════════════════════════
 * Export to window
 * ══════════════════════════════════════════════════════════════════ */
window.ScanEventBus   = ScanEventBus;
window.FindingsTable  = FindingsTable;
window.SeverityChart  = SeverityChart;
window.HeatmapView    = HeatmapView;
window.ContractGraph  = ContractGraph;
window.LiveFeedView   = LiveFeedView;
window.DashboardAPI   = DashboardAPI;

// Global instance reference (set by HTML after DOM ready)
window.dashFindingsTable = null;
