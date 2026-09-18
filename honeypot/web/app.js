/* ==========================================================================
   CogTrap 值守台 —— 前端逻辑
   ==========================================================================

   原则:
     · 零依赖、零构建。手写 DOM 与 SVG, 不使用任何框架或图表库。
     · 失败要可见。接口取不到数据时明确显示"连接中断", 而不是静默保留旧数据 ——
       值班人员必须能分辨"没有攻击"与"界面坏了"。
     · 不缓存旧值。所有数值都是服务端当前状态的直接投影。
   ========================================================================== */

(function () {
  'use strict';

  var REFRESH_MS = 3000;

  /* ---------- 工具 ---------- */

  function $(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function fmtTime(ts) {
    if (!ts) return '—';
    var d = new Date(ts * 1000);
    function p(n) { return n < 10 ? '0' + n : String(n); }
    return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
           p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function fmtDuration(seconds) {
    if (seconds === undefined || seconds === null) return '—';
    seconds = Math.floor(seconds);
    if (seconds < 60) return seconds + ' 秒';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' 分 ' + (seconds % 60) + ' 秒';
    var h = Math.floor(seconds / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    return h + ' 时 ' + m + ' 分';
  }

  function fmtNumber(n) {
    if (n === undefined || n === null) return '0';
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  /* 令牌高亮: 让金丝雀令牌在证据里一眼可见, 便于抄录进上报材料 */
  var TOKEN_RE = /(hpx-[0-9a-f]{6,32})/g;

  function withTokens(text) {
    var frag = document.createDocumentFragment();
    var parts = String(text || '').split(TOKEN_RE);
    for (var i = 0; i < parts.length; i++) {
      if (TOKEN_RE.test(parts[i])) {
        TOKEN_RE.lastIndex = 0;
        frag.appendChild(el('span', 'tok', parts[i]));
      } else if (parts[i]) {
        frag.appendChild(document.createTextNode(parts[i]));
      }
    }
    return frag;
  }

  /* ---------- 处置档与判定的视觉映射 ---------- */

  var ACTION_LABEL = {
    serve: '服务',
    serve_watch: '观察',
    tarpit: '拖滞',
    deceive_inject: '注入',
    lockdown: '锁定'
  };

  var ACTION_COLOR = {
    serve: 'var(--a-serve)',
    serve_watch: 'var(--a-watch)',
    tarpit: 'var(--a-tarpit)',
    deceive_inject: 'var(--a-inject)',
    lockdown: 'var(--a-lock)'
  };

  var EVIDENCE_DESC = {
    canary_echo: '对方把我们的响应内容当上下文复用',
    injection_compliance: '对方服从了我们嵌入的指令',
    agent_config_captured: '对方交出了自己的系统提示词与工具清单',
    honeytoken_read: '对方读取了伪造凭据, 证明窃取意图',
    beacon_callback: '对方按指令回连我方信标端点'
  };

  function labelTag(label) {
    var cls = 'tag-other';
    var text = label || 'unknown';
    if (label === 'llm_agent') { cls = 'tag-llm'; text = 'LLM 智能体'; }
    else if (label === 'llm_agent_probable') { cls = 'tag-prob'; text = '疑似智能体'; }
    else if (label === 'automation_scanner') { cls = 'tag-tarpit'; text = '自动化扫描'; }
    else if (label === 'browser') { cls = 'tag-serve'; text = '浏览器'; }
    else if (label === 'search_engine') { cls = 'tag-serve'; text = '搜索引擎'; }
    else if (label === 'suspicious_automation') { cls = 'tag-serve_watch'; text = '可疑自动化'; }
    else if (label === 'unknown') { text = '未定'; }
    return el('span', 'tag ' + cls, text);
  }

  function actionTag(action) {
    var cls = 'tag-' + (ACTION_COLOR[action] ? action : 'serve');
    return el('span', 'tag ' + cls, ACTION_LABEL[action] || action || '—');
  }

  function scoreCell(score) {
    var wrap = el('div', 'score');
    var value = el('span', null, score);
    var bar = el('div', 'score-bar');
    var fill = el('div', 'score-fill');
    fill.style.width = Math.max(2, Math.min(100, score)) + '%';
    fill.style.background = score >= 80 ? 'var(--a-lock)'
      : score >= 60 ? 'var(--a-inject)'
      : score >= 40 ? 'var(--a-tarpit)'
      : score >= 20 ? 'var(--a-watch)' : 'var(--a-serve)';
    bar.appendChild(fill);
    wrap.appendChild(value);
    wrap.appendChild(bar);
    return wrap;
  }

  /* ---------- 手写 SVG 横条图 ---------- */

  /* 估算文本像素宽度。
     中文/全角字符约等于一个字号宽, 拉丁字符约 0.55 — 这是无浏览器环境下
     唯一能预先算准标签区宽度的方法, 而算准它是必要的: 检测信号名最长可达
     34 字符(如 ssh_algorithm_fingerprint_repeat), 若标签区宽度写死, 它们
     会被裁掉或与条形重叠。 */
  function textWidth(text, fontSize) {
    var total = 0;
    for (var i = 0; i < text.length; i++) {
      total += text.charCodeAt(i) > 0x2e80 ? 1.0 : 0.55;
    }
    return total * fontSize;
  }

  function truncate(text, maxWidth, fontSize) {
    if (textWidth(text, fontSize) <= maxWidth) return text;
    var out = text;
    while (out.length > 3 && textWidth(out + '…', fontSize) > maxWidth) {
      out = out.slice(0, -1);
    }
    return out + '…';
  }

  function barChart(container, rows, colorFn) {
    clear(container);
    if (!rows.length) {
      container.appendChild(el('div', 'empty', '暂无数据'));
      return;
    }

    /* 两张图必须共用同一套行距与条厚。
       试过按行数自适应(稀疏图用更大行距), 结果适得其反: 两图节奏差异更明显,
       5 行的图看起来像被撑开的。行数少时让内容顶部对齐、底部自然留白即可 ——
       并排同构图表的一致性优先于单张的"填满感"。 */
    var rowH = 26, barH = 12, padTop = 4, valueW = 54, fontSize = 11.5;
    var width = Math.max(340, container.clientWidth || 420);

    // 标签区宽度按最长标签算, 并留出 12px 间隙; 上限为总宽的一半,
    // 避免长标签把条形挤没。
    var widest = 0;
    for (var i = 0; i < rows.length; i++) {
      widest = Math.max(widest, textWidth(rows[i].label, fontSize));
    }
    var labelW = Math.min(Math.max(widest + 12, 72), Math.floor(width * 0.5));
    var barMax = width - labelW - valueW;
    if (barMax < 40) {
      // 容器太窄: 优先保证条形可见, 标签截断
      labelW = Math.max(72, width - valueW - 40);
      barMax = width - labelW - valueW;
    }
    var height = padTop * 2 + rows.length * rowH;
    var max = rows.reduce(function (m, r) { return Math.max(m, r.value); }, 1);

    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
    svg.setAttribute('role', 'img');

    rows.forEach(function (row, index) {
      var y = padTop + index * rowH;
      var barW = Math.max(2, (row.value / max) * barMax);

      var label = document.createElementNS(svg.namespaceURI, 'text');
      label.setAttribute('x', labelW - 10);
      label.setAttribute('y', y + rowH / 2 + 4);
      label.setAttribute('text-anchor', 'end');
      label.setAttribute('class', 'bar-label');
      label.textContent = truncate(row.label, labelW - 12, fontSize);
      label.setAttribute('title', row.label);   // 完整值放 title, 悬停可见

      var track = document.createElementNS(svg.namespaceURI, 'rect');
      track.setAttribute('x', labelW);
      track.setAttribute('y', y + rowH / 2 - barH / 2);
      track.setAttribute('width', barMax);
      track.setAttribute('height', barH);
      track.setAttribute('rx', 3);
      track.setAttribute('class', 'bar-track');

      var bar = document.createElementNS(svg.namespaceURI, 'rect');
      bar.setAttribute('x', labelW);
      bar.setAttribute('y', y + rowH / 2 - barH / 2);
      bar.setAttribute('width', barW);
      bar.setAttribute('height', barH);
      bar.setAttribute('rx', 3);
      bar.setAttribute('fill', colorFn ? colorFn(row) : 'var(--accent)');

      /* 数值贴在条形末端, 而不是放在固定的右对齐列。
         实测(解析渲染后的 SVG): 条形长度是按最大值严格归一的(每单位值的像素
         宽度全相等), 所以"比例不对"不是问题; 真正的问题是数值固定在右缘时,
         短条与它自己的数字之间会横跨一大片空白 —— 动作分布图的值都很小
         (最大才 3), 整排看起来就像"没填满"。贴末端后数字紧邻条形, 空洞消失。 */
      var valueX = labelW + barW + 8;
      if (valueX + 20 > width) {
        valueX = width - 20;              // 靠右时回退, 避免超出画布
      }
      var value = document.createElementNS(svg.namespaceURI, 'text');
      value.setAttribute('x', valueX);
      value.setAttribute('y', y + rowH / 2 + 4);
      value.setAttribute('class', 'bar-value');
      value.textContent = row.value;

      svg.appendChild(label);
      svg.appendChild(track);
      svg.appendChild(bar);
      svg.appendChild(value);
    });

    container.appendChild(svg);
  }

  /* ---------- 各区块渲染 ---------- */

  var state = { actions: [], evidenceKinds: {} };

  function renderMeta(summary) {
    $('m-instance').textContent = summary.instance || '—';
    $('m-template').textContent = summary.template || '内置默认';
    $('m-scenario').textContent = summary.scenario || '未套用';
    $('m-uptime').textContent = fmtDuration(summary.uptime);
  }

  function renderCounters(summary) {
    var runtime = summary.runtime || {};
    var stats = summary.stats || {};
    var evidenceTotal = 0;
    var counts = (state.evidenceCounts || {});
    Object.keys(counts).forEach(function (k) { evidenceTotal += counts[k]; });

    /* 只保留 6 张主计数。原先一行塞 8 张, 每卡过窄导致主数字被副标签挤压,
       且破坏了"每卡一个大数字"的扫读节奏。次要指标改为一行文字摘要。 */
    var items = [
      { label: '确证证据', value: fmtNumber(evidenceTotal), hint: '上报材料主体', cls: 'counter--ev' },
      { label: 'LLM 智能体', value: fmtNumber(stats.sessions_llm), hint: '已确认的智能体会话', cls: 'counter--llm' },
      { label: '会话总数', value: fmtNumber(stats.sessions), hint: '独立来源 ' + fmtNumber(stats.distinct_ips) + ' 个', cls: '' },
      { label: '请求总数', value: fmtNumber(runtime.requests || stats.requests), hint: '连接 ' + fmtNumber(runtime.connections) + ' 次', cls: '' },
      { label: '告警', value: fmtNumber(runtime.alerts), hint: '高于告警阈值', cls: 'counter--alert' },
      { label: '拖滞累计', value: fmtDuration(runtime.tarpit_seconds), hint: '攻击方多付的时间成本', cls: '' }
    ];

    var wrap = $('counters');
    clear(wrap);
    items.forEach(function (item) {
      var card = el('div', 'counter ' + item.cls);
      card.appendChild(el('div', 'counter-label', item.label));
      card.appendChild(el('div', 'counter-value', item.value));
      card.appendChild(el('div', 'counter-hint', item.hint));
      wrap.appendChild(card);
    });

    var secondary = el('div', 'counters-secondary');
    var extras = [
      ['战役', fmtNumber(stats.campaigns) + ' 个 (按行为指纹聚合)'],
      ['非 HTTP 探测', fmtNumber(runtime.non_http) + ' 次 (TLS/二进制打到 HTTP 端口)'],
      ['拖滞预算', fmtNumber(runtime.budget_used) + ' / ' + fmtNumber(runtime.budget_total) + ' 秒'],
      ['熔断次数', fmtNumber(runtime.shed_events) + ' 次'],
      ['负载比', String(runtime.load_ratio)],
      ['蜜标', fmtNumber((summary.tokens || {}).touched) + ' / ' + fmtNumber((summary.tokens || {}).total) + ' 被读取']
    ];
    extras.forEach(function (pair) {
      var item = el('span');
      item.appendChild(document.createTextNode(pair[0]));
      item.appendChild(el('b', null, pair[1]));
      secondary.appendChild(item);
    });
    wrap.appendChild(secondary);
  }

  function renderEvidence(data) {
    state.evidenceCounts = data.counts || {};
    var grid = $('evidence-counts');
    clear(grid);

    Object.keys(state.evidenceKinds).forEach(function (kind) {
      var count = (data.counts || {})[kind] || 0;
      var card = el('div', 'ev-card ev-card--' + kind + ' ' + (count > 0 ? 'hot' : 'cold'));
      card.appendChild(el('div', 'ev-title', state.evidenceKinds[kind]));
      card.appendChild(el('div', 'ev-count', count));
      card.appendChild(el('div', 'ev-desc', EVIDENCE_DESC[kind] || ''));
      grid.appendChild(card);
    });

    var list = $('evidence-list');
    clear(list);
    if (!data.evidence || !data.evidence.length) {
      list.appendChild(el('div', 'empty', '暂无确证证据。等待自动化目标交互…'));
      return;
    }

    /* 按证据类型轮取, 而不是简单地取前 N 条。
       原先按时间倒序取 14 条, 结果是被同一类证据(数量最多的那种)刷屏,
       其余四类一条都看不到 —— 而"五类证据各有几次"正是这一区的核心信息。 */
    /* 多取一些把列表填满: 列表是内滚容器, 条目少时下方会留出空白,
       让最重要的卡片看起来"没排满"。 */
    var picked = pickAcrossKinds(data.evidence, 25);
    picked.forEach(function (item) {
      var row = el('div', 'ev-row');
      row.appendChild(el('div', 'ev-kind ev-kind--' + item.kind,
                         item.label || item.kind));
      row.appendChild(el('div', 'ev-time', fmtTime(item.ts)));
      var detail = el('div', 'ev-detail');
      /* 单行截断 + title 保留全文。原先每条完整折行 2-5 行, 13 条形成
         一堵无差别的文字墙, 反而不可扫读。 */
      var text = String(item.detail || '').replace(/\s+/g, ' ');
      detail.appendChild(withTokens(text));
      detail.title = text;
      row.appendChild(detail);
      list.appendChild(row);
    });

    /* 记录总数写在区域标题的说明行里, 而不是列表下方 —— 后者会在卡片
       右下角留下一段孤悬的小字, 显得整区没收尾。 */
    var total = $('evidence-total');
    if (total) {
      total.textContent = '共 ' + data.evidence.length + ' 条记录, 按类型轮取显示 ' +
                          picked.length + ' 条; 完整证据见取证材料导出。';
    }
  }

  /* 按类型轮流取, 保证每一类证据都能露脸 */
  function pickAcrossKinds(rows, limit) {
    var groups = {};
    rows.forEach(function (row) {
      var kind = row.kind || 'other';
      (groups[kind] = groups[kind] || []).push(row);
    });
    var kinds = Object.keys(groups);
    var out = [], index = 0;
    while (out.length < limit) {
      var added = false;
      for (var i = 0; i < kinds.length && out.length < limit; i++) {
        if (groups[kinds[i]].length > index) {
          out.push(groups[kinds[i]][index]);
          added = true;
        }
      }
      if (!added) break;
      index++;
    }
    return out;
  }

  function renderCharts(sessions, signals) {
    state.actions = (sessions.sessions || []).map(function (s) { return s.action || 'serve'; });

    var order = ['serve', 'serve_watch', 'tarpit', 'deceive_inject', 'lockdown'];
    var counts = {};
    order.forEach(function (a) { counts[a] = 0; });
    state.actions.forEach(function (a) { counts[a] = (counts[a] || 0) + 1; });

    barChart($('chart-actions'),
      order.map(function (a) { return { label: ACTION_LABEL[a], value: counts[a] || 0, action: a }; }),
      function (row) { return ACTION_COLOR[row.action]; });

    barChart($('chart-signals'),
      (signals.signals || []).slice(0, 12).map(function (s) {
        return { label: s.name, value: s.hits };
      }),
      function () { return 'var(--accent)'; });
  }

  function renderSessions(data) {
    var tbody = $('table-sessions').querySelector('tbody');
    clear(tbody);
    var rows = data.sessions || [];
    if (!rows.length) {
      var tr = el('tr');
      var td = el('td', 'empty', '暂无会话');
      td.colSpan = 8;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach(function (s) {
      var tr = el('tr');

      var tdLabel = el('td'); tdLabel.appendChild(labelTag(s.label)); tr.appendChild(tdLabel);

      var tdScore = el('td', 'num'); tdScore.appendChild(scoreCell(s.score)); tr.appendChild(tdScore);

      var tdAction = el('td'); tdAction.appendChild(actionTag(s.action)); tr.appendChild(tdAction);

      tr.appendChild(el('td', 'ip', s.ip || '—'));
      tr.appendChild(el('td', 'num', s.requests || 0));
      tr.appendChild(el('td', 'num', s.tarpit_ms ? (s.tarpit_ms / 1000).toFixed(1) + 's' : '—'));
      tr.appendChild(el('td', 'hash', s.behavior_hash || '—'));

      var tdUa = el('td', 'ua', s.ua || '—');
      tdUa.title = s.ua || '';
      tr.appendChild(tdUa);

      tbody.appendChild(tr);
    });
  }

  function renderCampaigns(data) {
    var wrap = $('campaigns');
    clear(wrap);
    var rows = data.campaigns || [];
    if (!rows.length) {
      wrap.appendChild(el('div', 'empty', '暂无战役。跨源 IP 的行为关联会在这里成形。'));
      return;
    }
    rows.forEach(function (c) {
      var card = el('div', 'camp');
      var head = el('div', 'camp-head');
      head.appendChild(el('span', 'camp-id', c.id));
      head.appendChild(labelTag(c.score_max >= 80 ? 'llm_agent'
        : c.score_max >= 55 ? 'llm_agent_probable' : 'unknown'));
      head.appendChild(el('span', 'camp-id', '分数上限 ' + c.score_max));
      card.appendChild(head);
      card.appendChild(el('div', 'camp-ips', (c.ips || []).join('   ')));
      var meta = '行为哈希 ' + (c.behavior_hash || '—') +
                 ' · 会话 ' + c.session_count +
                 ' · 最后活动 ' + fmtTime(c.last_seen);
      if (c.toolchain) meta += ' · 工具链 ' + c.toolchain;
      if (c.model_guess) meta += ' · 模型 ' + c.model_guess;
      card.appendChild(el('div', 'camp-meta', meta));
      wrap.appendChild(card);
    });
  }

  function renderTokens(summary) {
    var wrap = $('tokens');
    clear(wrap);
    var tokens = summary.tokens || {};
    var rows = [
      ['蜜标总数', fmtNumber(tokens.total)],
      ['已被读取', fmtNumber(tokens.touched)],
      ['读取次数', fmtNumber(tokens.reads)],
      ['拖滞预算已用', (summary.runtime && summary.runtime.budget_used !== undefined)
        ? summary.runtime.budget_used + ' / ' + summary.runtime.budget_total + ' 秒' : '—'],
      ['负载比', (summary.runtime && summary.runtime.load_ratio !== undefined)
        ? summary.runtime.load_ratio : '—'],
      ['熔断次数', (summary.runtime && summary.runtime.shed_events !== undefined)
        ? summary.runtime.shed_events : '—']
    ];
    rows.forEach(function (pair) {
      var row = el('div', 'kv-row');
      row.appendChild(el('div', 'kv-key', pair[0]));
      row.appendChild(el('div', 'kv-val', pair[1]));
      wrap.appendChild(row);
    });
  }

  function renderAlerts(data) {
    var wrap = $('alerts');
    clear(wrap);
    var rows = data.alerts || [];
    if (!rows.length) {
      wrap.appendChild(el('div', 'empty', '暂无告警'));
      return;
    }
    rows.slice(0, 26).forEach(function (line) {
      var cls = '';
      if (line.indexOf('[critical]') >= 0) cls = 'lv-critical';
      else if (line.indexOf('[warning]') >= 0) cls = 'lv-warning';
      wrap.appendChild(el('div', cls, line));
    });
  }

  /* ---------- 轮询 ---------- */

  function getJSON(path) {
    return fetch(path, { cache: 'no-store' }).then(function (response) {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    });
  }

  function setLive(ok, message) {
    var dot = $('live-dot');
    dot.className = 'live-dot ' + (ok ? 'on' : 'off');
    $('live-text').textContent = message;
  }

  function refresh() {
    Promise.all([
      getJSON('/api/summary'),
      getJSON('/api/sessions'),
      getJSON('/api/signals'),
      getJSON('/api/evidence'),
      getJSON('/api/campaigns'),
      getJSON('/api/alerts')
    ]).then(function (results) {
      var summary = results[0];
      state.evidenceKinds = summary.evidence_kinds || {};
      renderMeta(summary);
      renderCounters(summary);
      renderEvidence(results[3]);
      renderCharts(results[1], results[2]);
      renderSessions(results[1]);
      renderCampaigns(results[4]);
      renderTokens(summary);
      renderAlerts(results[5]);
      setLive(true, '实时 · ' + new Date().toLocaleTimeString('zh-CN'));
    }).catch(function (err) {
      setLive(false, '连接中断 · ' + err.message);
    });
  }

  refresh();
  setInterval(refresh, REFRESH_MS);
  window.addEventListener('resize', function () {
    // 图表宽度会随容器变化, 重绘一次避免拉伸
    getJSON('/api/sessions').then(function (s) { renderSessions(s); });
  });
})();
