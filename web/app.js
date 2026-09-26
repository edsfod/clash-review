'use strict';
// Clash Review 单页面（v2「收件箱」布局）。数据全部来自 /api/*（clash_review_web.py），本文件只负责渲染与交互。

const CAT_CN = { reject: '拉黑', direct: '直连', proxy: '代理' };
const KINDS = [['proxy', '代理', '1'], ['direct', '直连', '2'], ['reject', '拉黑', '3'], ['ignore', '忽略', '4']];

const S = {
  page: 'pending', status: null, susCount: null,
  pending: { data: null, choice: {}, focus: null, open: {}, result: [] },
  routed: { view: 'sus', markView: {}, sus: null, list: null, dir: null, dirBusy: {}, dirGen: null, totals: null, q: '', mark: {}, focus: null, result: [] },
  rules: { sets: null, tidy: null, sel: null, view: 'entries', q: '', draft: '', undo: null, result: [] },
};

// ---------------- 工具 ----------------
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = (n) => Number(n).toLocaleString('en-US');
const pct = (x) => `${Math.round(x * 100)}%`;
// 规则集名与先后顺序取自 Clash 配置（/api/status 的 names、order），不写死
const setName = (cat, kind = 'domain') => S.status?.names?.[kind]?.[cat] || `my-${cat}${kind === 'ip' ? '-ip' : ''}`;
const catOrder = () => (S.status?.order || ['reject', 'direct', 'proxy']).map((c) => CAT_CN[c]).join(' → ');
const fillNames = (html) => html.replace(/\{\{(reject|direct|proxy)\}\}/g, (_, c) => setName(c)).replace('{{order}}', catOrder());

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: 'POST', body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', 'X-Clash-Review': '1' },
  };
  const r = await fetch(path, opt);
  let j = {};
  try { j = await r.json(); } catch (e) { /* 非 JSON */ }
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}
let toastTimer = 0;
function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), 6000);
}
async function guard(fn) {
  try { await fn(); } catch (e) { toast(e.message); }
}

// ---------------- 配色、显示设置、本机显示参数、心跳：web-kit（/kit/kit.js）----------------
// 显示参数由 kit 读；这里只取结果画状态栏（WebKit.display.zoomOff / .text），变了时 kit 回调 renderStatus。
const DISPLAY = WebKit.display;

// ---------------- 顶栏状态 ----------------
async function loadStatus() {
  S.status = await api('/api/status');
  renderStatus();
}
async function loadSusCount() {
  const r = await api('/api/suggest');
  S.susCount = r.rows.length;
  if (S.page === 'routed' && S.routed.view === 'sus') { S.routed.sus = r; }
  renderStatus();
}
function renderStatus() {
  const d = S.status;
  if (!d) return;
  const out = [];
  const stale = d.sets.filter((s) => s.state === 'stale' || s.state === 'missing');
  if (!d.core) out.push('<span class="st bad"><span class="dot"></span>连不上内核</span>');
  else if (stale.length) out.push(`<span class="st warn"><span class="dot"></span>${stale.map((s) => esc(s.name)).join('、')} 未生效 · 去 Clash Verge 重新激活 <button data-act="recheck">重新检查</button></span>`);
  else out.push('<span class="st"><span class="dot"></span>规则集已生效</span>');
  out.push(d.watch === false ? '<span class="st bad"><span class="dot"></span>watch 未运行</span>'
    : `<span class="st"><span class="dot"></span>watch ${d.watch ? '运行中' : '状态未知'}</span>`);
  if (d.core && d.core.find_process_mode !== 'always') out.push('<span class="st warn"><span class="dot"></span>进程识别未开启</span>');
  d.fallback.filter((f) => !f.ok).forEach((f) => out.push(`<span class="st bad"><span class="dot"></span>${esc(f.host)} 未放行</span>`));
  if (d.dest) {
    const wait = d.dest.submitted.filter((r) => r.state === 'pending').length;
    const broke = d.dest.submitted.filter((r) => r.state === 'failed' || r.state === 'timeout').length;
    if (!d.dest.ok) out.push(`<span class="st bad" title="${esc(d.dest.error)}"><span class="dot"></span>规则服务连不上</span>`);
    else if (broke) out.push(`<span class="st bad"><span class="dot"></span>${broke} 次提交没上线 · 见 status</span>`);
    else if (wait) out.push(`<span class="st warn"><span class="dot"></span>${wait} 次提交等待上线</span>`);
  }
  if (DISPLAY.zoomOff) out.push(`<span class="st warn"><span class="dot"></span>浏览器缩放 ${pct(DISPLAY.zoomOff)} · Ctrl+0 复原</span>`);
  const m = /^\[\d{4}-(\d\d-\d\d) (\d\d:\d\d)/.exec(d.last_log || '');
  const tip = [...(d.log || []), '', DISPLAY.text].join('\n');
  const dec = d.decisions;
  if (dec && dec.due) out.push(`<span class="st muted" title="上次评估后新增 ${dec.new} 条人工裁定（累计 ${dec.total} 条）。在工具目录运行 python eval_decisions.py，比对模型推荐与你的决定">有 ${dec.new} 条新裁定可评估</span>`);
  out.push(`<span class="st muted opt" title="${esc(tip)}">上次采集 ${m ? m[2] : '—'}${d.core ? ` · 内核 ${esc(d.core.version)}` : ''}</span>`);
  $('status').innerHTML = out.join('');
  $('n-pending').textContent = d.pending.domains + d.pending.ips;
  $('n-routed').textContent = S.susCount ?? '–';
}
$('status').addEventListener('click', (e) => {
  if (e.target.closest('[data-act="recheck"]')) guard(loadStatus);
});

// ---------------- 路由与渲染 ----------------
function route() {
  const p = (location.hash || '#pending').slice(1);
  S.page = ['pending', 'routed', 'rules'].includes(p) ? p : 'pending';
  document.querySelectorAll('.tab').forEach((a) => a.classList.toggle('on', a.dataset.page === S.page));
  render();
  guard(loadPage);
}
async function loadPage() {
  if (S.page === 'pending') await loadPending();
  else if (S.page === 'routed') await loadRouted();
  else await loadRules();
}
// 按下鼠标到松开之间不重画：重画会把按钮换成新元素，按下与松开落在两个元素上，浏览器就不算一次点击。
// 查询进行中每 1.5 秒重画一次，「应用」常被这样吞掉（2026-09-26）。松开后再补画，排在这次点击之后。
let pointerDown = false, renderLater = false;
document.addEventListener('pointerdown', () => { pointerDown = true; }, true);
const pointerRelease = () => { pointerDown = false; if (renderLater) { renderLater = false; setTimeout(render, 0); } };
document.addEventListener('pointerup', pointerRelease, true);
document.addEventListener('pointercancel', pointerRelease, true);
function render() {
  if (pointerDown) { renderLater = true; return; }
  const old = document.querySelector('#page .list');
  const top = old ? old.scrollTop : 0;
  const html = S.page === 'pending' ? pendingHTML() : S.page === 'routed' ? routedHTML() : rulesHTML();
  $('page').innerHTML = html;
  const list = document.querySelector('#page .list');
  if (list) list.scrollTop = top;
}
function renderList() {   // 只换列表，不动页头（搜索框保持焦点）
  const list = document.querySelector('#page .list');
  if (!list) return render();
  const top = list.scrollTop;
  list.innerHTML = S.page === 'routed' ? routedRowsHTML() : S.page === 'rules' ? entriesHTML() : '';
  list.scrollTop = top;
}
function scrollFocus() {
  const el = document.querySelector('#page .row.focus');
  if (el) el.scrollIntoView({ block: 'nearest' });
}
window.addEventListener('hashchange', route);
// 回到窗口时刷新：在 Clash Verge 重新激活后切回来，状态即更新；watch 期间新落盘的待审也会出现
window.addEventListener('focus', () => guard(async () => { await loadStatus(); await loadPage(); }));

function resultHTML(lines, key) {
  if (!lines.length) return '';
  return `<div class="result">${lines.map((n) => `<span><span class="k${n.k === '提示' ? ' warn' : ''}">${esc(n.k)}</span><span class="mono">${esc(n.t)}</span></span>`).join('')}
    <button class="btn btn-ghost btn-sm x" data-act="close-result" data-k="${key}" aria-label="关闭">关闭</button></div>`;
}
function helpBtn() {
  return `<button class="help-btn" data-act="help" title="这页是做什么的、各个词的意思、原理">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01"/></svg>说明</button>`;
}
function kbdHint(parts) {
  return `<span class="hint">${parts.map(([k, t]) => k.split(' ').map((x) => `<span class="kbd">${x}</span>`).join('') + ' ' + t).join('&nbsp; ')}</span>`;
}

// ---------------- 推荐与理由（三层并排；见 layers.py 与 README 第五节）----------------
// 只作提示：推荐只写在行内「推荐 X」标签上，按钮不加描边、不选中；各层冲突时标「分歧」。名单（离线）随列表一起查；
// 模型较慢，按「理由」或「为本页全部生成」才在后台跑，结果缓存在 var/advice.json。
// 外发规则：单行「理由」会把前后连接（站点名）发给模型；「为本页全部生成」不发。
const ADV_CN = { reject: '拉黑', direct: '直连', proxy: '代理', keep: '不选', ignore: '忽略', ok: '正常' };
const A = { lists: {}, listsMissing: false, adv: { pending: {}, suspicious: {}, todirect: {} }, busy: { pending: {}, suspicious: {}, todirect: {} },
  open: { pending: {}, suspicious: {}, todirect: {} }, gen: { pending: null, suspicious: null, todirect: null } };
async function loadLists(hosts) {
  const need = hosts.filter((h) => !(h in A.lists));
  for (let i = 0; i < need.length; i += 150) {
    const r = await api('/api/lists?' + new URLSearchParams({ hosts: need.slice(i, i + 150).join(',') }));
    A.listsMissing = r.missing; Object.assign(A.lists, r.hosts);
    need.slice(i, i + 150).forEach((h) => { if (!(h in A.lists)) A.lists[h] = null; });
  }
}
async function loadAdvice(kind, hosts) {
  if (!hosts.length) return;
  const r = await api('/api/advice?' + new URLSearchParams({ kind, hosts: hosts.join(',') }));
  Object.assign(A.adv[kind], r.advice);
}
async function annotate(kind, hosts) {   // 列表加载后补上名单与已缓存的推荐，不阻塞列表显示
  await Promise.all([loadLists(hosts), loadAdvice(kind, hosts)]);
  if ((kind === 'pending' && S.page === 'pending') || (kind === 'suspicious' && S.page === 'routed' && S.routed.view === 'sus')) render();
}
async function runAdvice(kind, hosts) {
  hosts = hosts.filter((h) => !A.busy[kind][h]);
  if (!hosts.length) return;
  const r = await api('/api/advice/run', { kind, hosts });
  hosts.forEach((h) => { A.busy[kind][h] = true; });
  if (hosts.length > 1) A.gen[kind] = { done: 0, total: r.total };
  render();
  for (;;) {
    await new Promise((ok) => setTimeout(ok, 1500));
    const j = await api('/api/advice/job?' + new URLSearchParams({ id: r.job }));
    Object.entries(j.results).forEach(([h, v]) => { A.adv[kind][h] = v; delete A.busy[kind][h]; });
    if (hosts.length > 1) A.gen[kind] = { done: j.done, total: j.total };
    render();
    if (!j.running) {
      hosts.forEach((h) => delete A.busy[kind][h]);
      A.gen[kind] = null;
      const errs = Object.keys(j.errors).length;
      const modelErr = hosts.map((h) => A.adv[kind][h]?.model_error).find((x) => x);
      if (errs || modelErr) toast(`${errs ? `${errs} 项出错。` : ''}${modelErr ? '模型：' + modelErr : ''}`);
      render();
      if (kind === 'todirect') guard(loadRouted);
      return;
    }
  }
}
function advTags(kind, h) {
  const out = []; const l = A.lists[h]; const a = A.adv[kind][h];
  if (l && l.verdict === 'reject') out.push(`<span class="tag list" title="拦截名单收录">名单：${esc(l.block.join('·'))}</span>`);
  if (A.busy[kind][h]) out.push('<span class="tag busy">查询中…</span>');
  else if (a && a.split) out.push(`<span class="tag split" title="${esc(a.why)}">分歧</span>`);
  else if (a && a.recommend) out.push(`<span class="tag rec" title="${esc(a.why)}">推荐 ${ADV_CN[a.recommend]}</span>`);
  return out.join('');
}
function advOwner(h) {
  const l = A.lists[h];
  return l && l.owner.length ? `v2fly：${esc(l.owner.join('、'))}` : '';
}
function whyBtn(kind, h) {
  return `<button class="why-btn" data-act="why" data-kind="${kind}" data-h="${esc(h)}" title="三层证据与每个选项的理由（快捷键 ?）">理由</button>`;
}
function whyHTML(kind, h) {
  const a = A.adv[kind][h];
  if (A.busy[kind][h] && !a) return '<div class="why"><span class="lh">查询中</span><span>本机证据、名单与模型并排查询，模型要几十秒。</span></div>';
  if (!a) return `<div class="why"><span class="lh">未查询</span><span>还没有查过。<button class="link" data-act="why-run" data-kind="${kind}" data-h="${esc(h)}">现在查询</button></span></div>`;
  const lines = (arr) => arr.map((x) => `<div class="ln">${esc(x)}</div>`).join('') || '<div>（无）</div>';
  let model;
  if (a.model) {
    const m = a.model;
    const opts = [...m.options].sort((x, y) => y.confidence - x.confidence);
    model = `<div class="ln">${esc(ADV_CN[m.decision])}${m.votes ? `（问了 ${m.votes.length} 次：${m.votes.map((v) => ADV_CN[v]).join('、')}）` : ''}
        · ${esc(m.owner || '不认识')}（${{ known: '已知', inferred: '推断', unknown: '不认识' }[m.owner_basis] || ''}）</div>
      <div>归属与功能：${esc(m.function)}</div><div>触发场景：${esc(m.trigger)}</div><div>推荐理由：${esc(m.reason)}</div>
      ${m.block_impact ? `<div>拉黑影响：${esc(m.block_impact)}</div>` : ''}
      <div class="opt">${opts.map((o, i) => `<span class="${i === 0 ? 'top' : ''}">${ADV_CN[o.choice]}</span><span class="c">${o.confidence}</span><span>${esc(o.reason)}</span>`).join('')}</div>`;
  } else model = `<div class="err">${esc(a.model_error || '没有模型结论')}</div>`;
  return `<div class="why"><span class="lh">汇总</span><div class="ln">${esc(a.why)}${a.split ? '　由你决定' : ''}</div>
    <span class="lh">本机</span><div>${lines(a.layer1)}</div>
    <span class="lh">资料</span><div>${lines(a.layer3)}</div>
    <span class="lh">模型</span><div>${model}</div>
    <div class="foot">查询于 ${esc(a.checked.replace('T', ' '))}${a.stale ? ` · <b style="color:var(--amber)">已过期（${esc(a.stale)}）</b>` : ''}${a.ctx_sent ? ' · 发给模型的有前后连接（站点名）' : ' · 没有把前后连接发给模型'} · 推荐只作参考，不会替你选
      <button class="link" data-act="why-run" data-kind="${kind}" data-h="${esc(h)}">重新查询</button></div></div>`;
}
function genTodo(kind) {   // 「为本页生成」只查还没查过的；上次模型出错（如余额不足）或已过期（提示词改过、超过 30 天）的算没查过
  const hosts = kind === 'pending' ? pendingItems().map((i) => i.host) : routedRows().map((r) => r.host);
  return hosts.filter((h) => { const a = A.adv[kind][h]; return !A.busy[kind][h] && (!a || a.model_error || a.stale); });
}
function genHTML(kind, n) {
  const g = A.gen[kind];
  if (g) return `<span class="gen">生成中 ${g.done} / ${g.total}</span>`;
  const todo = n ? genTodo(kind).length : 0;
  if (n && !todo) return '<button class="btn btn-ghost btn-sm" disabled title="单项可在理由面板里点「重新查询」">本页已全部查过</button>';
  return `<button class="btn btn-ghost btn-sm" data-act="gen" data-kind="${kind}" ${todo ? '' : 'disabled'} title="对本页还没查过的项查三层证据并问模型；不发前后连接">为本页生成${todo ? `（${todo} 项未查）` : ''}</button>`;
}

// ---------------- 待审 ----------------
async function loadPending() {
  const P = S.pending;
  P.data = await api('/api/pending');
  const live = new Set(pendingItems().map((i) => i.host));
  Object.keys(P.choice).forEach((h) => { if (!live.has(h)) delete P.choice[h]; });
  if (P.focus && !live.has(P.focus)) P.focus = null;
  if (S.page === 'pending') render();
  guard(() => annotate('pending', [...live]));
}
function pendingSections() {
  const g = S.pending.data?.groups || [];
  const multi = g.filter((x) => x.items.length > 1);
  const singles = g.filter((x) => x.items.length === 1).map((x) => x.items[0]);
  return { multi, singles };
}
function pendingItems() {
  const { multi, singles } = pendingSections();
  return [...multi.flatMap((g) => g.items), ...singles];
}
function pendingCounts() {
  const P = S.pending; const c = { proxy: 0, direct: 0, reject: 0, ignore: 0, rest: 0 };
  pendingItems().forEach((i) => { const k = P.choice[i.host]; if (k) c[k] += 1; else c.rest += 1; });
  c.chosen = c.proxy + c.direct + c.reject + c.ignore;
  return c;
}
function pendingHTML() {
  const P = S.pending; const c = pendingCounts();
  let body;
  if (!P.data) body = '<div class="empty">读取中…</div>';
  else if (!pendingItems().length) body = '<div class="empty">待审清单已清空。</div>';
  else {
    const { multi, singles } = pendingSections();
    body = multi.map((g, gi) => {
      const procs = [...new Set(g.items.flatMap((i) => i.procs))];
      return `<div class="ghead"><b>同一次访问</b><span>${esc(g.last.slice(5, 16))}${procs.length ? ' · ' + esc(procs.join('、')) : ''} · ${g.items.length} 项</span>
        <span class="grow"></span><span>整组</span>
        ${KINDS.map(([k, l]) => `<button class="btn btn-ghost btn-sm" data-act="p-group" data-g="${gi}" data-k="${k}">${l}</button>`).join('')}</div>`
        + g.items.map((it) => inboxRowHTML(it, new Set(g.items.map((x) => x.host)))).join('');
    }).join('');
    if (singles.length) {
      body += `<div class="ghead"><b>单独出现</b><span>${singles.length} 项</span></div>` + singles.map((it) => inboxRowHTML(it, new Set())).join('');
    }
  }
  return `<div class="phead"><h1>漏网待审</h1>${helpBtn()}<span class="muted" style="font-size:13px">最终落到 MATCH,REJECT 的连接 · 同一次访问带出的归在一起</span>
      <span class="grow"></span>${genHTML('pending', pendingItems().length)}${kbdHint([['↑ ↓', '选择'], ['1', '代理'], ['2', '直连'], ['3', '拉黑'], ['4', '忽略'], ['0', '撤销'], ['Space', '展开上下文'], ['?', '理由']])}</div>
    <div class="list">${body}</div>
    ${resultHTML(P.result, 'pending')}
    <div class="bar"><span>已选 <b class="mono">${c.chosen}</b> 项</span>
      <span style="font-size:13px;color:var(--ink2)">代理 <b class="mono" style="color:var(--teal)">${c.proxy}</b> · 直连 <b class="mono">${c.direct}</b> · 拉黑 <b class="mono" style="color:var(--crimson)">${c.reject}</b> · 忽略 <b class="mono">${c.ignore}</b></span>
      <span class="muted" style="font-size:13px">其余 ${c.rest} 项留在待审</span><span class="grow"></span>
      <button class="btn btn-ghost" data-act="p-clear" ${c.chosen ? '' : 'disabled'}>清除选择</button>
      <button class="btn btn-primary" data-act="p-apply" ${c.chosen && !P.applying ? '' : 'disabled'}>${P.applying ? '提交中…' : `应用 ${c.chosen} 项 <span class="kbd">Ctrl Enter</span>`}</button></div>`;
}
function inboxRowHTML(it, same) {
  const P = S.pending; const cur = P.choice[it.host];
  const focus = P.focus === it.host; const open = focus && P.open[it.host] && it.ctx.length;
  const bits = [];
  if (it.procs.length) bits.push(`<span class="p">${esc(it.procs.join('、'))}</span>`);
  if (it.ctx.length) bits.push(`前后：${esc(it.ctx.slice(0, 3).join('、'))}${it.ctx.length > 3 ? ` 等 ${it.ctx.length} 个` : ''}`);
  if (it.info) bits.push(esc(it.info));
  const own = advOwner(it.host); if (own) bits.push(own);
  if (!bits.length) bits.push('旧记录，没有进程与前后连接');
  const acts = KINDS.map(([k, l, key]) => `<button class="act${cur === k ? ' on-' + k : ''}" data-act="p-pick" data-h="${esc(it.host)}" data-k="${k}"><span class="k">${key}</span>${l}</button>`).join('');
  return `<div class="row r-inbox${focus ? ' focus' : ''}" data-act="p-focus" data-h="${esc(it.host)}">
    <div class="acts" role="group" aria-label="归类">${acts}</div>
    <div style="min-width:0"><div class="host">${esc(it.host)}${whyBtn('pending', it.host)}</div><div class="sub">${advTags('pending', it.host)}${bits.join(' · ')}</div>
      ${open ? `<div class="chips">${it.ctx.map((h) => `<span class="chip${same.has(h) ? ' hit' : ''}">${esc(h)}</span>`).join('')}</div>` : ''}
      ${A.open.pending[it.host] ? whyHTML('pending', it.host) : ''}</div>
    <span class="meta">${fmtN(it.count)} 次</span><span class="meta dim">${esc(it.last.slice(5, 16))}</span></div>`;
}
function pendingPick(host, k) {
  const P = S.pending;
  if (!k || P.choice[host] === k) delete P.choice[host]; else P.choice[host] = k;
  P.focus = host;
  render();
}
// 写入后怎样生效：写收件箱要重新激活；写规则服务的，上线后由 watch 或本页的后台线程让 Clash 重新取
const reactivateNote = () => S.status?.dest
  ? { k: '生效', t: '规则服务上线后自动让 Clash 重新取，一般一两分钟；顶栏显示等待上线的提交' }
  : { k: '生效', t: '在 Clash Verge 对当前配置右键「重新激活」后生效' };

async function pendingApply() {
  const P = S.pending; const c = pendingCounts();
  if (!c.chosen || P.applying) return;
  const body = { proxy: [], direct: [], reject: [], ignore: [] };
  Object.entries(P.choice).forEach(([h, k]) => body[k].push(h));
  P.applying = true; render();       // 写规则服务要联网，要几秒：期间按钮显示「提交中…」，防止重复提交
  let r;
  try { r = await api('/api/pending/apply', body); } finally { P.applying = false; render(); }
  const wrote = body.proxy.length + body.direct.length + body.reject.length;
  P.result = [...r.notes, ...(wrote ? [reactivateNote()] : [])];
  P.choice = {}; P.focus = null;
  await afterWrite();
}

// ---------------- 地域放行 ----------------
async function loadRouted() {
  const R = S.routed;
  if (R.view === 'sus') {
    const [sus, tot] = await Promise.all([api('/api/suggest'), api('/api/routed?limit=1')]);
    R.sus = sus; R.totals = tot.totals; S.susCount = sus.rows.length; renderStatus();
  } else if (R.view === 'dir') {
    const [dir, tot] = await Promise.all([api('/api/todirect'), api('/api/routed?limit=1')]);
    R.dir = dir; R.totals = tot.totals; dirSyncAdvice();
  } else {
    R.list = await api('/api/routed?' + new URLSearchParams({ bucket: R.view, q: R.q, limit: '300' }));
    R.totals = R.list.totals;
  }
  const live = new Set(routedRows().map((r) => r.host));
  Object.keys(R.mark).forEach((h) => { if (!live.has(h) && R.view === 'sus') delete R.mark[h]; });
  if (S.page === 'routed') render();
  if (R.view === 'sus') guard(() => annotate('suspicious', [...live]));
}
function routedRows() {
  const R = S.routed; const q = R.q.trim().toLowerCase();
  if (R.view === 'sus') return (R.sus?.rows || []).filter((r) => !q || r.host.toLowerCase().includes(q));
  if (R.view === 'dir') return dirRows().filter((r) => !q || r.host.toLowerCase().includes(q));
  return R.list?.rows || [];
}
// ---------------- 可改直连（走代理、在国内可能有节点的主机；见 clash_review_web 的「代理改直连的候选」）----------------
// 两道关：测速（直连连不上或不比代理快的隐藏）→ 按策略问模型（建议保持代理的隐藏）。隐藏的可在页头展开。
// 排序：建议直连 → 建议拉黑 → 分歧 → 待问模型 → 没实测；同组内保持后端的流量与次数顺序。
function dirRank(r) {
  const a = r.advice;
  if (r.state === 'shown') return a.split ? 2 : a.recommend === 'direct' ? 0 : 1;
  return r.state === 'ask' ? 3 : r.state === 'untested' ? 4 : 5;
}
function dirRows() {
  const R = S.routed; const rows = [...(R.dir?.rows || []), ...(R.dirShowHidden ? R.dir?.hidden || [] : [])];
  return rows.map((r, i) => [r, i]).sort((a, b) => dirRank(a[0]) - dirRank(b[0]) || a[1] - b[1]).map((x) => x[0]);
}
function dirSyncAdvice() {   // 理由面板读 A.adv.todirect
  const R = S.routed;
  [...(R.dir?.rows || []), ...(R.dir?.hidden || [])].forEach((r) => { if (r.advice) A.adv.todirect[r.host] = r.advice; else delete A.adv.todirect[r.host]; });
}
function dirTodo() { const R = S.routed; return (R.dir?.rows || []).filter((r) => (r.state === 'untested' || r.state === 'ask') && !R.dirBusy[r.host]).map((r) => r.host); }
async function dirTest(hosts) {
  const R = S.routed;
  if (!hosts.length) return;
  const r = await api('/api/todirect/test', { hosts });
  hosts.forEach((h) => { R.dirBusy[h] = true; }); R.dirGen = { done: 0, total: r.total }; render();
  for (;;) {
    await new Promise((ok) => setTimeout(ok, 1500));
    const j = await api('/api/advice/job?' + new URLSearchParams({ id: r.job }));
    Object.entries(j.results).forEach(([h, v]) => {
      const i = R.dir ? R.dir.rows.findIndex((x) => x.host === h) : -1; if (i >= 0) R.dir.rows[i] = v; delete R.dirBusy[h];
    });
    dirSyncAdvice();
    R.dirGen = { done: j.done, total: j.total };
    if (!j.running) {
      hosts.forEach((h) => delete R.dirBusy[h]); R.dirGen = null;
      const errs = Object.keys(j.errors).length; if (errs) toast(`${errs} 项出错`);
      await loadRouted();          // 测完的按结论重新分成显示与隐藏，空出的名额由后面的候选补上
      return;
    }
    if (S.page === 'routed') render();
  }
}
function dirGenHTML() {
  const R = S.routed; const g = R.dirGen; const nh = R.dir?.hidden?.length || 0;
  const hid = nh ? `<button class="btn btn-ghost btn-sm" data-act="d-hidden" title="直连连不上、不比代理快、国内解析不到的，以及模型建议保持代理的">${R.dirShowHidden ? '收起' : '显示'}已隐藏的 ${nh} 项</button>` : '';
  if (g) return `${hid}<span class="gen">实测中 ${g.done} / ${g.total}</span>`;
  const n = dirTodo().length;
  if (!n) return `${hid}<button class="btn btn-ghost btn-sm" disabled title="测速与模型结论一直缓存，直到重新查询">本页已全部查过</button>`;
  return `${hid}<button class="btn btn-ghost btn-sm" data-act="d-test" title="直连与走代理各测 3 次首字节；过了测速的按策略问模型">实测（${n} 项）</button>`;
}
function routedHTML() {
  const R = S.routed; const t = R.totals;
  const views = [['sus', '可疑', S.susCount], ['dir', '可改直连', R.dir ? R.dir.rows.length : null], ['all', '全部', t?.all], ['direct', '直连', t?.direct], ['proxy', '代理', t?.proxy]];
  const mk = { reject: 0, ok: 0, direct: 0, keep: 0 }; Object.values(R.mark).forEach((v) => { mk[v] += 1; });
  const total = mk.reject + mk.ok + mk.direct + mk.keep;
  const dir = R.view === 'dir';
  const hint = R.view === 'sus' ? '按可疑度排序，第二行是理由' : dir ? '走代理、直连更快的主机，按策略判断该不该直连' : '按次数排序，最多显示 300 条，用搜索缩小范围';
  const keys = R.view === 'sus' ? [['↑ ↓', '选择'], ['3', '拉黑'], ['0', '正常'], ['?', '理由']] : dir ? [['↑ ↓', '选择'], ['2', '直连'], ['0', '保持代理'], ['3', '拉黑'], ['?', '理由']] : [['↑ ↓', '选择'], ['3', '拉黑']];
  const tally = [['拉黑', mk.reject, 'var(--crimson)'], ['改直连', mk.direct, ''], ['标为正常', mk.ok, ''], ['保持代理', mk.keep, '']]
    .filter(([, n], i) => n || (dir ? i === 1 || i === 3 : i === 0 || i === 2))
    .map(([l, n, c]) => `${l} <b class="mono"${c ? ` style="color:${c}"` : ''}>${n}</b>`).join(' · ');
  return `<div class="phead"><h1>地域放行</h1>${helpBtn()}
      <div class="seg" role="group" aria-label="视图">${views.map(([k, l, n]) => `<button class="${R.view === k ? 'on' : ''}" data-act="r-view" data-k="${k}">${l} <span class="n">${n == null ? '' : fmtN(n)}</span></button>`).join('')}</div>
      <span class="muted" style="font-size:13px">${hint}</span>
      <span class="grow"></span>${R.view === 'sus' ? genHTML('suspicious', routedRows().length) : dir ? dirGenHTML() : ''}${kbdHint(keys)}
      <input class="fld" style="width:260px" type="search" placeholder="搜索主机" aria-label="搜索主机" id="r-q" value="${esc(R.q)}"></div>
    <div class="list">${routedRowsHTML()}</div>
    ${resultHTML(R.result, 'routed')}
    <div class="bar"><span>${tally}</span>
      <span class="muted" style="font-size:13px">${dir ? `改直连的写入 ${setName('direct')} 并移出地域放行；保持代理的以后不再出现在「可改直连」里` : `拉黑的写入 ${setName('reject')} 并移出地域放行；标为正常的以后不再出现在「可疑」里`}</span><span class="grow"></span>
      <button class="btn btn-ghost" data-act="r-clear" ${total ? '' : 'disabled'}>清除选择</button>
      <button class="btn btn-primary" data-act="r-apply" ${total && !S.routed.applying ? '' : 'disabled'}>${S.routed.applying ? '提交中…' : `应用 ${total} 项 <span class="kbd">Ctrl Enter</span>`}</button></div>`;
}
function routedRowsHTML() {
  const R = S.routed; const sus = R.view === 'sus';
  if (R.view === 'dir') return dirRowsHTML();
  if ((sus && !R.sus) || (!sus && !R.list)) return '<div class="empty">读取中…</div>';
  const rows = routedRows();
  if (!rows.length) return `<div class="empty">${sus ? '没有达到阈值的可疑项。' : '没有匹配的主机。'}</div>`;
  const html = rows.map((r) => {
    const m = R.mark[r.host];
    const sub = sus ? r.why.join(' · ') : `端口 ${r.ports.slice(0, 3).join(',')}${r.ports.length > 3 ? '…' : ''} · 最近 ${r.last.slice(5, 16)}`;
    const own = sus ? advOwner(r.host) : '';
    const acts = `<button class="act${m === 'reject' ? ' on-reject' : ''}" data-act="r-mark" data-h="${esc(r.host)}" data-k="reject"><span class="k">3</span>拉黑</button>`
      + (sus ? `<button class="act${m === 'ok' ? ' on-ok' : ''}" data-act="r-mark" data-h="${esc(r.host)}" data-k="ok"><span class="k">0</span>正常</button>` : '');
    return `<div class="row r-routed${R.focus === r.host ? ' focus' : ''}" data-act="r-focus" data-h="${esc(r.host)}">
      <div class="acts" role="group" aria-label="处理">${acts}</div>
      <div style="min-width:0"><div class="host">${esc(r.host)}${sus ? whyBtn('suspicious', r.host) : ''}</div>
        <div class="sub">${sus ? advTags('suspicious', r.host) : ''}${esc(sub)}${own ? ' · ' + own : ''}</div>
        ${sus && A.open.suspicious[r.host] ? whyHTML('suspicious', r.host) : ''}</div>
      <span class="meta" style="font-weight:600;color:${sus && r.score >= 4.5 ? 'var(--copper)' : 'var(--ink2)'}">${sus ? r.score.toFixed(1) : ''}</span>
      <span class="meta" style="text-align:center;color:${r.bucket === 'proxy' ? 'var(--teal)' : 'var(--ink2)'}">${r.bucket === 'proxy' ? '代理' : '直连'}</span>
      <span class="meta cnt">${fmtN(r.count)}</span></div>`;
  }).join('');
  const more = !sus && R.list.matched > rows.length ? `<div class="empty" style="padding:16px">显示 ${rows.length} / ${fmtN(R.list.matched)}</div>` : '';
  return html + more;
}
function fmtSize(n) {
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; }
  return i ? `${n.toFixed(1)}${u[i]}` : `${n}B`;
}
function dirRowsHTML() {
  const R = S.routed;
  if (!R.dir) return '<div class="empty">读取中…</div>';
  const rows = routedRows();
  if (!rows.length) return '<div class="empty">没有候选。</div>';
  return rows.map((r) => {
    const m = R.mark[r.host]; const a = r.advice; const hidden = r.state === 'hidden';
    const tag = R.dirBusy[r.host] ? '<span class="tag busy">查询中…</span>'
      : r.state === 'untested' ? '<span class="tag busy">未实测</span>'
      : r.state === 'ask' ? '<span class="tag busy">待问模型</span>'
      : hidden ? '<span class="tag">已隐藏</span>'
      : a.split ? `<span class="tag split" title="${esc(a.why)}">分歧</span>`
      : `<span class="tag rec">推荐 ${a.recommend === 'direct' ? '直连' : '拉黑'}</span>`;
    const id = r.identity || (a?.model ? { owner: a.model.owner, owner_basis: a.model.owner_basis, function: a.model.function } : null);
    const what = id ? (id.owner_basis === 'unknown' ? '模型不认识' : `${id.function}${id.owner ? `（${id.owner}）` : ''}`)
      : (r.owner.length ? `${r.owner.join('、')} 的服务` : '');
    const vol = r.conns ? `近期 ${r.conns} 个连接、下载 ${fmtSize(r.down)}` : '';
    const line = [hidden ? r.why : r.speed, vol].filter(Boolean).join(' · ');
    const detail = [r.resolve && `国内解析：${r.resolve}`, `端口 ${r.ports.join(',')}`, r.checked && `实测于 ${r.checked.slice(5, 16).replace('T', ' ')}`].filter(Boolean).join('\n');
    const btn = (k, key, label, on) => `<button class="act${m === k ? ' ' + on : ''}" data-act="r-mark" data-h="${esc(r.host)}" data-k="${k}"><span class="k">${key}</span>${label}</button>`;
    return `<div class="row r-routed${R.focus === r.host ? ' focus' : ''}${hidden ? ' dim' : ''}" data-act="r-focus" data-h="${esc(r.host)}">
      <div class="acts" role="group" aria-label="处理">${btn('direct', '2', '直连', 'on-direct')}${btn('keep', '0', '保持代理', 'on-ok')}${btn('reject', '3', '拉黑', 'on-reject')}</div>
      <div style="min-width:0" title="${esc(detail)}"><div class="host">${esc(r.host)}${a ? whyBtn('todirect', r.host) : ''}<span class="what">${esc(what)}</span></div>
        <div class="sub">${tag}${esc(line)}</div>
        ${A.open.todirect[r.host] ? whyHTML('todirect', r.host) : ''}</div>
      <span class="meta"></span>
      <span class="meta" style="text-align:center;color:var(--teal)">代理</span>
      <span class="meta cnt">${fmtN(r.count)}</span></div>`;
  }).join('');
}
function routedMark(host, k) {
  const R = S.routed;
  if (!k || R.mark[host] === k) { delete R.mark[host]; delete R.markView[host]; } else { R.mark[host] = k; R.markView[host] = R.view; }
  R.focus = host;
  render();
}
async function routedApply() {
  const R = S.routed; const body = { reject: [], ok: [], direct: [], keep: [], views: { ...R.markView } };   // views：裁定日志按视图区分可疑 / 可改直连
  Object.entries(R.mark).forEach(([h, k]) => body[k].push(h));
  if (!Object.values(body).some((x) => x.length) || R.applying) return;
  R.applying = true; render();
  let r;
  try { r = await api('/api/routed/apply', body); } finally { R.applying = false; render(); }
  R.result = [...r.notes, ...(body.reject.length || body.direct.length ? [reactivateNote()] : [])];
  R.mark = {}; R.markView = {}; R.focus = null;
  await afterWrite();
  guard(loadSusCount);
}

// ---------------- 规则 ----------------
async function loadRules() {
  const [r, t] = await Promise.all([api('/api/rules'), api('/api/tidy')]);
  S.rules.sets = r.sets; S.rules.tidy = t; S.rules.dest = r.dest || null;
  if (r.sets.length && !r.sets.some((s) => s.name === S.rules.sel)) S.rules.sel = (r.sets.find((s) => s.name === r.default) || r.sets.find((s) => s.kind === 'domain' && s.cat === 'proxy') || r.sets[0]).name;
  if (S.page === 'rules') render();
}
// 规则服务的规则集可能带层（如 common、windows），类别未知的写「?」（服务端没给、这台电脑也没用到）
const setLabel = (s) => `${s.layer ? s.layer + ' · ' : ''}${CAT_CN[s.cat] || '?'} · ${s.kind === 'ip' ? 'IP' : '域名'}`;
// 条目可以移到哪里：收件箱是另外两类（按类名）；规则服务是服务端给的目标规则集（同层别的类、同类别的层）
function moveTargets(s) {
  if (!S.rules.dest) return ['reject', 'direct', 'proxy'].filter((c) => c !== s.cat).map((c) => ({ to: c, label: `移到${CAT_CN[c]}` }));
  return [...Object.entries(s.moves || {}).map(([c, id]) => ({ to: id, label: `移到${CAT_CN[c]}` })),
          ...Object.entries(s.layers || {}).map(([l, id]) => ({ to: id, label: `移到${l}层` }))];
}
function tidyCount() {
  const T = S.rules.tidy; if (!T) return 0;
  return T.redundant.length + T.placeholder.length + T.reserved.length + T.overlap.length + T.merge.length;
}
function rulesHTML() {
  const U = S.rules;
  if (!U.sets) return '<div class="empty">读取中…</div>';
  if (!U.sets.length) return '<div class="empty">没有规则集。</div>';
  const st = Object.fromEntries((S.status?.sets || []).map((s) => [s.name, s]));
  const cur = U.sets.find((s) => s.name === U.sel) || U.sets[0];
  const btn = (s) => {
    const x = st[s.name]; const bad = x && x.state !== 'ok' && x.state !== 'unknown';
    return `<button class="set${s.name === cur.name ? ' on' : ''}" data-act="u-sel" data-k="${esc(s.name)}">
      <span class="mono">${esc(s.name)}</span><span class="mono" style="font-size:13px;color:var(--ink2);text-align:right">${s.entries.length}</span>
      <span style="font-size:12.5px;color:var(--ink3)">${setLabel(s)}</span><span style="font-size:12.5px;text-align:right;color:var(--amber)">${bad ? '未生效' : ''}</span></button>`;
  };
  const grp = (t) => `<p class="muted" style="margin:10px 12px 4px;font-size:12.5px">${t}</p>`;
  // 规则服务：这台电脑的 Clash 用到的排在前面，其余（别的平台的层）另起一组
  const nav = U.dest ? grp('这台电脑在用') + U.sets.filter((s) => s.used).map(btn).join('')
      + (U.sets.some((s) => !s.used) ? grp('这台电脑没用到') + U.sets.filter((s) => !s.used).map(btn).join('') : '')
    : U.sets.map(btn).join('');
  if (U.dest && U.view === 'audit') U.view = 'entries';     // 体检只管本机收件箱
  const n = tidyCount();
  const seg = U.dest ? (U.dest.admin_url ? `<a class="link" href="${esc(U.dest.admin_url)}" target="_blank" rel="noreferrer" style="font-size:13px">管理页</a>` : '')
    : `<div class="seg" role="group" aria-label="视图"><button class="${U.view === 'entries' ? 'on' : ''}" data-act="u-view" data-k="entries">条目</button>
        <button class="${U.view === 'audit' ? 'on' : ''}" data-act="u-view" data-k="audit">体检 <span class="n" style="color:${n ? 'var(--amber)' : 'var(--teal)'}">${n}</span></button></div>`;
  const head = `<div class="phead"><h1 class="mono">${esc(cur.name)}</h1>${helpBtn()}<span class="muted" style="font-size:13px">${setLabel(cur)} · ${cur.entries.length} 条</span>
      ${seg}<span class="grow"></span>${U.view === 'entries' ? `<input class="fld" style="width:240px" type="search" placeholder="搜索全部规则集" aria-label="搜索全部规则集" id="u-q" value="${esc(U.q)}">` : ''}</div>`;
  let body;
  if (U.view === 'entries') {
    body = `<form class="add" id="u-add"><label for="u-new" style="font-size:13.5px;color:var(--ink2);white-space:nowrap">新增到 ${esc(cur.name)}</label>
        <input id="u-new" class="fld grow" placeholder="${cur.kind === 'ip' ? 'IP 或 CIDR，如 203.0.113.7/32' : '域名，如 api.example.com'}" value="${esc(U.draft)}" autocomplete="off">
        <button class="btn" type="submit">添加</button>
        <span class="muted" style="font-size:12.5px">${cur.kind === 'ip' ? '单个 IP 写成 /32，已知服务自动扩成整段' : '域名自动匹配子域，已覆盖的会跳过'}</span></form>
      <div class="list" style="border-top:0">${entriesHTML()}</div>
      ${U.undo ? `<div class="bar"><span>已从 ${esc(U.undo.set)} 删除 <span class="mono">${esc(U.undo.entry)}</span></span><span class="grow"></span><button class="btn" data-act="u-undo">撤销</button></div>` : ''}`;
  } else {
    body = `<div class="list">${auditHTML()}</div>`;
  }
  const order = U.dest ? '改动直接提交到规则服务，上线后自动让 Clash 重新取，一般一两分钟'
    : `匹配顺序：${catOrder()} → 其余规则（广告、国内、境外）→ 兜底拒绝`;
  return `<div class="split"><nav class="sets" aria-label="规则集">${nav}<span class="grow"></span>
      <p class="muted" style="margin:0;padding:0 12px;font-size:12.5px;line-height:1.6">${order}</p></nav>
    <section class="pane">${head}${body}${resultHTML(U.result, 'rules')}</section></div>`;
}
function entriesHTML() {
  const U = S.rules; const cur = U.sets.find((s) => s.name === U.sel) || U.sets[0];
  const q = U.q.trim().toLowerCase();
  // 有搜索词时搜全部规则集，每条标出所在的规则集；没有时只列当前规则集
  const rows = q ? U.sets.flatMap((s) => s.entries.filter((v) => v.toLowerCase().includes(q)).map((v) => [s, v]))
    : cur.entries.map((v) => [cur, v]);
  if (!rows.length) return `<div class="empty">${q ? '全部规则集里都没有匹配的条目。' : '这个规则集是空的。'}</div>`;
  return rows.slice(0, 500).map(([s, v]) => `<div class="row r-entry"><span class="host">${esc(v)}${q ? ` <span class="muted" style="font-size:12.5px">${esc(s.name)} · ${setLabel(s)}</span>` : ''}</span><span style="display:flex;gap:2px">
      ${moveTargets(s).map((m) => `<button class="link" data-act="u-move" data-set="${esc(s.name)}" data-h="${esc(v)}" data-k="${esc(m.to)}" data-label="${esc(m.label)}">${esc(m.label)}</button>`).join('')}
      <button class="link link-del" data-act="u-del" data-set="${esc(s.name)}" data-h="${esc(v)}">删除</button></span></div>`).join('')
    + (rows.length > 500 ? `<div class="empty">还有 ${rows.length - 500} 条没显示，用搜索缩小范围。</div>` : '');
}
function auditHTML() {
  const T = S.rules.tidy; if (!T) return '<div class="empty">读取中…</div>';
  const auto = T.redundant.length + T.placeholder.length;
  const group = (kind, hint, items) => items.length ? `<div class="ghead"><b>${kind}</b><span>${hint}</span></div>`
    + items.map(([c, t, act]) => `<div class="row r-audit"><span style="font-size:12.5px;color:var(--ink3)">${esc(c)}</span>
      <span class="mono" style="font-size:13.5px">${esc(t)}</span><span>${act || ''}</span></div>`).join('') : '';
  return `<div style="display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--line2)">
      <b>可自动清理</b><span class="mono" style="color:${auto ? 'var(--amber)' : 'var(--teal)'}">${auto}</span>
      <span class="muted" style="font-size:13px">${auto ? '被同类覆盖的冗余条目与残留占位；删除后匹配行为不变' : '没有被同类覆盖的冗余条目或残留占位'}</span>
      <span class="grow"></span><button class="btn" data-act="u-tidy" ${auto ? '' : 'disabled'}>一键清理</button></div>`
    + group('冗余', '删除后匹配行为不变', [...T.redundant.map((r) => [CAT_CN[r.cat], `${r.entry}  已被 ${r.by} 覆盖`]),
      ...T.placeholder.map((p) => [CAT_CN[p.cat], `${p.kind === 'ip' ? 'IP' : '域名'}：已有真实条目，占位可删`])])
    + group('保留域名', '测试用的占位域名，不会出现在真实流量里', T.reserved.map((r) =>
      [CAT_CN[r.cat], r.entry, `<button class="link link-del" data-act="a-del" data-set="${esc(setName(r.cat))}" data-h="${esc(r.entry)}">删除</button>`]))
    + group('跨类重叠', '同一目标落在两类里，按匹配顺序前者生效', T.overlap.map((o) => ['', o]))
    + group('合并候选', '同一父域下有多个子域；父域可能是大站或公共后缀，逐个确认', T.merge.map((m) =>
      [CAT_CN[m.cat], `${m.parent}  ·  ${m.hosts.length} 个子域：${m.hosts.join(', ')}`,
        `<button class="link" data-act="a-merge" data-k="${m.cat}" data-h="${esc(m.parent)}">合并为 +.${esc(m.parent)}</button>`]))
    + (tidyCount() ? '' : '<div class="empty">体检没有发现问题。</div>');
}

// ---------------- 说明（每页页头的「说明」按钮）----------------
const HELP = {
  pending: { title: '漏网待审：这页是做什么的', html: `
<h3>这页是什么</h3>
<p>Clash 的规则最后一条是 <code>MATCH,REJECT</code>：前面所有规则都没认领的连接，一律拒绝。这是白名单式的策略——没见过的网站默认不通。</p>
<p>被这条兜底规则拒掉的连接，由后台常驻的 watch 从内核日志里记下来、去重累计，列在这里，由你决定它们以后的去向。</p>
<h3>四个操作</h3>
<dl><dt>代理</dt><dd>写入 <code>{{proxy}}</code>，以后走代理。</dd>
<dt>直连</dt><dd>写入 <code>{{direct}}</code>，以后不经代理直接连。</dd>
<dt>拉黑</dt><dd>写入 <code>{{reject}}</code>，以后明确拒绝，不再出现在这里（广告、追踪、没用的连接）。</dd>
<dt>忽略</dt><dd>只从待审里移除，不写任何规则。用于一次性的噪声：测试用的站、打错的网址、命令行误把文件名当网址。不记名单——以后再连到它，会重新出现在这里。</dd>
<dt>不选</dt><dd>应用后仍留在待审。</dd></dl>
<p>代理、直连、拉黑写入收件箱后，要在 Clash Verge 对当前配置右键「重新激活」才生效，顶栏会提示。配了规则服务时不用：写进规则服务，上线后自动让 Clash 重新取，一般一两分钟。</p>
<h3>各个词的意思</h3>
<dl><dt>同一次访问</dt><dd>互相出现在对方「前后连接」里的几条，通常是同一个网页或同一个程序一起带出来的，可以整组处理。</dd>
<dt>前后</dt><dd>这条连接前后各 8 条连接的目标主机（按条数，不按时间）。页面本身的域名通常就在里面，用来判断当时在访问什么。点中这一行再点一次，或按空格，展开全部。</dd>
<dt>发起进程</dt><dd>第二行开头的程序名，如 <code>curl.exe</code>、<code>claude.exe</code>。需要内核开启进程识别（<code>find-process-mode: always</code>）。</dd>
<dt>旧记录</dt><dd>进程识别和前后连接是 2026-09-23 才开始记的，之前记下的条目没有这两项。</dd>
<dt>次数 · 时间</dt><dd>累计被拒次数，最近一次被拒的时间。</dd></dl>
<h3>原理</h3>
<p>watch 经 Clash 内核的命名管道订阅实时日志，挑出最终命中 <code>MATCH,REJECT</code> 的连接，每 200 条连接日志写一次盘。已经被规则集覆盖的主机不会再进来：这六个之外，Clash 配置里按网址取的规则集（<code>type: http</code>，读本地缓存）也算。</p>
<h3>主机名像文件名？</h3>
<p>像 <code>INDEX.md</code> 这种，多半是命令行把文件名当成了网址去连（例如没加引号的 <code>*</code> 被展开成文件列表）。<code>.md</code> 是真实存在的域名后缀（摩尔多瓦），工具没法按后缀排除。这类条目用「忽略」清掉。</p>` },
  routed: { title: '地域放行：这页是做什么的', html: `
<h3>这页是什么</h3>
<p>有一类连接不会进「待审」：它们被<b>地域规则</b>直接放行了——国内网站（GeoSite cn、GeoIP CN）直连，境外网站（GeoSite geolocation-!cn）走代理，根本走不到最后的 <code>MATCH,REJECT</code>。</p>
<p>广告、统计、追踪也会混在里面一起被放行。这页把它们列出来，找出该拉黑的。</p>
<h3>五个视图</h3>
<dl><dt>可疑</dt><dd>给每个主机打分，3 分及以上的按分数排列，第二行是得分理由。</dd>
<dt>可改直连</dt><dd>走代理、但直连可能更好的主机（微软、苹果、Steam 的下载 CDN、证书吊销检查等），直连更快也省代理流量。候选按流量与次数排，去掉登录/账号类、AI 服务、同站你已归到代理的、拦截名单收录的。点「实测」过两道关：先直连与走代理各测 3 次首字节，直连连不上或不比代理快的隐藏；过了的再按策略问模型该不该直连——涉及登录、支付、个人数据或有地区限制的保持代理，出口 IP 探测之类照样拉黑。模型建议保持代理的也隐藏，页头可展开。「直连」写入 {{direct}}，「拉黑」写入 {{reject}}，「保持代理」记下来以后不再列出；测速与模型结论一直缓存，直到重新查询。</dd>
<dt>全部 · 直连 · 代理</dt><dd>原始清单，按连接次数排序，最多列 300 条，用搜索缩小范围。</dd></dl>
<h3>分数怎么来</h3>
<dl><dt>关键词</dt><dd>主机名含 analytics、telemetry、track、sentry、cnzz 等，或整段是 ad、stats、rum、metrics 等，3 分；log、event、sdk 等有歧义的弱关键词 1.5 分。</dd>
<dt>同站已拉黑</dt><dd>和你已拉黑的条目属于同一个网站，且这个网站已知的主机里一半以上被你拉黑，3 分（两成以上 1 分）。只拉黑过一个 Google 广告域名，不会让整个 google.com 都变可疑。</dd>
<dt>只在拉黑里出现的词</dt><dd>从你的规则集里学出来的：某个词只出现在你拉黑的条目里、没出现在放行的条目里，最多 3 分。</dd>
<dt>跨站出现</dt><dd>这个主机最初 40 次出现时，前后跟着很多个不同网站（典型的第三方追踪），最多 1.5 分，单靠它到不了 3 分。</dd>
<dt>子域像随机串</dt><dd>如 <code>o1158394</code>，1.5 分。</dd></dl>
<p>分数只决定排序，不会自动拉黑。</p>
<h3>两个操作</h3>
<dl><dt>拉黑</dt><dd>写入 <code>{{reject}}</code>，并从本清单移除。重新激活后生效。</dd>
<dt>正常</dt><dd>记入「看过」名单，以后不再出现在「可疑」里（「全部」里仍有）。不改任何规则。</dd></dl>
<h3>其它列</h3>
<dl><dt>代理 · 直连</dt><dd>它现在被地域规则送去哪里。</dd><dt>最右的数字</dt><dd>累计连接次数。</dd></dl>` },
  rules: { title: '规则：这页是做什么的', html: `
<h3>配了规则服务时</h3>
<p>左栏是规则服务上能写的全部规则集，这台电脑的 Clash 用到的排在前面。搜索框搜全部规则集；改类、换层、删除直接提交到规则服务（写入密钥只在本机后台用），上线后自动让 Clash 重新取，一般一两分钟。期间别处（如管理页）改过同一个规则集会提示，重新操作一次即可。冗余、重叠由规则服务在写入时提示，没有体检页。下面讲的是没配规则服务时的六个收件箱。</p>
<h3>六个规则集</h3>
<p><code>{{reject}}</code>（拉黑）、<code>{{direct}}</code>（直连）、<code>{{proxy}}</code>（代理），各分域名版和 IP 版，名字取自 Clash 配置。待审和地域放行里的归类，最终都写进这里；这页可以直接增删改。</p>
<p>Clash 配置里另有按网址取的规则集（<code>type: http</code>）时，它们只读：判断「是否已覆盖」、写入时的重叠提示和体检都会算上它们（读本地缓存），但这里不列出，也不会写入。</p>
<h3>匹配顺序</h3>
<p>{{order}}，再往后是 Clash 配置里的其余规则（如广告、国内、境外），最后兜底拒绝。顺序取自 Clash 配置。同一个目标落在两类里时，排在前面的生效。</p>
<h3>条目的写法</h3>
<dl><dt><code>+.example.com</code></dt><dd>匹配 example.com 本身和它的所有子域。新增域名时自动加上 <code>+.</code>。</dd>
<dt><code>example.com</code></dt><dd>不带 <code>+.</code>，只匹配它自己。</dd>
<dt><code>1.2.3.0/24</code></dt><dd>IP 版里的网段。单个 IP 写成 <code>/32</code>；属于已知服务（如 Telegram）的会自动扩成整段。</dd></dl>
<h3>写入时自动做的检查</h3>
<p>已被同类现有条目覆盖的，跳过；新条目覆盖了同类更小的旧条目，旧的一并删掉；和另外两类重叠的，提示按匹配顺序哪一类生效。</p>
<h3>未生效</h3>
<p>配置目录里的文件比 Clash 内核已加载的新：改了还没重新激活。去 Clash Verge 对当前配置右键「重新激活」，回到这个页面状态会自动更新。</p>
<h3>体检</h3>
<dl><dt>冗余</dt><dd>已被同类更大范围的条目覆盖，删掉后匹配行为不变，可一键清理。</dd>
<dt>保留域名</dt><dd><code>.invalid</code>、<code>.example</code> 等永远不会出现在真实流量里的域名，多为测试用。</dd>
<dt>跨类重叠</dt><dd>同一目标落在两类里。有的是有意的例外，如在代理的 ccswitch.io 里单独拉黑它的更新源。</dd>
<dt>合并候选</dt><dd>同一父域下有 3 个以上子域。合并为 <code>+.父域</code> 后，该父域下所有子域都归入这一类，包括以后新出现的；父域若是大站（microsoft.com）或免费子域服务（qzz.io），不要合并。</dd></dl>` },
};

// ---------------- 事件 ----------------
async function afterWrite() {
  await loadPage();
  guard(loadStatus);      // 顶栏在后台更新，不挡列表
}
let qTimer = 0;
document.addEventListener('input', (e) => {
  if (e.target.id === 'r-q') {
    S.routed.q = e.target.value;
    if (S.routed.view === 'sus') renderList();
    else { clearTimeout(qTimer); qTimer = setTimeout(() => guard(async () => { S.routed.list = await api('/api/routed?' + new URLSearchParams({ bucket: S.routed.view, q: S.routed.q, limit: '300' })); renderList(); }), 200); }
  } else if (e.target.id === 'u-q') { S.rules.q = e.target.value; renderList(); }
  else if (e.target.id === 'u-new') S.rules.draft = e.target.value;
});
document.addEventListener('submit', (e) => {
  if (e.target.id !== 'u-add') return;
  e.preventDefault();
  const U = S.rules; const v = U.draft.trim(); if (!v) return;
  guard(async () => {
    const r = await api('/api/rules/add', { set: U.sel, value: v });
    U.draft = ''; U.undo = null;
    U.result = [...r.added.map((a) => ({ k: '写入', t: `${U.sel}  ${a}` })), ...r.notes.map((t) => ({ k: '提示', t }))];
    if (!U.result.length) U.result = [{ k: '提示', t: `${v} 未写入` }];
    await afterWrite();
  });
});
document.addEventListener('click', (e) => {
  if (e.target.closest('.why') && !e.target.closest('.why [data-act]')) return;   // 在理由面板里点字、选字，不触发整行
  const el = e.target.closest('[data-act]'); if (!el) return;
  const a = el.dataset.act; const h = el.dataset.h; const k = el.dataset.k;
  const P = S.pending; const R = S.routed; const U = S.rules;
  if (a === 'help') { $('help-title').textContent = HELP[S.page].title; $('help-body').innerHTML = fillNames(HELP[S.page].html); $('help').showModal(); }
  else if (a === 'help-close') $('help').close();
  else if (a === 'why') toggleWhy(el.dataset.kind, h);
  else if (a === 'why-run') guard(() => runAdvice(el.dataset.kind, [h]));
  else if (a === 'gen') {
    const kind = el.dataset.kind;
    const hosts = genTodo(kind);
    if (hosts.length && confirm(`对本页还没查过的 ${hosts.length} 项查询三层证据并问模型（DeepSeek）？\n\n不发送前后连接；已查过的跳过，要重查请在该项的理由面板里点「重新查询」。结果只作参考，不会替你选择。`)) guard(() => runAdvice(kind, hosts));
  }
  else if (a === 'p-pick') pendingPick(h, k);
  else if (a === 'p-focus') { if (P.focus === h) P.open[h] = !P.open[h]; P.focus = h; render(); }
  else if (a === 'p-group') {
    pendingSections().multi[+el.dataset.g].items.forEach((i) => { P.choice[i.host] = k; });
    render();
  }
  else if (a === 'p-clear') { P.choice = {}; render(); }
  else if (a === 'p-apply') guard(pendingApply);
  else if (a === 'r-view') { R.view = k; R.focus = null; R.list = null; render(); guard(loadRouted); }
  else if (a === 'r-mark') routedMark(h, k);
  else if (a === 'd-test') {
    const hosts = dirTodo();
    if (hosts.length && confirm(`实测 ${hosts.length} 项：直连与走代理各测 3 次首字节时间。\n\n直连可用且更快的，再按策略问模型（DeepSeek）该不该直连：发送主机名、连接次数、国内解析与测速结果，不发前后连接。每项十几到几十秒。`)) guard(() => dirTest(hosts));
  }
  else if (a === 'd-hidden') { R.dirShowHidden = !R.dirShowHidden; render(); }
  else if (a === 'r-focus') { R.focus = h; render(); }
  else if (a === 'r-clear') { R.mark = {}; R.markView = {}; render(); }
  else if (a === 'r-apply') guard(routedApply);
  else if (a === 'close-result') { S[k].result = []; render(); }
  else if (a === 'u-sel') { U.sel = k; U.q = ''; U.undo = null; U.result = []; render(); }
  else if (a === 'u-view') { U.view = k; render(); }
  else if (a === 'u-del') guard(async () => {
    const set = el.dataset.set || U.sel;       // 搜索全部规则集时，每一行属于自己的规则集
    const r = await api('/api/rules/delete', { set, entry: h });
    U.undo = { set, entry: r.removed[0] }; U.result = (r.notes || []).map((t) => ({ k: '提示', t }));
    await afterWrite();
  });
  else if (a === 'u-undo') guard(async () => {
    const r = await api('/api/rules/add', { set: U.undo.set, value: U.undo.entry, exact: true });   // 按原样写回
    U.result = [{ k: '恢复', t: `${U.undo.set}  ${r.added.join(', ') || U.undo.entry}` }, ...r.notes.map((t) => ({ k: '提示', t }))];
    U.undo = null;
    await afterWrite();
  });
  else if (a === 'u-move') guard(async () => {
    const r = await api('/api/rules/move', { set: el.dataset.set || U.sel, entry: h, to: k });
    U.undo = null;
    U.result = [{ k: '移动', t: `${h}：${el.dataset.label || k}${r.added.length ? '' : '（目标已覆盖，未新增）'}` }, ...r.notes.map((t) => ({ k: '提示', t }))];
    await afterWrite();
  });
  else if (a === 'u-tidy') guard(async () => {
    const r = await api('/api/tidy/apply', {});
    U.result = r.notes.map((t) => ({ k: '清理', t }));
    await afterWrite();
  });
  else if (a === 'a-del') guard(async () => {
    await api('/api/rules/delete', { set: el.dataset.set, entry: h });
    U.result = [{ k: '删除', t: `${el.dataset.set}  ${h}` }];
    await afterWrite();
  });
  else if (a === 'a-merge') {
    if (!confirm(`把 ${CAT_CN[k]}类下 ${h} 的子域合并为 +.${h}？\n\n合并后 ${h} 的所有子域都会${CAT_CN[k]}，包括现在没列出的。`)) return;
    guard(async () => {
      const r = await api('/api/tidy/merge', { cat: k, parent: h });
      U.result = [...r.added.map((x) => ({ k: '写入', t: `${setName(k)}  ${x}` })), ...r.notes.map((t) => ({ k: '提示', t }))];
      await afterWrite();
    });
  }
});

function toggleWhy(kind, h) {
  A.open[kind][h] = !A.open[kind][h];
  if (kind === 'pending') S.pending.focus = h; else S.routed.focus = h;
  if (A.open[kind][h] && !A.adv[kind][h] && !A.busy[kind][h]) guard(() => runAdvice(kind, [h]));
  render();
}

// 键盘：只在焦点不在输入框时生效
document.addEventListener('keydown', (e) => {
  if ($('help').open) return;
  const tag = (e.target.tagName || '').toLowerCase();
  if (e.ctrlKey && e.key === 'Enter') {
    if (S.page === 'pending') { e.preventDefault(); guard(pendingApply); }
    else if (S.page === 'routed') { e.preventDefault(); guard(routedApply); }
    return;
  }
  if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.ctrlKey || e.altKey || e.metaKey) return;
  const move = (list, cur, d) => {
    if (!list.length) return null;
    const i = list.indexOf(cur);
    return list[i < 0 ? 0 : Math.max(0, Math.min(list.length - 1, i + d))];
  };
  if (S.page === 'pending') {
    const P = S.pending; const hosts = pendingItems().map((i) => i.host);
    if (e.key === 'ArrowDown' || e.key === 'j') { P.focus = move(hosts, P.focus, 1); render(); scrollFocus(); }
    else if (e.key === 'ArrowUp' || e.key === 'k') { P.focus = move(hosts, P.focus, -1); render(); scrollFocus(); }
    else if (P.focus && ['1', '2', '3', '4'].includes(e.key)) pendingPick(P.focus, KINDS[+e.key - 1][0]);
    else if (P.focus && e.key === '0') pendingPick(P.focus, null);
    else if (P.focus && e.key === ' ') { P.open[P.focus] = !P.open[P.focus]; render(); }
    else if (P.focus && e.key === '?') toggleWhy('pending', P.focus);
    else return;
    e.preventDefault();
  } else if (S.page === 'routed') {
    const R = S.routed; const hosts = routedRows().map((r) => r.host);
    if (e.key === 'ArrowDown' || e.key === 'j') { R.focus = move(hosts, R.focus, 1); render(); scrollFocus(); }
    else if (e.key === 'ArrowUp' || e.key === 'k') { R.focus = move(hosts, R.focus, -1); render(); scrollFocus(); }
    else if (R.focus && e.key === '3') routedMark(R.focus, 'reject');
    else if (R.focus && e.key === '2' && R.view === 'dir') routedMark(R.focus, 'direct');
    else if (R.focus && e.key === '0' && R.view === 'dir') routedMark(R.focus, 'keep');
    else if (R.focus && e.key === '?' && R.view === 'dir' && A.adv.todirect[R.focus]) toggleWhy('todirect', R.focus);
    else if (R.focus && e.key === '0' && R.view === 'sus') routedMark(R.focus, 'ok');
    else if (R.focus && e.key === '?' && R.view === 'sus') toggleWhy('suspicious', R.focus);
    else return;
    e.preventDefault();
  }
});


WebKit.init({ header: 'X-Clash-Review', onDisplay: renderStatus, onError: (m) => toast(m) });
guard(loadStatus);
guard(loadSusCount);
route();
