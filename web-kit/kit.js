'use strict';
/* web-kit：本仓库本地网页工具共用的、与页面内容无关的部分（见本目录 README）。
   一、配色：四套，取值与名字来自 schemes.json（webkit.py 送出本文件时替换下面的占位，不异步取，不闪）。
   二、显示设置面板：配色、英文字体、英文粗细、灰字亮度；当前值（localStorage）/ 设为默认（/api/prefs）/ 还原出厂 三层。
   三、本机显示参数：系统分辨率与缩放由后端 /api/display 读，反推浏览器缩放；高分辨率低缩放时整体放大。
   四、心跳：页面开着时每 60 秒 GET /api/ping，服务据此判断有没有人在用（空闲退出）。
   用法：<head> 里 <script src="/kit/kit.js" data-prefix="cr"></script>（尽早施加配色）；页面脚本里 WebKit.init({...})。
   页面内容、api()/guard()/toast() 不在这里，由各工具自己写。 */
(function () {
  const DATA = /*@@KIT_DATA@@*/null;
  const script = document.currentScript;
  const PREFIX = (script && script.dataset.prefix) || 'kit';
  const KEY_DISP = PREFIX + '-display';
  const KEY_THEME = PREFIX + '-theme';     // 旧版只存深浅，读它做兼容
  const SCHEMES = DATA.schemes;
  const FACTORY = { ...DATA.factory };
  const LEVEL = ['默认', '+1', '+2', '+3'];
  const pct = (x) => `${Math.round(x * 100)}%`;
  const read = (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } };
  const schemeOf = (id) => SCHEMES.find((s) => s.id === id) || schemeOf(FACTORY.scheme);

  // ---------------- 配色 ----------------
  // 没存过配色、但旧版存过「浅」的浏览器，取出厂配色同一对里的浅色那一套，保持原来的样子
  const LEGACY = (() => {
    const f = schemeOf(FACTORY.scheme);
    return read(KEY_THEME) === 'light' && f.theme !== 'light' ? f.pair : f.id;
  })();
  function setScheme(id) {
    const s = schemeOf(id);
    document.documentElement.dataset.scheme = s.id;
    document.documentElement.dataset.theme = s.theme;
  }
  let disp = { ...FACTORY, scheme: LEGACY };
  let saved = false;   // 本浏览器是否存过自己的设置
  try { const s = read(KEY_DISP); if (s) { disp = { ...FACTORY, scheme: LEGACY, ...JSON.parse(s) }; saved = true; } } catch (e) { /* 忽略 */ }
  setScheme(disp.scheme);          // 在 <head> 里执行：页面画出来之前就是这套配色
  let dflt = { ...FACTORY };

  const O = { header: 'X-Kit', settings: 'settings', theme: 'theme', onDisplay: () => {}, onError: (m) => console.error(m), ping: 60000 };

  async function req(path, body) {
    const opt = body === undefined ? {} : { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', [O.header]: '1' } };
    const r = await fetch(path, opt);
    let j = {};
    try { j = await r.json(); } catch (e) { /* 非 JSON */ }
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    return j;
  }
  const guard = async (fn) => { try { await fn(); } catch (e) { O.onError(e.message); } };
  const $ = (id) => document.getElementById(id);

  // ---------------- 显示设置 ----------------
  const style = document.createElement('style');
  document.head.appendChild(style);
  const same = (a, b) => a.scheme === b.scheme && a.font === b.font && +a.weight === +b.weight && +a.ink === +b.ink;
  function apply(save = true) {
    const sc = schemeOf(disp.scheme);
    disp.scheme = sc.id;
    setScheme(sc.id);
    const [i2, i3] = sc.ink[disp.ink] || sc.ink[0];
    style.textContent = `:root { --sans: '${String(disp.font).replace(/'/g, '')}', 'Microsoft YaHei UI', 'Microsoft YaHei', sans-serif; }
      body { font-weight: ${+disp.weight || 400}; }
      ${+disp.ink ? `:root[data-scheme="${sc.id}"] { --ink2: ${i2}; --ink3: ${i3}; }` : ''}`;
    if (save) { try { localStorage.setItem(KEY_DISP, JSON.stringify(disp)); saved = true; } catch (e) { /* 忽略 */ } }
    const p = $('disp');
    if (!p) return;
    p.querySelectorAll('.sch').forEach((b) => { const on = b.dataset.scheme === sc.id; b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); });
    $('disp-f').value = disp.font; $('disp-w').value = disp.weight; $('disp-c').value = disp.ink;
    $('disp-wo').textContent = disp.weight; $('disp-co').textContent = LEVEL[disp.ink];
    $('disp-def').textContent = same(dflt, FACTORY) ? '默认：出厂值'
      : `默认：${schemeOf(dflt.scheme).name} / ${dflt.font} / ${dflt.weight} / 灰字${LEVEL[dflt.ink]}`;
    $('disp-setdef').disabled = same(disp, dflt);
  }
  function buildPanel() {
    const box = document.createElement('div');
    box.className = 'disp hidden'; box.id = 'disp';
    const pair = SCHEMES.filter((s) => s.theme === 'dark').map((s) => `${s.name}↔${schemeOf(s.pair).name}`).join('，');
    box.innerHTML = `<div style="display:flex;align-items:center;gap:4px"><span style="font-weight:600;color:var(--ink)">显示设置</span><span class="grow"></span>
        <button class="btn btn-ghost btn-sm" id="disp-reset">恢复默认</button><button class="btn btn-sm" id="disp-setdef">设为默认</button></div>
      <div class="schemes" role="group" aria-label="配色">${SCHEMES.map((s) => `<button class="sch" data-scheme="${s.id}" aria-pressed="false">
        <span class="sw" aria-hidden="true">${s.swatch.map((c) => `<i style="background:${c}"></i>`).join('')}</span>
        <span class="nm">${s.name}<span class="muted" style="margin-left:6px;font-size:11px">${s.theme === 'dark' ? '深' : '浅'}</span></span><span class="ds">${s.desc}</span></button>`).join('')}</div>
      <label>英文字体<select id="disp-f">${DATA.fonts.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select><span></span></label>
      <label>英文粗细<input id="disp-w" type="range" min="${DATA.weight[0]}" max="${DATA.weight[1]}" step="10"><output id="disp-wo"></output></label>
      <label>灰字亮度<input id="disp-c" type="range" min="0" max="3" step="1"><output id="disp-co"></output></label>
      <span class="muted">顶栏的深浅按钮在同一对里切换（${pair}）。字体与粗细只改英文：粗细在 500 以内时中文仍是常规体。</span>
      <div style="display:flex;align-items:center;gap:8px;border-top:1px solid var(--line2);padding-top:8px"><span class="muted grow" id="disp-def"></span>
        <button class="link" id="disp-factory">还原出厂</button></div>`;
    document.body.appendChild(box);
    box.addEventListener('input', () => {
      disp = { ...disp, font: $('disp-f').value, weight: +$('disp-w').value, ink: +$('disp-c').value };
      apply();
    });
    box.addEventListener('click', (e) => {
      const b = e.target.closest('.sch'); if (!b) return;
      disp = { ...disp, scheme: b.dataset.scheme }; apply();
    });
    $('disp-reset').onclick = () => { disp = { ...dflt }; apply(); };
    $('disp-setdef').onclick = () => guard(async () => {
      const r = await req('/api/prefs', { display: disp });
      dflt = { ...FACTORY, ...r.display }; apply();
    });
    $('disp-factory').onclick = () => guard(async () => {
      if (!confirm('把默认值还原成出厂值，并把当前显示也改回出厂值？')) return;
      await req('/api/prefs', { display: null });
      dflt = { ...FACTORY }; disp = { ...FACTORY }; apply();
    });
    const btn = $(O.settings);
    btn.onclick = (e) => { e.stopPropagation(); box.classList.toggle('hidden'); };
    document.addEventListener('click', (e) => { if (!box.contains(e.target) && !e.target.closest('#' + O.settings)) box.classList.add('hidden'); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') box.classList.add('hidden'); });
    // 顶栏深浅按钮：在同一对里切换
    $(O.theme).onclick = () => { disp = { ...disp, scheme: schemeOf(disp.scheme).pair }; apply(); };
    apply(false);
    // 后端保存的默认值；本浏览器没存过自己的设置时直接用它（旧的默认值文件没有配色一项：按旧的深浅取）
    req('/api/prefs').then((r) => {
      if (r.display) dflt = { ...FACTORY, scheme: LEGACY, ...r.display };
      if (!saved) disp = { ...dflt };
      apply(saved);
    }).catch(() => {});
  }

  // ---------------- 本机显示参数（ui-style 第 3 节「本机硬件参数 · 显示」）----------------
  // 页面里的 devicePixelRatio = 系统缩放 × 浏览器缩放，两者分不开。系统的分辨率与缩放由后端 /api/display
  // 直接向 Windows 读，浏览器缩放 = devicePixelRatio ÷ 系统缩放；不是 100% 时由页面提示 Ctrl+0 复原（display.zoomOff）。
  // 高分辨率配低系统缩放（屏幕 CSS 宽度 > 2200，如 4K@100%）时整体放大，上限 1.35 倍，只看系统参数。
  // 标签页在后台或窗口不可见时，浏览器报 screen 0×0、缩放 1，这组值无效：不采用，等可见时再测。
  const display = { scale: 1, sys: null, text: '', zoomOff: 0 };
  let dprWatch = null;
  async function loadDisplay() {
    try { display.sys = (await req('/api/display')).screens || null; } catch (e) { display.sys = null; }
    adaptDisplay();
  }
  function pickScreen() {
    const s = display.sys;
    if (!s || !s.length) return null;
    if (s.length === 1) return s[0];
    const r = screen.width / screen.height;   // 多屏：浏览器缩放不改变宽高比，按它找当前所在的屏，比不出来取主屏
    const byRatio = s.filter((m) => Math.abs(m.physical[0] / m.physical[1] - r) < 0.01);
    return byRatio.length === 1 ? byRatio[0] : (s.find((m) => m.primary) || s[0]);
  }
  function adaptDisplay() {
    const dpr = window.devicePixelRatio || 1;
    if (document.hidden || !screen.width || !screen.height) {
      display.text = display.text || '显示参数检测中（窗口不可见）';
      return;
    }
    const m = pickScreen();
    const cssW = m ? m.css[0] : screen.width;
    const scale = cssW > 2200 ? Math.min(1.35, Math.round((cssW / 1920) * 20) / 20) : 1;
    display.scale = scale;
    if (m) {
      const zoom = dpr / m.scale;
      display.zoomOff = Math.abs(zoom - 1) > 0.02 ? zoom : 0;
      display.text = `屏幕 ${m.physical[0]}×${m.physical[1]} · 系统缩放 ${pct(m.scale)} · 浏览器缩放 ${pct(zoom)} · 界面 ×${scale}`;
    } else {
      display.zoomOff = 0;
      display.text = `屏幕 ${Math.round(screen.width * dpr)}×${Math.round(screen.height * dpr)} · 缩放 ${pct(dpr)}（未读到系统参数，含浏览器缩放）· 界面 ×${scale}`;
    }
    document.body.style.zoom = scale === 1 ? '' : String(scale);
    if (dprWatch) dprWatch.removeEventListener('change', adaptDisplay);
    dprWatch = matchMedia(`(resolution: ${dpr}dppx)`);
    dprWatch.addEventListener('change', adaptDisplay);
    O.onDisplay();
  }

  /* 页面脚本调用一次。选项：
     header     写操作的自定义请求头名（如 'X-Clash-Review'），后端据此拒绝跨站请求
     settings   打开显示设置面板的按钮 id（默认 'settings'）；theme 深浅切换按钮 id（默认 'theme'）
     onDisplay  显示参数变了时调用（页面据 WebKit.display.zoomOff / .text 重画状态栏）
     onError    出错时调用，参数是一句话（页面用自己的 toast）
     ping       心跳间隔毫秒，默认 60000；0 表示不发 */
  function init(opts) {
    Object.assign(O, opts || {});
    buildPanel();
    document.addEventListener('visibilitychange', adaptDisplay);
    window.addEventListener('resize', adaptDisplay);
    adaptDisplay();
    loadDisplay();
    if (O.ping) setInterval(() => { fetch('/api/ping').catch(() => { /* 服务已退出 */ }); }, O.ping);
  }

  window.WebKit = { init, display, schemes: SCHEMES, schemeOf, get settings() { return { ...disp }; } };
})();
