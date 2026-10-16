// 面板 UI 冒烟测试: 用 jsdom 真实执行 index.html 的 JS, 验证
// ① 无运行时错误 ② 所有元素/样式就位 ③ 关键文案渲染
const fs = require("fs");
const { JSDOM, VirtualConsole } = require("jsdom");

const html = fs.readFileSync("D:/C/Desktop/Cloudflare WARP/index.html", "utf8");
const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", (e) => errors.push("jsdomError: " + (e.message || e)));
vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));

const dom = new JSDOM(html, {
  runScripts: "dangerously",
  pretendToBeVisual: true,
  url: "http://127.0.0.1:8777/",
  virtualConsole: vc,
  beforeParse(window) {
    // 接口永不 resolve —— 只验证渲染与脚本执行, 不依赖后端
    window.fetch = () => new Promise(() => {});
    window.localStorage = { getItem: () => null, setItem: () => {} };
  },
});

setTimeout(() => {
  const d = dom.window.document;
  const $ = (id) => d.getElementById(id);
  const fail = [];
  const ok = (cond, name) => (cond ? console.log("  ✓ " + name) : (fail.push(name), console.log("  ✗ " + name)));

  console.log("== 运行时错误 ==");
  ok(errors.length === 0, "无 JS 运行时错误" + (errors.length ? " -> " + errors.join(" | ") : ""));

  console.log("== 结构 ==");
  const cards = d.querySelectorAll(".card");
  ok(cards.length >= 9, "卡片数量 " + cards.length + " (>=9)");
  ok(d.querySelectorAll(".tile").length === 4, "指标磁贴 4 块");
  ok(!!$("chart"), "图表 canvas 存在");
  ok(!!$("switch"), "分流大开关存在");
  ok(!!$("btnRescue") && !!$("btnSelfTest") && !!$("btnRestore"), "关键按钮齐全");
  ok(d.querySelectorAll("#segRoute .segbtn").length === 2, "分路切换 2 项");
  ok(d.querySelectorAll(".settings .row").length >= 7, "设置项 >= 7");

  console.log("== 出口拓扑 ==");
  ok(!!$("topoSvg"), "拓扑 SVG 存在");
  ok(d.querySelectorAll(".topo-node").length === 4, "拓扑节点 4 个 (本机/引擎/直连/WARP)");
  ok(d.querySelectorAll(".topo-epath").length === 3, "拓扑连线 3 条");
  ok(d.querySelectorAll(".topo-pt").length === 9, "流动粒子 9 个 (每边 3)");
  ok(!!$("topoDetail") && !!$("topoChips"), "详情面板与数据条存在");
  ok(d.querySelector(".topo-node.sel") && d.querySelector(".topo-node.sel").dataset.node === "engine", "默认选中分流引擎");
  const warp = d.querySelector('[data-node="warp"]');
  ok(warp && warp.querySelectorAll("text").length >= 4, "WARP 节点 >=4 行数据");

  // jsdom 的 getComputedStyle 不解析 var(), 新版直接返回字面量,
  // 所以样式相关断言一律校验原始 CSS 文本, 不做计算样式断言。
  const css = d.querySelector("style").textContent;

  console.log("== 网络体检 ==");
  ok(!!$("btnAudit"), "体检按钮存在");
  ok(!!$("auditCard") && !!$("auditBody"), "体检结果卡片存在(默认隐藏)");
  ok(d.getElementById("auditCard").classList.contains("hidden"), "体检卡片默认隐藏");
  ok(/audit-ring/.test(css) && /audit-grp/.test(css), "体检样式类齐全");
  ok(typeof dom.window.renderAudit === "function" && typeof dom.window.renderPollutionItem === "function",
     "渲染函数已导出到 window");

  console.log("== 样式 ==");
  // 注意: jsdom 的 getComputedStyle 不解析 var(), 新版直接返回字面量,
  // 所以这里校验原始 CSS 文本(变量定义 / 关键声明), 不做计算样式断言。
  ok(/--bg:\s*#0a0e14/.test(css), "暗色底变量定义");
  ok(/\.card\{[\s\S]*?border-radius:\s*var\(--r\)/.test(css), "卡片圆角 var(--r)");
  ok(/body\{[\s\S]*?radial-gradient/.test(css), "顶部光晕背景");
  const tile = d.querySelector(".tile.up .n");
  ok(tile && /rgb\(167, 139, 250\)/.test(dom.window.getComputedStyle(tile).color), "在线时长磁贴配色");

  console.log("== 文案 ==");
  ok($("heroHint").textContent.includes("国际流量"), "hero 副文案");
  ok($("mUp").textContent === "—" || /秒|分|时/.test($("mUp").textContent), "在线时长占位/格式");
  ok($("kvNetOk").textContent.length > 0, "联网状态占位");

  console.log(fail.length ? "\nFAILED: " + fail.join("; ") : "\nALL_PASS");
  process.exit(fail.length ? 1 : 0);
}, 300);
