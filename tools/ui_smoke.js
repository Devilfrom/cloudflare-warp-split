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

  console.log("== 样式 ==");
  const cs = dom.window.getComputedStyle(d.body);
  ok(/rgb\(10, 14, 20\)|#0a0e14/.test(cs.backgroundColor), "暗色底 " + cs.backgroundColor);
  const card0 = cards[0] ? dom.window.getComputedStyle(cards[0]) : null;
  ok(card0 && parseInt(card0.borderRadius) >= 12, "卡片圆角 " + (card0 && card0.borderRadius));
  const tile = d.querySelector(".tile.up .n");
  ok(tile && /rgb\(167, 139, 250\)/.test(dom.window.getComputedStyle(tile).color), "在线时长磁贴配色");
  ok(cs.backgroundImage.includes("radial-gradient"), "顶部光晕背景");

  console.log("== 文案 ==");
  ok($("heroHint").textContent.includes("国际流量"), "hero 副文案");
  ok($("mUp").textContent === "—" || /秒|分|时/.test($("mUp").textContent), "在线时长占位/格式");
  ok($("kvNetOk").textContent.length > 0, "联网状态占位");

  console.log(fail.length ? "\nFAILED: " + fail.join("; ") : "\nALL_PASS");
  process.exit(fail.length ? 1 : 0);
}, 300);
