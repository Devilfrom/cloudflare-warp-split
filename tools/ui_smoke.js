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
    // 接口默认永不 resolve —— 只验证渲染与脚本执行, 不依赖后端。
    // /api/hosts 例外: 返回空列表, 让域名卡片走完"空列表占位文案"这条渲染路径。
    window.fetch = (url) => {
      if (String(url).includes("/api/hosts")) {
        return Promise.resolve({
          json: () => Promise.resolve({
            hosts: [], daemon_hosts: [], applying: false,
            enabled: false, preset_count: 28,
          }),
        });
      }
      return new Promise(() => {});
    };
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
  ok(cards.length >= 11, "卡片数量 " + cards.length + " (>=11)");
  ok(["mCn", "mIntl", "mSpd", "mUp"].every((id) => !!$(id)), "指标磁贴 4 块");
  ok(d.querySelectorAll("#tunnelCard .tile").length === 4, "隧道磁贴 4 块");
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

  console.log("== 面板版本自动刷新 ==");
  ok(!!$("panelUpdateBar"), "新版本提示条存在(默认隐藏)");
  ok(d.getElementById("panelUpdateBar").classList.contains("hidden"), "提示条默认隐藏");
  ok(/panel-update-bar/.test(css), "提示条样式齐全");
  ok(typeof dom.window.checkPanelVer === "function", "checkPanelVer 函数已导出");
  ok(typeof dom.window.__PANEL_VER__ === "string" && /^\d+\.\d+\.\d+$/.test(dom.window.__PANEL_VER__),
     "__PANEL_VER__ 常量: " + dom.window.__PANEL_VER__);
  ok(/warp-split-res v\d+\.\d+\.\d+/.test(html), "HTML 头部带资源版本标记");
  // 版本徽标: header 里常驻显示, 用户一眼可辨当前页面新旧
  ok(!!$("verText"), "版本徽标元素存在");
  ok(/\.verchip/.test(css) && /\.verchip b\{/.test(css), "版本徽标样式齐全");
  ok($("verText").textContent === "v" + dom.window.__PANEL_VER__,
     "版本徽标已填充: " + $("verText").textContent);
  // 版本一致 -> 不提示; 版本更新 -> 显示提示条
  dom.window.checkPanelVer(dom.window.__PANEL_VER__);
  ok(d.getElementById("panelUpdateBar").classList.contains("hidden"), "版本一致时不弹提示");
  dom.window.checkPanelVer("9.9.9");
  ok(!d.getElementById("panelUpdateBar").classList.contains("hidden"), "版本过旧时弹出提示条");
  ok(/9\.9\.9/.test(d.getElementById("panelUpdateBar").textContent), "提示条含新版本号");

  console.log("== 隧道实时状态 ==");
  ok(!!$("tunnelCard"), "隧道状态卡片存在");
  ok(d.getElementById("tunnelCard").style.display === "none", "隧道卡片默认隐藏(未连接不占位)");
  ok(["tsLat","tsLoss","tsSent","tsRecv","tsProto","tsEp","tsColo","tsTls","tsPq","tsHs"]
     .every((id) => !!$(id)), "隧道卡片 10 个字段元素齐全");
  ok(typeof dom.window.loadTunnelStats === "function" && typeof dom.window.fmtBytes === "function",
     "loadTunnelStats / fmtBytes 已导出到 window");
  // fmtBytes 单测: B/kB/MB/GB 四档 + null 占位
  const fb = dom.window.fmtBytes;
  ok(fb(null) === "—" && fb(512) === "512 B" && fb(2048) === "2.0 kB" &&
     fb(5 * 1048576) === "5.0 MB" && fb(3 * 1073741824) === "3.00 GB", "fmtBytes 各档格式正确");

  console.log("== 域名级分流 ==");
  ok(!!$("hostList") && !!$("hostInput"), "域名卡片列表与输入框存在");
  ok(!!$("btnHostAdd") && !!$("btnHostPreset") && !!$("btnHostClear"), "域名卡片三个按钮齐全");
  ok(typeof dom.window.loadHosts === "function" && typeof dom.window.hostAction === "function",
     "loadHosts / hostAction 已导出到 window");
  ok(/\.hostrow/.test(css) && /\.hostrow \.tag\.ok/.test(css), "域名行样式齐全");
  // 空列表时给出引导文案(不是空白)
  ok($("hostList").textContent.length > 0, "空列表有占位引导文案");

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
