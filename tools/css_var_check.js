// CSS 变量引用校验: 解析 index.html 内联 CSS, 确认
// ① 语法可解析 ② 所有 var(--x) 在 :root 或 [data-theme=light] 中有定义
const fs = require("fs");
const csstree = require("css-tree");

const html = fs.readFileSync("D:/C/Desktop/Cloudflare WARP/index.html", "utf8");
const css = html.split("<style>")[1].split("</style>")[0];

let ast;
try {
  ast = csstree.parse(css);
  console.log("  [ok] CSS 语法可解析");
} catch (e) {
  console.log("  [FAIL] CSS 语法错误: " + e.message);
  process.exit(1);
}

// 收集 :root 与 [data-theme="light"] 规则里定义的自定义属性
const defined = new Set();
csstree.walk(ast, (node) => {
  if (node.type !== "Rule") return;
  const sel = csstree.generate(node.prelude);
  if (sel === ":root" || sel.indexOf('[data-theme="light"]') >= 0) {
    node.block.children.forEach((decl) => {
      if (decl.type === "Declaration" && decl.property.indexOf("--") === 0) {
        defined.add(decl.property);
      }
    });
  }
});
console.log("  [ok] :root / 亮色主题共定义变量 " + defined.size + " 个");

// 收集所有 var() 引用 (css-tree 的 Identifier 名已含前导 --)
// 带兜底值的 var(--x, fallback) 跳过 —— 那种写法允许未定义
const used = new Set();
csstree.walk(ast, (node) => {
  if (node.type === "Function" && node.name === "var") {
    const kids = node.children ? node.children.toArray() : [];
    if (kids.length === 1 && kids[0].type === "Identifier") used.add(kids[0].name);
  }
});
const missing = [...used].filter((u) => !defined.has(u));
console.log("  [ok] 被引用变量 " + used.size + " 个");
if (missing.length) {
  console.log("  [FAIL] 未定义的引用: " + missing.join(", "));
  process.exit(1);
}
console.log("  [ok] 所有 var() 引用均有定义");
console.log("CSS_VAR_OK");
