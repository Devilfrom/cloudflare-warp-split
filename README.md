# Cloudflare WARP 智能分流控制台

> 国际流量走 Cloudflare WARP 加密出口，国内流量直连 —— 一个零依赖、可视化的 Windows 流量分流工具。

![status](https://img.shields.io/badge/python-3.8%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![platform](https://img.shields.io/badge/platform-Windows-0078D4)

---

## 一、它能做什么

- 🌍 **国际流量走 WARP**：访问境外网站 / 服务时，流量经 Cloudflare WARP 隧道加密出口。
- 🏠 **国内流量直连**：中国大陆 IP 走本地网络直连，不绕路、不掉速、不影响国内视频 / 游戏 / 网银。
- 🖥️ **可视化控制台**：浏览器打开即看状态、出口 IP、已注入规则数，一键开关。
- 🔘 **一键开关 / 一键还原**：随时启用、停用；任何异常点「一键还原」立刻回到干净网络状态。
- 🩺 **分流自检**：一键验证「国际是否走 WARP、国内是否直连」，不再靠猜。
- 🔧 **修复 IPv6**：解决 WARP 连接卡在 `happy eyeballs` 的问题（一键禁用适配器 IPv6）。
- 📡 **规则库自更新**：内置中国大陆 IPv4 段，可一键从 APNIC 刷新到最新。

---

## 二、工作原理

```
                        你的电脑
┌──────────────────────────────────────────────┐
│                                                │
│   国内流量 (中国大陆 IP)  ────►  本地网关  ──────┼──► 直连（不走 WARP）
│                                                │
│   国际流量 (其余所有 IP) ──►  Cloudflare WARP   ┼──► 加密隧道 ──► Cloudflare 出口
│                          (split-tunnel 排除)   │
└──────────────────────────────────────────────┘
```

工具把 **中国 IPv4 段**加入 WARP 的 **split-tunnel 排除列表（exclude）**：

- 命中排除列表（中国大陆）→ 直连本地网络；
- 未命中（国际）→ 走 WARP 全隧道出口。

这是 WARP 官方能力，比手工改系统路由表更干净、更易还原，且停用时一条 `tunnel ip reset` 即可瞬间清空全部自定义规则。

---

## 三、环境要求

| 项目 | 要求 |
|---|---|
| 操作系统 | Windows 10 / 11（需管理员权限） |
| Python | 3.8+（仅运行后端需要；无需任何第三方库，仅用标准库） |
| Cloudflare WARP | 已安装并可用（见下文安装步骤） |
| 浏览器 | 任意现代浏览器（Chrome / Edge / Firefox） |

> 💡 本工具**不依赖 pip 安装任何包**，WARP 也只需官方客户端即可。

---

## 四、Cloudflare WARP 安装与配置（详细）

### 1. 下载客户端

前往 Cloudflare 官方页面下载 **Cloudflare WARP（即 1.1.1.1 客户端）** 的 Windows 版本：

- 官网入口：<https://one.one.one.one/> → 点击 **Download for Windows**
- 或 Cloudflare 产品页：<https://www.cloudflare.com/products/warp/>

> 安装后默认路径为 `C:\Program Files\Cloudflare\Cloudflare WARP\`，包含：
> - `Cloudflare WARP.exe`（图形客户端）
> - `warp-cli.exe`（命令行工具，本工具依赖它）

### 2. 安装

双击下载的安装包，按向导一路「下一步」完成安装。安装后任务栏右下角会出现 Cloudflare WARP 图标。

### 3. 登录 / 激活（可选但建议）

- 打开 Cloudflare WARP 客户端，默认即为 **WARP** 模式。
- 点击登录可绑定免费账号（**WARP 基础模式免费，无需付费**；WARP+ 需要邀请密钥，非必需）。
- 即使是完全不登录的匿名状态，基础 WARP 模式通常也能连接。

### 4. 验证安装

以**管理员**身份打开 PowerShell，执行：

```powershell
# 查看版本（能输出版本号即说明安装成功）
warp-cli --version

# 若提示 "warp-cli 不是命令"，用完整路径：
& "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe" --version

# 确认文件存在
Test-Path "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
```

### 5. 首次注册（如连接报注册错误时）

若启用分流时 `warp-cli connect` 报错提示需要注册，请先在管理员 PowerShell 执行一次：

```powershell
warp-cli register
warp-cli connect
# 看到 "Status update: Connected" 即成功，随后可 warp-cli disconnect
```

> 本工具的 `run.bat` 会自动以管理员身份运行，并在启用时自动执行 `warp-cli --accept-tos connect`，多数情况下无需手动注册。

---

## 五、快速开始

1. **双击 `run.bat`**（弹出 UAC 用户账户控制时点击「是」允许提权）。
2. 脚本会自动启动本地服务，并在浏览器打开控制台：
   ```
   http://127.0.0.1:8777/
   ```
3. 点击控制台中间的**大开关 → 启用**：
   - 先连接 WARP 隧道（约 6–30 秒，偶发卡顿时自动重试）；
   - 再并发注入中国大陆 IP 规则（约 5400 条，1–2 分钟，带进度条）。
4. 启用完成后状态变为 **「分流中」**，点 **「分流自检」** 查看验证结果。

> ⚠️ 注意：**必须用 `run.bat` 启动**，不要直接双击 `index.html`。
> 直接以 `file://` 打开页面会导致前端连不上本地服务，点击按钮报「请求失败」。

---

## 六、功能说明

| 按钮 | 作用 |
|---|---|
| **大开关（启用 / 停用）** | 一键启用或停用分流。启用 = 连接 WARP + 注入国内规则；停用 = 断开 WARP + 清空规则。 |
| **刷新状态** | 立即刷新运行状态、出口 IP、规则计数。 |
| **更新中国IP列表** | 从 APNIC 重新拉取最新中国大陆 IPv4 分配，生成 `china_cidr.txt`。建议每隔一段时间点一次。 |
| **分流自检** | 只读验证：检查 WARP 是否连接、出口 IP 是否 Cloudflare、国内规则是否注入、中国 IP 是否直连、外国 IP 是否走 WARP。返回 **PASS / FAIL**。 |
| **修复IPv6** | 一键禁用 `CloudflareWARP` 虚拟适配器的 IPv6，解决连接卡在 `happy eyeballs` 的问题（可逆，可再点一次恢复）。 |
| **停用分流** | 断开 WARP 并清空分流规则，网络恢复正常。 |
| **一键还原** | 终止正在进行的操作并强制断开 + 重置，回到最干净的网络状态（紧急兜底）。 |

### 分流自检怎么看

自检会给出 5 项检查结果（绿色 ✅ / 红色 ⚠）：

- **WARP 已连接**：底层 WARP 隧道是否建立；
- **出口 IP / 归属**：你的公网出口是否落在 Cloudflare 段（说明国际流量确实走 WARP）；
- **已注入国内规则**：排除列表中的中国 IP 段数量（应为数千条）；
- **中国 IP 首跳**：访问中国 IP 的第一跳是否为你的本地网关（是 = 直连）；
- **外国 IP 首跳**：访问外国 IP 的第一跳是否为 Cloudflare（是 = 走 WARP）。

全部通过即 **PASS**，代表分流真正生效。

---

## 七、常见问题（FAQ）

### Q1. 点启用报 `Connecting ... happy eyeballs ...` 卡住 / 启用失败
这是 WARP 守护进程在同时探测 IPv4 / IPv6 端点，IPv6 探测卡住导致握手完不成。
**解决**：
1. 工具已内置「断开重连重试 4 次 + 重启 `CloudflareWARP` 服务兜底」，多数情况会自动恢复；
2. 若仍失败，点控制台的 **「修复IPv6」** 按钮禁用适配器 IPv6 后再启用；
3. 或在「网络连接 → CloudflareWARP 适配器 → 属性」取消 IPv6 勾选。

### Q2. 启用后国内某些网站变慢 / 异常？
极少数国内服务依赖 IPv6 或特定路由。可在控制台点「停用分流」立即恢复直连，或点「更新中国IP列表」刷新更全的规则。

### Q3. 前端报「请求失败 / 无法连接本地服务」
- 确认是**双击 `run.bat`** 启动，而不是直接打开 `index.html`；
- 浏览器地址栏必须是 `http://127.0.0.1:8777/`；
- 若系统 / 浏览器走了代理，把 `127.0.0.1` 加入代理「绕过列表」（或临时关闭代理）；
- 用管理员 PowerShell 运行 `netstat -ano | findstr 8777` 看端口是否真的在监听。

### Q4. 端口 8777 被占用？
关闭其它实例，或修改环境变量 `WARP_SPLIT_PORT` 换端口（同时 `run.bat` 里的端口也要一致）。

### Q5. 用的是公司 / 团队的 Zero Trust WARP？
若 WARP 被团队策略接管，`tunnel ip add-range`（split-tunnel 排除）可能被策略锁定而报错。
此时请改用团队后台的 Device Profile 配置分流，或联系管理员。个人免费 WARP 不受影响。

### Q6. 规则库是空的 / 更新失败？
`china_cidr.txt` 来自 APNIC（直连可用，无需翻墙）。若点「更新中国IP列表」失败，检查网络是否能访问 `ftp.apnic.net`，或手动下载后覆盖该文件。

---

## 八、技术细节

- **后端** `warp_split.py`：纯 Python 标准库实现的 HTTP 服务（端口 `8777`）。
  - 启用流程：`disconnect → mode warp → connect（含重试 / 服务重启兜底）→ 并发 add-range 注入 china_cidr.txt`。
  - 停用 / 还原：`disconnect + tunnel ip reset` 瞬间清空自定义排除。
- **并发注入**：使用线程池（`WARP_SPLIT_WORKERS`，默认 20）并发调用 `warp-cli`，数千条规则约 1–2 分钟完成。
- **状态持久化**：`state.json` 记录开关状态（运行时自动生成，已加入 `.gitignore`）。
- **环境变量**（可选）：
  | 变量 | 默认 | 说明 |
  |---|---|---|
  | `WARP_SPLIT_PORT` | `8777` | 本地服务端口 |
  | `WARP_SPLIT_WORKERS` | `20` | 并发注入线程数 |
  | `WARP_SPLIT_MAX` | `0`（全部） | 仅注入前 N 条（调试用） |

---

## 九、文件结构

```
Cloudflare WARP/
├── run.bat            # 启动器：自动提权 + 打开控制台
├── warp_split.py      # 后端（Python 标准库）
├── index.html         # 可视化控制台
├── china_cidr.txt     # 中国大陆 IPv4 规则库（APNIC 生成）
├── README.md          # 本文档
├── .gitignore         # 忽略运行时产物
├── state.json         # 运行时状态（自动生成，已忽略）
├── warp_split.log     # 运行日志（自动生成，已忽略）
└── __pycache__/       # Python 缓存（已忽略）
```

---

## 十、安全与隐私

- 所有流量策略都由你本机的 `warp-cli` 执行，**不会上传任何数据到第三方**。
- 国际流量经 Cloudflare WARP 出口，出口 IP 属于 Cloudflare，属正常 VPN / 隧道行为。
- 停用 / 一键还原后，所有自定义规则被清空，网络回到系统默认状态（直连）。
- 规则库仅包含公开的中国大陆 IP 分配信息（APNIC），不含任何个人数据。

---

## 十一、卸载

1. 控制台点「一键还原」确保网络干净；
2. 关闭 `run.bat` 打开的页面与后台服务（任务管理器结束 `python.exe` 进程，或 `netstat` 找到 8777 端口进程结束）；
3. 直接删除整个 `Cloudflare WARP` 文件夹即可；
4. （可选）在「应用和功能」中卸载 Cloudflare WARP 客户端。

---

## 十二、许可证与免责声明

- 本项目以 **MIT 许可证** 开源。
- Cloudflare WARP 相关商标与软件版权归 Cloudflare, Inc. 所有；本工具仅作技术集成与自动化封装，与 Cloudflare 无隶属关系。
- 使用本工具产生的任何网络行为由使用者自行负责，请遵守当地法律法规与服务条款。

---

## 十三、贡献

欢迎提 Issue / PR。仓库地址（示例）：<https://github.com/Devilfrom/cloudflare-warp-split>
