# 安卓端（手机）配置指南

## 先说结论

**手机端不需要安装本工具，也不需要额外的 App。**

安卓版 WARP（1.1.1.1）**自带分流能力**，在 App 内配置即可实现
「国内应用直连、国外应用走 WARP」。

本目录提供的是配套资料：

| 文件 | 用途 |
|---|---|
| `excluded-apps.txt` | 建议排除直连的国内应用包名清单（勾选时对照用） |
| `china-routes-lite.txt` | 中国大陆 IPv4 网段，用于「按 IP 段分流」或 Zero Trust |

---

## 一、安装 WARP

### 方式 1：Google Play（首选）

搜索 **1.1.1.1** 或 **Cloudflare WARP**，开发者为 **Cloudflare, Inc.**，
包名 `com.cloudflare.app`。

### 方式 2：从另一台已装的手机导出

若无法访问 Play 商店，可从已安装 WARP 的手机导出完整安装包：

```powershell
python ..\tools\export_android_app.py
```

前置条件：手机开启 **开发者选项 → USB 调试**，数据线连接电脑，并在手机上
点「允许 USB 调试」。

> ⚠️ **不要只复制 `base.apk`**。Google Play 分发的是 App Bundle（AAB），
> 装到手机后会被拆成 `base.apk` + `split_config.arm64_v8a.apk` 等多个分包。
> WARP 的 WireGuard 实现 **boringtun** 是 Rust 编写的 native 库，位于 ABI 分包里。
> 只装 `base.apk` 会缺 `.so`，表现为**能装上，但连不上 / 一开就断**。

---

## 二、方案 A：排除国内应用（推荐，零门槛）

把常用的国内 App 排除出隧道：它们的流量直连国内网络，
其余（Chrome、YouTube、X、Telegram 等）走 WARP。

### 操作步骤

1. 打开 **1.1.1.1** App
2. 点右上角 **⚙（设置）**
3. 进入 **Advanced（高级）**
4. 进入 **Connection options（连接选项）**
5. 找到 **Manage excluded apps（管理被排除的应用）**
6. 勾选需要直连的国内 App

对照 `excluded-apps.txt` 里的包名勾选，避免勾错。

> 找不到入口时用 App 内的搜索框搜 **"Exclude"** 或 **"排除"**。

### 重要：版本差异

Cloudflare 在 2025 年调整过安卓客户端：

| 版本 | 排除应用 | 排除路由 |
|---|---|---|
| 旧版 1.1.1.1（v6.x 及更早） | ✅ 有 | ✅ 有 |
| 新版 Cloudflare One Agent | ⚠️ 可能没有此入口 | ✅ 有 |

若你的 App 里**没有「排除应用」入口**，说明是新版 One Agent。
两个选择：

- **装旧版 1.1.1.1**：排除应用的功能更完整，但登录 Zero Trust 后该入口会再次消失
- **用方案 B**：按 IP 段分流（不受此限制）

> 参考：Cloudflare 社区反馈
> <https://community.cloudflare.com/t/warp-on-android-manage-excluded-apps-option-missing-suddenly/784879>

---

## 三、方案 B：按 IP 段精确分流

适合：想让分流行为与 Windows 端完全一致（按目标 IP 判断，而非按 App）。

### 操作步骤

1. **1.1.1.1** App → **⚙** → **Advanced** → **Connection options**
2. 找到 **Manage excluded routes（管理被排除的路由）**
3. 粘贴 `china-routes-lite.txt` 里的 CIDR 网段

### 关于规则文件

| 版本 | 条数 | 冗余 | 适用 |
|---|---|---|---|
| `china-routes-lite.txt` | **1849** | 6.4% | **手机推荐**，条目少、好粘贴 |
| `china_cidr.txt`（仓库根目录） | 5433 | 0% | 桌面端用，精确但手机不好操作 |

冗余含义：把零散小网段合并成大网段时，会顺带覆盖少量本不属于中国大陆的地址，
这些地址会走直连而非 WARP。lite 版约 6%，日常使用感知不到。

### Zero Trust（团队）批量下发

1849 条手动粘贴仍偏多。更好的做法是在后台统一配置：

1. 登录 <https://one.dash.cloudflare.com/>
2. **Settings → WARP Client → Device profile → 编辑**
3. **Split Tunnels** 区域切换到 **Exclude** 模式
4. 粘贴网段列表并保存

之后所有登录该团队的设备（含手机）自动同步，无需逐台录入。

---

## 四、验证分流是否生效

连上 WARP 后，用手机浏览器分别访问：

| 检测项 | 预期结果 |
|---|---|
| <https://www.ip138.com/> | 显示**国内** IP（说明走直连） |
| <https://cloudflare.com/cdn-cgi/trace> | `ip=` 为 **Cloudflare** 地址（说明走 WARP） |

也可在 App 里观察：被排除的 App 走本地网络，其余走 WARP。

---

## 五、常见问题

### 连不上 / 一开就断？

先确认安装包完整：只装了 `base.apk` 会缺 native 库。用
`tools/export_android_app.py` 整包导出，或从 Play 直接安装。

### Android Auto、投屏、NAS 连不上？

把相关 App 加入排除列表。走隧道时局域网设备不可达，这是社区反馈最多的问题。

### 银行 App 提示异常？

把银行、支付类 App 全部排除。走境外出口容易触发风控。

### 想让国内流量也加密，只是别绕远路？

WARP 的出口由 Cloudflare 就近分配，通常不慢。若确实变慢，再考虑排除。

### 手机上有另一个 VPN App？

安卓同时只允许一个 VPN 连接。1.1.1.1 与别的 VPN 会互斥，需二选一。

---

## 六、为什么手机端不做成独立 App

1. **没必要**：官方 App 已内置分流，重复造轮子且难做得更好
2. **权限限制**：安卓上修改路由/VPN 需要用户逐一授权 `BIND_VPN_SERVICE`，
   第三方工具无法绕过，体验不会比官方更好
3. **合规风险**：分发修改过的 WARP 客户端可能违反 Cloudflare 服务条款

因此本仓库把安卓端定位为「配置指南 + 规则数据」，而不是可执行程序。
