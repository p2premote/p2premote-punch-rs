# p2premote-punch-rs 复刻路线图

目标：**完整复刻 gonc 的 P2P 穿透能力**（easyp2p + 相关 netx 原语），保持与 Go 端
字节级协议互通，最终在 Win7 / Ubuntu 18.04 等老系统上完全替换 Go 库。

> 各阶段涉及的 gonc 流程细节（状态机/时序/报文格式/常量）统一参照
> **[GONC_DESIGN.md](GONC_DESIGN.md)**：P1→§10/§11（UDP/TCP 打洞状态机）、
> P2→§2/§5（网络矩阵与 STUN）、P3→§15（唤醒）、LAN 相关→§12/§13。
> 中继（GONC_DESIGN §14）按决策**不复刻**，文档仅作 gonc 设计记录。

## 1. 范围界定

### 1.1 范围内（"复刻 gonc"的主体）

| 能力 | gonc 参照 | 现状 |
|---|---|---|
| TCP4 打洞 | `easyp2p/p2p.go:1886-2391` | ❌ 未实现 |
| IPv6 网络矩阵（tcp6 / udp6 / "any"） | `easyp2p/stun.go:29-46` | ❌ 仅 udp4 |
| MQTT 唤醒（MqttWait / MQTTHello） | `easyp2p/p2p.go:2393-2613` | ❌ 未实现 |
| 参数可配置（STUN/broker/TTL/端口数/topic） | gonc 导出变量 | ❌ 硬编码 |
| NAT 类型独立查询（-nat-checker 等价入口） | `DetectNATAddressInfo` | ⚠️ 仅内部使用 |

### 1.2 范围外 / 明确排除 / 并行工作流

| 工作流 | 说明 | 决策 |
|---|---|---|
| **relay 中继（SOCKS5 UDP ASSOCIATE）** | gonc 的 `-x`/`-x2` 降级路径（GONC_DESIGN §14） | **已决策：不实现**（2026-09-11）。FFI 维持 `allow_relay=true` 报错 |
| **WX1 userspace WireGuard 数据面**（boringtun + wintun/utun + 用户态 TCP 栈） | **不属于 gonc 复刻**（是 p2premote 扩展），但属于"完全替换 Go 库"的必要条件（Win/Mac 侧） | 并行推进，独立排期 |
| **WX2 secure 层**（TLS1.3+PSK / DTLS / KCP / ShadowStream） | gonc 有；但 p2premote-punch 已删除 secure 栈并固定**明文 UDP**，主程序不需要 | 默认**不做**，仅当要做独立 gonc CLI 替代品时启动 |
| **WX3 gonc 应用层**（netcat CLI、mux、socks5 server、文件分享、PTY shell、端口轮换、ACL） | 属于 gonc 工具本体，不属于打洞库定位 | 默认**不做** |

> 待决策问题见 §6。若用户确认"完整复刻"仅指打洞核心，则 WX2/WX3 永久搁置。

## 2. 阶段计划

每个阶段的通用验收底线：**Go↔Rust 互通测试（go-interop）全通** + 既有 18 个离线 FFI
测试不回归 + `cargo build --release` 无警告级错误。

### P0 工程基础（本次启动）

- [x] 创建开发 worktree（`../p2premote-punch-rs-gonc`，分支 `dev/replicate-gonc`），master 保持稳定
- [x] 撰写 PROJECT.md / ROADMAP.md
- [ ] 调研 Win7 的 Rust 交付路径：tier-3 target `x86_64-win7-windows-msvc` / `i686-win7-windows-msvc`
      可用性、与 1.94.1 工具链 pin 的冲突及 std-external 一致性影响
- [ ] 搭建 Ubuntu 18.04 验证环境（容器或实机），固化 musl `.a` + 源码集成冒烟脚本

### P1 TCP4 打洞（最大功能差距，优先级最高）

gonc 参照：`p2p.go:1886-2391`（Auto_P2P_TCP_NAT_Traversal）+ `netx/control_*.go`。

任务：
1. `stun.rs`：`networks_for_stun` 支持 `tcp4`（TCP 传输的 StunConn 已存在，接线即可）
2. 新增 `src/easyp2p/punch_tcp.rs`：
   - 双端同时 listen（SO_REUSEADDR）+ 并发 dial（worker 上限 800）
   - **端口 +100 约定**（双方避开 STUN 通讯端口，本端与对端端口各 +100）
   - punch ACK 握手：`derive_key_for_payload(uid, ascii=false)` 8 字节二进制，双向写+读确认
   - `tcpPunchAckSelector`：双方从多条建立成功的连接中共同选中唯一一条
   - Accept 来源 IP 校验；随机源/目的端口并发拨号（TCP 版生日悖论）
   - LANProbeOnly 模式（TCP 非 easy 场景只做内网直连）
3. `candidates.rs` / `p2p.rs`：tcp 候选接线到打洞分发循环（排序、过滤规则已有基础）
4. `udp_tunnel.rs`：`network` 参数放行 `tcp4`；本地转发层增加 TCP 形态
   （本地 TCP listen ↔ P2P TCP 连接的管道，复用句柄/转发框架）
5. FFI 契约：`udpTunnelInput.network` 扩展枚举，与 Go 端 / `protocol/client-client` 规范同步

验收：Rust↔Rust、Go↔Rust 的 tcp4 打洞 + 本地转发全链路互通；easy×easy、
easy×hard 组合下连通。

### P2 IPv6 与全网络矩阵

任务：
1. `networks_for_stun("any")` → `[tcp6, tcp4, udp4]`（对齐 gonc）；显式 `udp6` 支持
2. v6 socket 绑定、本机地址枚举（`if-addrs` 已有，补 v6 过滤与 scope 处理）
3. STUN XOR-MAPPED-ADDRESS v6 解析已有；补 v6 NAT 分类与候选构造路径
4. LAN 判定的同 /64 规则已有，接线验证

验收：v6 环境（本机 v6 + 公网 v6）Rust↔Go 互通；`any` 模式下网络优选顺序
tcp6 > tcp4 > udp4 生效。

### P3 MQTT 唤醒（MqttWait / MQTTHello）

gonc 参照：`p2p.go:2393-2613`（`nat-exchange-wait/<uid>` topic、`SYN@tid`/`ACK@tid`、
`HelloPayload` 字符串化 `";k=v;k=v|App::Param"`）。

任务：wait/hello 原语 + topic salt 贯通（`Mqtt_ensure_ready` 流程）；
按主程序需要决定是否暴露到 FFI。

验收：与 Go CLI `-mqtt-wait` / `-mqtt-hello` 互通唤醒后打洞。

### P4 参数化与库 API 对齐

任务：
1. 可配置项：STUN 服务器列表、MQTT broker 列表、`PunchingShortTTL`、
   `PunchingRandomPortCount`、`TopicExchange`（builder / 环境变量两级）
2. `DetectNATAddressInfo` 等价入口（Rust api + 可选 FFI），对齐 gonc `-nat-checker`
3. 复核 `EasyP2PMPOptions` 形态的选项对象（Bind / Multipath / 回调；RelayConn 按决策不实现）

验收：同参数下与 Go 行为一致；参数覆盖经 interop 测试验证。

### P5 老系统交付与全量回归

任务：
1. Ubuntu 18.04：musl `.a` 与源码集成两条路径实机冒烟（P0 环境上执行）
2. Win7：按 P0 调研结论落地交付物（可能需要独立工具链 profile 与 win7 target；
   若决策为 Win7 继续用 Go go120 wgonly DLL，则本项缩小为打洞库验证）
3. 全回归：离线 FFI 测试 + c-tests + go-interop 全矩阵（udp4/tcp4/v6/lan/exchange）
   + 实网 live tests

验收：目标老系统冒烟通过；BUILD.md 更新交付矩阵。

### 并行 WX1：userspace WireGuard 数据面（独立于 gonc 复刻）

参照 `p2premote-punch/punchffi/subnet_router_windows.go`（wintun + wireguard-go + gVisor）
与 `userspace_wg_darwin.go`（utun）。Rust 技术选型候选：boringtun + wintun/utun +
smoltcp（或自评估 gVisor 等价物）；`GenerateWgKeypair` 用 x25519 实现先行补齐。
验收标准对齐 Go 侧 FFI 语义（session 限制、状态回传字段）。

## 3. 测试与验收策略（贯穿所有阶段）

| 层 | 手段 | 说明 |
|---|---|---|
| 密码学/协议 | `crypto.rs` 内置 Go 交叉验证向量 | 新增派生逻辑必须先加 Go 向量 |
| 离线契约 | `tests/ffi_abi.rs` | 每个新 FFI 字段/枚举补用例 |
| 互通 | `go-interop/` + `examples/interop.rs` | **每阶段必须全通**，Go 原生 easyp2p ↔ Rust |
| C 宿主 | `c-tests/` | 链接与 JSON 契约冒烟 |
| 实网 | `easyp2p/live_tests.rs`（`#[ignore]`） | 手动跑，覆盖 NAT 组合矩阵 |
| 老系统 | P0 搭建的环境 | P5 全量冒烟 |

## 4. 老系统兼容矩阵

| 目标系统 | 交付形态 | 现状 |
|---|---|---|
| Ubuntu 18.04 / 老 glibc Linux | musl 静态 `.a`（`NEEDED=0`）/ 源码集成 | ✅ WSL 已验证，待 18.04 实机确认 |
| Windows 7 | 待定（win7 tier-3 target 或维持 Go DLL 分工） | ⏳ P0 调研 |
| Windows 10+ | 源码集成（现走 master） | ✅ |
| Android | Go aar（不在本路线图） | — |

## 5. 风险

| 风险 | 缓解 |
|---|---|
| win7 tier-3 target 维护性差、与 1.94.1 工具链 pin 冲突 | P0 先调研出结论再承诺；保留"Win7 用 Go go120 wgonly DLL"的分工退路 |
| 公网 MQTT/STUN broker 不可控 | 测试容忍多 broker 任一可用；本地起 mosquitto 做确定性用例 |
| TCP 打洞 800 并发 dial 的 fd/内存峰值 | 压测并设上限；Linux ulimit 文档化 |
| Go/Rust 双库并存期协议漂移 | `protocol/client-client` schema 为真源，互通测试锁定 |
| WX1 用户态 TCP 栈选型（smoltcp vs 其他） | 先做 spike 对比吞吐/语义，再定 |

## 6. 待决策问题（影响排期，需确认）

1. **"完整复刻 gonc"的边界**：仅打洞核心（easyp2p + netx，推荐），还是包含 secure 层
   与 CLI 工具本体（WX2/WX3）？
2. **Win7 终态**：Rust 全量替换（含 WX1 WG 数据面），还是 Win7 长期维持
   "Go go120 wgonly DLL + Rust 打洞库"分工？
3. **FFI 契约演进方式**：tcp4 等新枚举是否同步推进 Go 端 punchffi 与
   `protocol/client-client` 规范升级（三端对齐节奏）？

## 7. 分支与交付节奏

- 开发：`dev/replicate-gonc`（worktree `D:\work\p2premote-all\p2premote-punch-rs-gonc`）
- 每阶段一个合并点：互通测试全过 → 合回 master → 更新 BUILD.md 与本文件勾选状态
- master 随时保持可被 p2premote-desktop-client path 依赖引用
