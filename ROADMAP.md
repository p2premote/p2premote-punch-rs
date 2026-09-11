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

### 1.2 范围外 / 已决策排除 / 暂缓项

| 工作流 | 说明 | 决策 |
|---|---|---|
| **relay 中继（SOCKS5 UDP ASSOCIATE）** | gonc 的 `-x`/`-x2` 降级路径（GONC_DESIGN §14） | **已决策：不实现**（2026-09-11）。FFI 维持 `allow_relay=true` 报错 |
| **WX1 userspace WireGuard 数据面**（boringtun + wintun/utun + 用户态 TCP 栈） | p2premote 扩展，非 gonc 范畴 | **已决策：取消**（2026-09-11）。**全平台**（Win7/Win10/Linux/macOS/Android）终态均为 "Go go120 wgonly（WG 数据面）+ Rust 打洞库" 分工 |
| **WX2 secure 层**（TLS1.3+PSK / DTLS / KCP / ShadowStream） | gonc 有；但 p2premote-punch 已删除 secure 栈并固定**明文 UDP**，主程序不需要 | **已决策：暂缓**（2026-09-11）。先满足 p2premote 项目需求，完整复刻以后再说 |
| **WX3 gonc 应用层**（netcat CLI、mux、socks5 server、文件分享、PTY shell、端口轮换、ACL） | 属于 gonc 工具本体，不属于打洞库定位 | **已决策：暂缓**（同上） |

> 决策记录见 §6（2026-09-11 三项待决策问题已全部裁定）。

## 2. 阶段计划

每个阶段的通用验收底线：**Go↔Rust 互通测试（go-interop）全通** + 既有 18 个离线 FFI
测试不回归 + `cargo build --release` 无警告级错误。

### P0 工程基础（本次启动）

- [x] 创建开发 worktree（`../p2premote-punch-rs-gonc`，分支 `dev/replicate-gonc`），master 保持稳定
- [x] 撰写 PROJECT.md / ROADMAP.md
- [ ] 调研 **Rust 打洞库**的 Win7 交付路径（分工已定：WG 数据面由 Go go120 wgonly DLL
      承担，不在本项目范围）：tier-3 target `x86_64-win7-windows-msvc` /
      `i686-win7-windows-msvc` 可用性、与 1.94.1 工具链 pin 的冲突及 std-external
      一致性影响
- [ ] 搭建 Ubuntu 18.04 验证环境（容器或实机），固化 musl `.a` + 源码集成冒烟脚本

### P1 TCP4 打洞（最大功能差距，优先级最高）✅ 2026-09-11 完成

gonc 参照：`p2p.go:1886-2391`（Auto_P2P_TCP_NAT_Traversal）+ `netx/control_*.go`。

任务：
1. ✅ `stun.rs`：`networks_for_stun` 支持 `tcp4`（TCP 传输的 StunConn 已存在，接线即可）
2. ✅ 新增 `src/easyp2p/punch_tcp.rs`：
   - 双端同时 listen（SO_REUSEADDR）+ 并发 dial（worker 上限 800）
   - **端口 +100 约定**（双方避开 STUN 通讯端口，本端与对端端口各 +100）
   - punch ACK 握手：`derive_key_for_payload(uid, ascii=false)` 8 字节二进制，双向写+读确认
   - `tcpPunchAckSelector`：双方从多条建立成功的连接中共同选中唯一一条
   - Accept 来源 IP 校验；随机源/目的端口并发拨号（TCP 版生日悖论）
   - LANProbeOnly 模式（TCP 非 easy 场景只做内网直连）
3. ✅ `candidates.rs` / `p2p.rs`：tcp 候选接线到打洞分发循环（`P2PConn` 传输枚举）
4. ✅ `udp_tunnel.rs`：`network` 参数放行 `tcp4`；本地转发层 TCP 形态
   （本地仍为 UDP 前转口，FFI 契约零变更；TCP 上以 2 字节小端长度帧承载报文，
   gonc FramedConn 语义）
5. ✅ FFI 契约：`udpTunnelInput.network` 枚举扩展为 `udp4|tcp4`（Go punchffi 已停维护，
   无需同步；`protocol/client-client` 规范待主程序接入 tcp4 时更新）
6. ✅ `lan.rs`：协商出的 tcp transport 分发到 TCP 打洞（round=0）

验收结论（2026-09-11 实测）：
- **Go↔Rust tcp4 互通**：go-interop `punch-tcp`（Go 底层 `Easy_P2P_MPWithOptions`）
  × examples `punch-tcp` —— 实网完成 tcp4 STUN（双 hard 分类）→ MQTT 加密地址交换 →
  轮同步 → 角色互补（Rust=C / Go=S）→ 8 字节二进制 punch-ACK 逐字节互通 → ping/ACK 回环
- **Rust↔Rust tcp4 FFI 全链路**：`tcp_tunnel_rust_to_rust` live test 通过
  （WG UDP 报文经本地前转 → TCP 帧 → 打洞流 → 对端回显）
- udp4 回归 live test 通过；离线 20 lib + 18 FFI 测试全绿
- 限制：单机环境只覆盖同 LAN 直连路径；easy×easy +100 同时打开与 RDP/RSP
  生日悖论路径需跨 NAT 环境验证（列入 P5 全量回归）

### P2 IPv6 与全网络矩阵 ✅ 2026-09-11 完成

任务（原计划基础上按现状调整）：
1. ✅ `resolve_stun_target` 按网络族过滤（去掉 v4 优先，Go 无跨族回退）
2. ✅ netx：v6-only UDP 绑定（Go "udp6" 等价）、`set_udp_ttl` 分派
   IP_TTL/IPV6_UNICAST_HOPS、按族空闲端口探测
3. ✅ punch_udp RDP 喷雾正确构造 v6 地址（`SocketAddr::new`）
4. ✅ `udp_tunnel` 闸口放行 `udp6`/`tcp6`；多网络探测按族分配端口
5. ✅ `networks_for_stun` 全矩阵（含 any/any6/any4/tcp/udp）原本已就绪

验收结论（2026-09-11 实测）：
- **Go↔Rust tcp6 互通**：hard×easy 组合经 **+100 端口位移 + RSP 600 随机源端口
  生日悖论** 打通，ping/ACK 双向回环（比 tcp4 首验更深的路径覆盖）
- Rust↔Rust udp6 FFI 全链路通过；tcp6 在本机 hard×hard 下按 gonc 语义正确拒绝
  （live test 预探测确定性跳过）
- 本机运营商 v6 防火墙一致改写源端口（hard），Go 侧分类为 easy 的差异源于
  运营商对不同流的行为，非实现分歧

### P3 MQTT 唤醒（MqttWait / MQTTHello）✅ 2026-09-11 完成

gonc 参照：`p2p.go:2393-2613`（`nat-exchange-wait/<uid>` topic、`SYN@tid`/`ACK@tid`、
`HelloPayload` 字符串化 `";k=v;k=v|App::Param"`）。

任务：
1. ✅ `src/easyp2p/wake.rs`：唤醒 topic 派生（`"nat-exchange-wait/" +
   deriveKeyForTopic("mqtt-topic-gonc-wait", uid)`）、HelloPayload
   `";k=v|App::Param"` 编解码（首段为随机 tid）、`mqtt_wait_session`（waitOnly +
   `SYN@` 前缀过滤 + 首选 broker 回 `ACK@tid` 15s）、`mqtt_hello_session`
   （mutual burst + `ACK@` 逐字节校验）、便捷包装 5s 延迟关会话
2. ✅ FFI 暴露按决策暂缓（主程序需要时再加）；库级 `pub` 可直接调用

验收结论（2026-09-11 实测，双向）：
- **Go wait ↔ Rust hello**：SYN/ACK 逐字节一致，tid `"kF54…|br::someparam"`
  跨实现完整携带 app/param
- **Rust wait ↔ Go hello**：同样通过，HelloPayload 解析（salt/control/app/param）正确

### P4 参数化与库 API 对齐 ✅ 2026-09-11 完成

任务：
1. ✅ 可配置项（环境变量级，FFI JSON 契约不动）：`P2PREMOTE_STUN_SERVERS`、
   `P2PREMOTE_MQTT_BROKERS`、`P2PREMOTE_PUNCH_SHORT_TTL`、
   `P2PREMOTE_PUNCH_RANDOM_PORTS`、`P2PREMOTE_TOPIC_PREFIX`
   （gonc 包变量的 Rust 等价；builder 级 API 待主程序需要时再加）
2. ✅ `api::detect_nat`（-nat-checker 等价，返回逐网络 NAT 分类）
3. ✅ `EasyP2PMPOptions` 形态保持（Bind；Multipath/回调暂无消费方）

验收结论（2026-09-11 实测）：Rust 侧 `P2PREMOTE_MQTT_BROKERS` 收敛到单 broker
（日志确认 "via 1 MQTT servers"）与 Go 默认全 broker 互通打洞成功——参数覆盖
生效且不破坏互通。

### P5 老系统交付与全量回归

任务：
1. Ubuntu 18.04：musl `.a` 与源码集成两条路径实机冒烟（P0 环境上执行）
2. Win7：按 P0 调研结论落地 **Rust 打洞库**交付物（可能需要独立工具链 profile 与
   win7 target；WG 数据面由 Go go120 wgonly DLL 承担，不在本项目范围）
3. 全回归：离线 FFI 测试 + c-tests + go-interop 全矩阵（udp4/tcp4/v6/lan/exchange）
   + 实网 live tests

验收：目标老系统冒烟通过；BUILD.md 更新交付矩阵。

### 并行 WX1：userspace WireGuard 数据面（已取消）

原计划用 boringtun + wintun/utun + 用户态 TCP 栈在 Rust 侧复刻 WG 数据面。
2026-09-11 决策取消：**全平台**终态均为 "Go go120 wgonly + Rust 打洞库" 分工，
WG 数据面在所有平台由 go120 基线模块（p2premote-wg-ffi）承担；
Rust 侧的 WG 相关 FFI（`GenerateWgKeypair` 等）维持现状（桩，由 Go 侧提供）。

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

| 目标系统 | 终态交付形态（Rust 打洞库 + Go go120 wgonly） | 现状 |
|---|---|---|
| Ubuntu 18.04 / 老 glibc Linux | 打洞：musl 静态 `.a`（`NEEDED=0`）/ 源码集成；WG：go120 wgonly | ✅ 打洞 WSL 已验证，待 18.04 实机确认 |
| Windows 7 | 打洞：win7 target 待 P0 调研；WG：go120 wgonly DLL | ⏳ P0 调研 |
| Windows 10+ / macOS | 打洞：Rust 库（源码集成）；WG：go120 wgonly DLL/dylib | ⏳ 过渡期打洞仍用 Go DLL/dylib，随 punchffi 废弃切换 |
| Android | 打洞：Rust 库（集成方式待定）；WG：go120 wgonly（aar） | ⏳ 当前全 Go aar，后续排期 |

## 5. 风险

| 风险 | 缓解 |
|---|---|
| win7 tier-3 target 维护性差、与 1.94.1 工具链 pin 冲突 | 分工已定（WG 走 Go go120 DLL，Rust 只交付打洞库）；剩余风险集中在打洞库自身的 win7 target 可用性，P0 调研出结论再承诺 |
| 公网 MQTT/STUN broker 不可控 | 测试容忍多 broker 任一可用；本地起 mosquitto 做确定性用例 |
| TCP 打洞 800 并发 dial 的 fd/内存峰值 | 压测并设上限；Linux ulimit 文档化 |
| Go/Rust 双库并存期协议漂移 | `protocol/client-client` schema 为真源，互通测试锁定（punchffi 废弃完成后此风险自然消除） |

## 6. 决策记录（2026-09-11，原待决策问题已全部裁定）

1. **"完整复刻 gonc"的边界**：只复刻**打洞核心**（easyp2p + 相关 netx 原语），
   先满足 p2premote 项目需求；secure 层与 gonc 应用层（WX2/WX3）**暂缓**，
   完整功能以后再说。
2. **全平台终态**（Win7/Win10/Linux/macOS/Android）：统一为 **"Go go120 wgonly
   （WG 数据面）+ Rust 打洞库"** 分工——WG 数据面在所有平台由 go120 基线模块
   （p2premote-wg-ffi）承担，Rust 负责全部打洞能力。Win7 需 P0 调研 win7 target；
   Android 的 Rust 打洞库集成方式后续排期；userspace WG 数据面复刻（WX1）取消。
3. **Go 端 punchffi**：**不再维护，后续废弃**。新特性（tcp4/v6 等网络枚举、唤醒等）
   只落地 Rust 与 `protocol/client-client` 规范，无需同步 Go punchffi；
   Go 侧代码（gonc-main / p2premote-punch）保留为参照与互测对手（go-interop 在
   punchffi 废弃完成前仍有效）。

## 7. 分支与交付节奏

- 开发：`dev/replicate-gonc`（worktree `D:\work\p2premote-all\p2premote-punch-rs-gonc`）
- 每阶段一个合并点：互通测试全过 → 合回 master → 更新 BUILD.md 与本文件勾选状态
- master 随时保持可被 p2premote-desktop-client path 依赖引用
