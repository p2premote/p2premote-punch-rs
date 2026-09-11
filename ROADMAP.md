# p2premote-punch-rs 复刻路线图

目标：**完整复刻 gonc 的 P2P 穿透能力**（easyp2p + 相关 netx 原语），保持与 Go 端
字节级协议互通，最终在 Win7 / Ubuntu 18.04 等老系统上完全替换 Go 库。

> 各阶段涉及的 gonc 流程细节（状态机/时序/报文格式/常量）统一参照
> **[GONC_DESIGN.md](GONC_DESIGN.md)**：P1→§10/§11（UDP/TCP 打洞状态机）、
> P2→§2/§5（网络矩阵与 STUN）、P3→§15（唤醒）、LAN 相关→§12/§13。
> 中继（GONC_DESIGN §14）按决策**不复刻**，文档仅作 gonc 设计记录。

## 1. 范围界定

### 1.1 范围内（"复刻 gonc"的主体）

打洞核心范围内的工作（原 §1.1 能力清单）已于 2026-09-11 全部完成并经 gonc 实网
互通验收，明细见各阶段小节：

| 能力 | 完成于 |
|---|---|
| TCP4 打洞（`p2p.go:1886-2391`） | P1 |
| IPv6 网络矩阵（tcp6/udp6） | P2 |
| MQTT 唤醒（MqttWait / MQTTHello） | P3 |
| 参数可配置（env 覆盖，gonc 包变量等价） | P4 |
| NAT 类型独立查询（`api::detect_nat`） | P4 |

### 1.2 范围外 / 已决策排除 / 暂缓项

| 工作流 | 说明 | 决策 |
|---|---|---|
| **relay 中继（SOCKS5 UDP ASSOCIATE）** | gonc 的 `-x`/`-x2` 降级路径（GONC_DESIGN §14） | **已决策：不实现**（2026-09-11）。FFI 维持 `allow_relay=true` 报错 |
| **WX1 userspace WireGuard 数据面**（boringtun + wintun/utun + 用户态 TCP 栈） | p2premote 扩展，非 gonc 范畴 | **已决策：取消**（2026-09-11）。**全平台**（Win7/Win10/Linux/macOS/Android）终态均为 "Go go120 wgonly（WG 数据面）+ Rust 打洞库" 分工 |
| **WX2 secure 层**（TLS1.3+PSK / DTLS / KCP / ShadowStream） | gonc 有；但 p2premote-punch 已删除 secure 栈并固定**明文 UDP**，主程序不需要 | **已决策：暂缓**（2026-09-11）。先满足 p2premote 项目需求，完整复刻以后再说 |
| **WX3 gonc 应用层**（netcat CLI、mux、socks5 server、文件分享、PTY shell、端口轮换、ACL） | 属于 gonc 工具本体，不属于打洞库定位 | **已决策：暂缓**（同上） |

> 决策记录见 §6（原三项待决策问题已全部裁定，另追加全平台动态库形态决策）。

## 2. 阶段计划

每个阶段的通用验收底线：**Go↔Rust 互通测试（go-interop）全通** + 既有 18 个离线 FFI
测试不回归 + `cargo build --release` 无警告级错误。

### P0 工程基础（本次启动）

- [x] 创建开发 worktree（`../p2premote-punch-rs-gonc`，分支 `dev/replicate-gonc`），master 保持稳定
- [x] 撰写 PROJECT.md / ROADMAP.md
- [x] 调研 **Rust 打洞库**的 Win7 交付路径（2026-09-11）：
  `x86_64-win7-windows-msvc` / `i686-win7-windows-msvc` 在 rustc target 列表中
  存在（tier-3），但 1.94.1 工具链**无预编译 std**（`rustup target add` 失败）→
  Win7 交付需 nightly + `-Z build-std` 产出自包含静态库（不走 std-external 剥离
  路线，与工具链 pin 无冲突），或等社区预编译。结论：**可行但需额外 nightly 构建
  通道**，P5 交付时按需搭建。（后注：全平台 DLL 决策后此路线已被更简单的
  1.77 stable cdylib 方案取代，见 §6 决策 3 与 P5。）
- [x] 搭建 Ubuntu 18.04 验证环境（2026-09-11）：WSL Debian + cloud-images
  bionic 18.04.6 rootfs（chroot 运行）；WSL 内安装 rustup 1.94.1 + musl target
  交叉构建链已就绪

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

### P5 老系统交付与全量回归（部分完成，2026-09-11）

任务：
1. ✅ Ubuntu 18.04 实机冒烟（2026-09-11）：WSL 交叉构建 musl 静态 interop 二进制
   （rustup 1.94.1 + musl-gcc + `RUSTFLAGS='-C linker=musl-gcc'`），在 18.04.6
   rootfs chroot 内与 Windows 上的 Go 完成 **MQTT 唤醒互通**（DNS/TLS/MQTT 全链路），
   `ldd` 确认静态链接
2. ⏳ Win7 交付物：全平台 DLL 决策后简化——1.77 工具链（最后的 Win7 兼容 stable，
   标准 tier-1 target）编译同一 cdylib 即可，无需 nightly/build-std；需 pin 依赖
   到 1.77 兼容版本。待 Win7 客户端排期时执行
3. ⏳ 全回归矩阵：2026-09-11 已覆盖 udp4/tcp4/udp6 的 Rust↔Rust FFI 全链路、
   tcp4/tcp6/唤醒的 Go↔Rust 互通、18.04 冒烟；**跨 NAT easy×easy +100 同时打开
   路径**需双机环境，待有条件时补验
4. ✅ musl `.a` 交付物重产（2026-09-11）：WSL 构建链产出 x86_64（musl-gcc）与
   aarch64（gnu 交叉 gcc + zig 链接）双架构 staticlib，经 `strip-rustlib.sh` 后
   更新 master `dist/`（40.5MB/40.6MB，22 个 ABI 符号齐全）；c-tests harness
   以 zig cc 链接全过（WSL Debian + 18.04 chroot 双环境）

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
| Ubuntu 18.04 / 老 glibc Linux | 打洞：glibc 2.27 基线 `.so` / musl 静态 `.a` / 源码集成；WG：go120 wgonly | ✅ 18.04.6 chroot 实测（dlopen 调用 + 唤醒互通 + C harness） |
| Windows 7 | 打洞：1.77 工具链编译同一 cdylib（决策 3 简化路线）；WG：go120 wgonly DLL | ⏳ 待 Win7 客户端排期 |
| Windows 10+ / macOS | 打洞：Rust cdylib（win .dll 已就绪 / mac .dylib 待产出）；WG：go120 wgonly DLL/dylib | ⏳ 过渡期打洞仍用 Go DLL/dylib，随客户端切换 |
| Android | 打洞：Rust 库（集成方式待定）；WG：go120 wgonly（aar） | ⏳ 当前全 Go aar，后续排期 |

## 5. 风险

| 风险 | 缓解 |
|---|---|
| Win7 交付（1.77 工具链路线）：EOL 编译器无安全补丁、依赖需冻结在 1.77 兼容版本 | 仅作 Win7 专用旁路通道，不影响主线；执行时先验证依赖树可 pin |
| 公网 MQTT/STUN broker 不可控 | 测试容忍多 broker 任一可用；本地起 mosquitto 做确定性用例 |
| TCP 打洞 800 并发 dial 的 fd/内存峰值 | 压测并设上限；Linux ulimit 文档化 |
| Go/Rust 双库并存期协议漂移 | `protocol/client-client` schema 为真源，互通测试锁定（punchffi 废弃完成后此风险自然消除） |

## 6. 决策记录（2026-09-11，原待决策问题已全部裁定）

1. **"完整复刻 gonc"的边界**：只复刻**打洞核心**（easyp2p + 相关 netx 原语），
   先满足 p2premote 项目需求；secure 层与 gonc 应用层（WX2/WX3）**暂缓**，
   完整功能以后再说。
2. **全平台终态**（Win7/Win10/Linux/macOS/Android）：统一为 **"Go go120 wgonly
   （WG 数据面）+ Rust 打洞库"** 分工——WG 数据面在所有平台由 go120 基线模块
   （p2premote-wg-ffi）承担，Rust 负责全部打洞能力。Win7 交付路线已定（见决策 3）；
   Android 的 Rust 打洞库集成方式后续排期；userspace WG 数据面复刻（WX1）取消。
3. **全平台动态库形态**（2026-09-11 追加）：punch-rs 所有平台统一 cdylib + C ABI
   交付（`dist/windows-x86_64/*.dll`、`dist/linux-x86_64-gnu.2.27/*.so`），主客户
   端 C 接口调用。工具链解耦；Win7 交付简化为 1.77 工具链编译同一 cdylib。
   源码集成与 std-external 静态库降为备选。
4. **Go 端 punchffi**：**不再维护，后续废弃**。新特性（tcp4/v6 等网络枚举、唤醒等）
   只落地 Rust 与 `protocol/client-client` 规范，无需同步 Go punchffi；
   Go 侧代码（gonc-main / p2premote-punch）保留为参照与互测对手（go-interop 在
   punchffi 废弃完成前仍有效）。

## 7. 分支与交付节奏

- 开发：`dev/replicate-gonc`（worktree `D:\work\p2premote-all\p2premote-punch-rs-gonc`）
- 每阶段一个合并点：互通测试全过 → 合回 master → 更新 BUILD.md 与本文件勾选状态
- master 随时保持可被 p2premote-desktop-client path 依赖引用
