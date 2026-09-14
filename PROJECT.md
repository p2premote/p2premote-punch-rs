# p2premote-punch-rs 项目说明

gonc（Go 版 NAT 穿透 / P2P 打洞库）的 Rust 复刻，作为 p2premote 主程序的打洞传输层。
**长期目标：完整复刻 gonc 的 P2P 穿透能力（中继模式按决策不实现），最终替换 Go 侧 punchffi 库。**

| 仓库 | 角色 |
|---|---|
| `D:\work\p2premote-all\3rdsrc\gonc-main\` | 上游参照（gonc v2.6.9，Go 1.25），只读 |
| `D:\work\p2premote-all\p2premote-punch\` | 接口蓝本（gonc fork + punchffi C ABI + 客户端间协议规范） |
| `D:\work\p2premote-all\p2premote-punch-rs\` | 本项目（Rust 实现），master 分支为稳定交付线 |

## 1. 背景与动机：为什么用 Rust 重写

- gonc 上游要求 **Go 1.25**，编译出的二进制无法在 **Win7、Ubuntu 18.04** 等老旧系统上运行，
  而 p2premote 需要支持这些老系统。
- Go 侧原交付物是 c-archive/c-shared（punchffi），与宿主静态链接存在 Go 运行时与 musl
  组合的运行期问题（见 BUILD.md 背景说明）。
- Rust 走 **musl 静态链接**（Linux 侧 `NEEDED = 0`，WSL 已实测），从根本上摆脱 glibc/Go
  运行时基线，天然兼容老系统；同时通过**字节级协议兼容**与 Go 端互通（已验证
  Go↔Rust 全链路打洞）。

> 兼容性说明：`rust-toolchain.toml` 锁定 Rust **1.77.2**，与 p2premote-desktop-client
> 一致——1.77 是最后一个官方支持 Windows 7 的 stable，客户端锁它正是为了 Win7。
> 本库统一同一工具链后，**同一份 Windows DLL 覆盖 Win10 与 Win7，无需任何独立
> 交付通道**。老系统 Linux 侧由 glibc 2.27 基线 `.so` / musl 静态 `.a` 覆盖。

## 2. 三个仓库的关系

```
gonc-main (上游 v2.6.9, Go 1.25)
   │  fork + p2premote 扩展（LAN/Internet 联合穿越、明文 UDP、WG 数据面、go120 基线）
   ▼
p2premote-punch (Go)
   ├── easyp2p/          打洞核心（本项目的主要移植对象）
   ├── punchffi/         桌面 C ABI（本项目 FFI 接口 1:1 镜像的蓝本）
   ├── protocol/client-client/   客户端间协议规范（Go/Rust/Android 三端对齐的"协议真源"）
   └── mobile/           Android aar（暂不迁移）
   │  Rust 重写（easyp2p + punchffi 子集），与 Go 端字节级协议互通
   ▼
p2premote-punch-rs (本项目)
   │  源码 path 依赖（唯一主路径；工具链统一 1.77.2 与客户端一致）
   ▼
p2premote-desktop-client   消费方（Linux/Windows/macOS 直接调 api::*，同一源码集成路径）
```

> **分工决策（2026-09-11）**：**全平台终态**（Win7/Win10/Linux/macOS/Android）统一为
> "Go go120 wgonly（WG 数据面）+ Rust 打洞库"；Go 端 punchffi **不再维护、后续废弃**
> （其 WG 子集由 go120 独立模块 p2premote-wg-ffi 承接）——打洞新特性
> （tcp4/v6/唤醒等）只落地 Rust 与 `protocol/client-client` 规范。

## 3. 当前实现状态

### 3.1 已实现（打洞核心 · 全网络矩阵，均经 gonc 实网互通验收）

UDP4 链路自初版即相当完整（并非"简单 demo"），2026-09-11 起补齐 TCP/IPv6/唤醒：

- **STUN 探测**：6 个公共服务器（TCP / UDP / 多端口竞速三种传输）、手写 STUN 编解码
  （Binding Request、XOR-MAPPED-ADDRESS v4/v6）、RTO 120ms 指数退避
- **NAT 分类**：easy（端口保映射）/ hard（端口重映射但一致）/ symm（对称）分组研判
- **MQTT 加密信令**：4 个公共 broker 并发连接、断线重连、QoS1、burst 重发
  （200ms/800ms/2s 起步）、自回声过滤、topic 派生
- **密钥协议**：与 Go 字节级一致的派生链（`derive_key` / `derive_key_for_topic` /
  `derive_key_for_payload` / AES-256-GCM / P-256 ECDH），内置 Go 生成的交叉验证向量
- **UDP 打洞引擎**：低 TTL 探测（TTL=5，多出口 TTL=10）、随机目的端口喷雾（RDP，600 端口）、
  随机源端口生日悖论（RSP，600 本地端口竞争）、多出口备选地址、LAN probe、三连握手
- **LAN 直连**：组播 `239.255.255.250:19730` 四步握手（Beacon/Response/Confirm/Ack）+
  HMAC-SHA256 认证；`traversal_mode = auto / lan / internet` 双端协商
- **MQTT Exchange**：WGVPN 密钥/IP 交换（exmode：mutual / waitOnly / publishOnly）
- **Linux 子网路由**：iptables 链 `P2PREMOTE-FWD` / `P2PREMOTE-NAT`，引用计数增删
- **FFI**：22 个 C ABI 符号（JSON-in/JSON-out），与 Go punchffi 一一对应；
  另有 Rust 原生 `api` 模块（async，不嵌套 runtime）
- **TCP 打洞**（`punch_tcp.rs`）：同时打开 + 端口 +100 约定、8 字节二进制 punch-ACK
  三层收敛、800 worker RDP/RSP 生日悖论、LANProbeOnly；隧道层以 2 字节长度帧在
  TCP 流上承载 WG 报文（本地前转口不变，FFI 契约零变更）
- **IPv6**：udp6/tcp6 全链路（按族解析、v6-only 绑定、IPV6_UNICAST_HOPS）
- **MQTT 唤醒**（`wake.rs`）：MqttWait/MqttHello、SYN@/ACK@、HelloPayload 编解码
- **运行时可调参数**：STUN/broker 列表、短 TTL、随机端口数、topic 前缀（环境变量，
  gonc 包变量等价）；`api::detect_nat` NAT 分类查询入口
- 结构化失败诊断（attempts、双端 NAT 类型回传）、幂等 stop、句柄注册表

### 3.2 范围外 / 桩 / 待环境验证（详见 ROADMAP 决策记录）

| 项 | 状态 |
|---|---|
| SOCKS5 UDP 中继（relay） | **决策不实现**：维持 `allow_relay=true` 报错（GONC_DESIGN §14 仅作设计记录） |
| userspace WireGuard 数据面（Win/Mac） | **决策不做**（WX1 取消，WG 数据面长期由 go120 wgonly 承担）；`src/platform.rs` 全部桩 |
| `GenerateWgKeypair` | 维持桩（由 Go 侧提供） |
| secure 层（TLS/DTLS/KCP/SS） | **暂缓**（gonc 有；p2premote-punch 已删除并固定明文 UDP，主程序不需要） |
| 跨 NAT easy×easy +100 路径实网验证 | 待双机环境（单机已覆盖同 LAN 直连与 hard×easy RSP 路径） |
| ~~macOS 编译验证~~ | ✅ 2026-09-12 mac 实测（Sonoma/1.77.2）：测试全过 + 客户端 core 编译过 + 与 Windows Go 跨机 tcp4/udp4 互通 |
| Win7 真机冒烟 | 构建兼容已随工具链统一（1.77.2，与客户端相同）解决；待 Win7 真机验证 |

## 4. 代码结构

```
src/
├── lib.rs              FFI 入口（panic 防护）+ JSON 编解码 + Rust 原生 api 模块（staticlib/rlib）
├── types.rs            全部 JSON 请求/响应结构（镜像 punchffi/main.go，含 omitempty 语义）
├── runtime.rs          全局 tokio 多线程 runtime（支撑阻塞式 C ABI）
├── handles.rs          长生命周期隧道句柄注册表（udp-<unix-nanos>，幂等 stop）
├── platform.rs         平台能力上报 + userspace WireGuard 桩（全部 unsupported）
├── subnet_router.rs    Linux 子网路由：sysctl ip_forward + 引用计数 iptables 链
└── easyp2p/            gonc NAT 穿透引擎移植（核心）
    ├── mod.rs          错误 / CancelToken / Scope / 日志 / 运行时可调参数（env 覆盖，gonc 包变量等价）
    ├── stun.rs         STUN 探测 + NAT 分类；UdpMux 单 socket 多路复用；TCP/UDP/竞速三种 StunConn
    ├── mqtt_signal.rs  多 broker MQTT 信令会话 + exchange 原语（重连重放、burst、pending 队列）
    ├── crypto.rs       topic 派生 / AES-GCM / P-256 ECDH（与 Go 字节级一致，内置交叉验证向量）
    ├── candidates.rs   候选对构造 / 角色选择 / 排序 / 多出口备选地址
    ├── p2p.rs          打洞总编排（do_auto_p2p_ex2 → easy_p2p_mp，5 轮候选循环；P2PConn 传输枚举分发）
    ├── punch_udp.rs    UDP 打洞本体（低 TTL + RDP/RSP 600 端口喷雾 + 三连握手）
    ├── punch_tcp.rs    TCP 打洞本体（+100 端口约定 / punch-ACK 三层收敛 / RDP-RSP 生日悖论）
    ├── lan.rs          LAN 组播发现（四步握手 + HMAC；tcp/udp transport 分发）
    ├── exchange.rs     MQTT_ExchangePayload（WGVPN 密钥/IP 交换，topic salt "wgvpn-kx/"）
    ├── wake.rs         MQTT 唤醒（MqttWait/MqttHello + HelloPayload 编解码）
    ├── netx.rs         socket 工具（REUSEADDR / SIO_UDP_CONNRESET / TTL(v4+v6) / TCP listen-dial / 空闲端口）
    ├── udp_tunnel.rs   StartUdpTunnel：模式协调 → 打洞 → 本地 UDP 双向转发（TCP 时为帧转发）
    └── live_tests.rs   实网集成测试（#[ignore]，手动跑）
```

测试与工具目录：

| 目录 | 用途 |
|---|---|
| `tests/ffi_abi.rs` | 18 个离线 FFI 契约测试（镜像 Go punchffi/main_test.go） |
| `tests/go-vector/` | Go 标准库生成密码学交叉验证向量的脚本（`//go:build ignore`） |
| `go-interop/` | Go 侧互通 harness（自包含 module，replace 指向 Go 原仓库） |
| `c-tests/` | C 宿主冒烟测试（zig cc 链 musl） |
| `examples/interop.rs` | 跨实现互通驱动器（exchange / tunnel / punch-tcp / wait / hello） |
| `scripts/strip-rustlib.sh` | 从 staticlib 剥离 rustlib，产出 std-external 库 |
| `dist/` | 预构建产物（gitignore，仅 master 工作区有）：win .dll / linux .so / musl .a ×2 |

## 5. 对外接口

### 5.1 C ABI（`feature = "ffi"` 默认关闭；不在主程序源码集成路径上）

与 Go punchffi 一一对应（详见 BUILD.md 符号清单），当前无消费者，仅作静态库
备选保留：

- **打洞隧道**：`StartUdpTunnel` / `StopUdpTunnel`
- **子网路由**：`StartSubnetRouter` / `StopSubnetRouter` / `GetSubnetRouterStatus`
- **密钥交换**：`Exchange`
- **WG 能力/数据面**：`GetWgCapabilities`（恒 `abi_version=2, userspace_wg=false`）、
  `GenerateWgKeypair`（桩）、`Start/Stop/Get/Allowed/StopEngine/Cleanup` ×
  （WindowsWg 别名 + UserspaceWg 别名，均为桩）
- `FreeCString`、`P2PremotePunchRsAbiVersion()`（恒 2，防与 Go 库双重链接的标记符号）

### 5.2 主程序调用面（源码集成，`pub mod api`，无 C ABI、不嵌套 runtime）

客户端 `core/Cargo.toml`：`p2premote-punch = { path = "../../p2premote-punch-rs",
default-features = false }`（关 ffi feature，无 C ABI 导出）。主程序当前
（`core/src/gonc_ffi.rs` 的 `*_native` 函数，Linux/Windows 生效）使用的接口：

```rust
// 打洞 + 本地前转隧道（network 字段：udp4/tcp4/udp6/tcp6 或聚合 any/any4/any6/tcp/udp；
// any 按 gonc 优先级 tcp6>tcp4>udp4 逐候选探测，前转自动跟随命中传输）
pub async fn start_udp_tunnel(request: UdpTunnelInput, budget: Duration)
    -> Result<UdpTunnelResult, String>
// 幂等停止（handle_id 来自返回的 UdpTunnelResult）
pub fn stop_udp_tunnel(handle_id: &str)
// WGVPN 密钥/地址交换（exmode 0=mutual / 1=waitOnly / 2=reply）
pub async fn exchange(request: ExchangeInput, timeout: Duration)
    -> Result<ExchangeResult, String>

// 类型（serde 兼容客户端的 JSON 结果契约，从客户端 UdpTunnelRequest 直接转换）
p2premote_punch::{UdpTunnelInput, UdpTunnelResult, ExchangeInput, ExchangeResult}
```

库级另可选用的公开接口（主程序暂未调用）：
`api::detect_nat`（NAT 分类查询）、`api::*_json`（JSON 直通便捷版）、
`easyp2p::wake::{mqtt_wait, mqtt_hello}`（待命唤醒）、`easyp2p::*`（打洞内核
全部公开，供深度集成）。

C ABI（§5.1，`ffi` feature，默认关闭）不在主程序源码集成路径上（macOS 亦为
源码集成，2026-09-12 决策），仅作静态库备选保留。

## 6. 协议兼容性要点（改动时必须保持）

以下常量/派生链与 Go 端**字节级一致**，是互通的根基（`src/easyp2p/crypto.rs` 有向量锁定）：

- 打洞短 TTL = 5（多出口 10）、随机端口数 = 600、topic 前缀 `nat-exchange/`
- MQTT salt = `mqtt-exchange-gonc-v2.2.0`；exchange topic salt = `wgvpn-kx/`
- `derive_key_for_topic = hex(sha256(salt ‖ md5hex(uid)))[:16]`
- `derive_key_for_payload = sha256("gonc-p2p-payload" ‖ md5hex(uid))[:8]`（打洞包/ACK 内容）
- `derive_key = sha256(sha256("nc-p2p-tool" ‖ salt ‖ uid))`（AES 密钥）
- ECDH：P-256 非压缩 SEC1 公钥，共享密钥 = `sha256(X 坐标去前导零)`
- LAN 发现：magic `GONC-LAN-V1`，密钥 `sha256("gonc-lan-discovery-v1" ‖ key)`
- 4 个 MQTT broker、6 个 STUN 服务器**默认清单**与 gonc 相同（可环境变量覆盖，见 §3.1）

客户端间协议的规范真源在 `p2premote-punch/protocol/client-client/`（README + JSON Schema），
字段变更需三端（Go/Rust/Android）对齐。

## 7. 构建与集成（详见 BUILD.md）

- **唯一主路径 = 源码集成**（2026-09-11 定稿）：主程序 path 依赖 + 直调
  `api::*`（见 §5.2）；动态库交付（cdylib/DLL/.so）已决策回退并删除。
- 备选 = 静态库交付：`cargo build --release --lib --target *-musl` 产自包含 `.a`；
  供 Rust 宿主必须先 `scripts/strip-rustlib.sh` 剥离 rustlib，且两端同版本工具链。
- 工具链锁定 1.77.2（与 p2premote-desktop-client 一致，Win7 兼容的最后一个 stable）；
  依赖 pin：`base64ct=1.6.0`、`zeroize=1.7.0`。
- 日志默认静默，`P2PREMOTE_PUNCH_LOG=1` 输出到 stderr。

## 8. 开发工作流（worktree 隔离）

本项目 master 工作区被 p2premote-desktop-client 以 path 依赖直接引用，**不得在上面直接
开发**。所有复刻开发在独立 worktree 进行：

| 项 | 值 |
|---|---|
| 稳定线 | `D:\work\p2premote-all\p2premote-punch-rs`（master，保持可构建、可被客户端引用） |
| 开发 worktree | `D:\work\p2premote-all\p2premote-punch-rs-gonc`（分支 `dev/replicate-gonc`） |
| 合并策略 | 每个阶段完成并互通测试全过后，`dev/replicate-gonc` 合回 master |
| 远程 | 本仓库当前无 remote，纯本地 |

worktree 相关注意：`dist/`、`target/` 均被 gitignore，worktree 内首次构建需重新编译；
预构建 `.a` 只存在于 master 工作区 `dist/`。

## 9. 配套文档

| 文档 | 内容 |
|---|---|
| [GONC_DESIGN.md](GONC_DESIGN.md) | **gonc 打洞逻辑详细设计文档**：全部穿透流程的状态机/时序/报文格式/常量（STUN 探测、MQTT 信令、地址交换、候选与角色、UDP/TCP 打洞、LAN 直连与 probe、SOCKS5 中继、唤醒、CLI 竞速仲裁、netx 原语），复刻时的协议行为参照 |
| [ROADMAP.md](ROADMAP.md) | 复刻路线图：阶段划分、验收标准、老系统兼容矩阵、风险与决策记录 |
