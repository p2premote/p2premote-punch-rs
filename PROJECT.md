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

> 兼容性说明：`rust-toolchain.toml` 锁定 Rust 1.94.1 并非为了老系统，而是
> "std-external 静态库"要求宿主与库使用同一版本工具链的 std 符号（与
> p2premote-desktop-client 锁定同版本）。老系统兼容由 musl 静态链接解决；Win7 侧交付
> 路径见 ROADMAP P0/P6。

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
   │  源码 path 依赖（Linux）/ 剥离 rustlib 的静态库 .a
   ▼
p2premote-desktop-client   消费方（打洞：Linux 走 Rust 源码集成；Win/Mac 过渡期仍用 Go DLL/dylib）
```

> **分工决策（2026-09-11）**：Win7 长期维持 "Go go120 wgonly DLL（WG 数据面）+
> Rust 打洞库" 分工；Go 端 punchffi **不再维护、后续废弃**——打洞新特性
> （tcp4/v6/唤醒等）只落地 Rust 与 `protocol/client-client` 规范。

## 3. 当前实现状态

### 3.1 已实现（udp4 链路已相当完整）

 udp4 并不是"简单 demo"，以下全链路均已落地且经 Go↔Rust 互通验证：

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
- 结构化失败诊断（attempts、双端 NAT 类型回传）、幂等 stop、句柄注册表

### 3.2 未实现 / 桩（与 gonc 的差距，详见 ROADMAP.md）

| 差距点 | 现状 | gonc 参照 |
|---|---|---|
| TCP 打洞（tcp4/tcp6） | `network != "udp4"` 直接拒绝（`src/easyp2p/udp_tunnel.rs:367`） | `easyp2p/p2p.go:1886-2391` |
| IPv6（udp6 / "any" 网络矩阵） | `networks_for_stun("udp4")` 恒返回 `["udp4"]`（`src/easyp2p/stun.rs:31`） | `easyp2p/stun.go:29-46` |
| SOCKS5 UDP 中继（relay） | **决策不实现**：维持 `allow_relay=true` 报错（`udp_tunnel.rs:371`） | GONC_DESIGN §14（仅记录） |
| MQTT 唤醒（wait/hello） | 无 | `easyp2p/p2p.go:2393-2613` |
| 参数可配置（STUN/broker/TTL/端口数） | 硬编码常量 | gonc 导出变量可被 CLI 覆盖 |
| NAT 类型独立查询入口 | 仅内部使用 | `DetectNATAddressInfo`（-nat-checker） |
| userspace WireGuard 数据面（Win/Mac） | 全部桩返回 unsupported（`src/platform.rs`） | **决策：不做**（WX1 取消，WG 数据面长期由 Go DLL 承担） |
| `GenerateWgKeypair` | 桩返回错误 | 维持桩（由 Go 侧/DLL 提供） |
| secure 层（TLS/DTLS/KCP/SS） | 未实现 | gonc 有；p2premote-punch 已删除并固定明文 UDP |

## 4. 代码结构

```
src/
├── lib.rs              FFI 入口 + JSON 编解码 + Rust 原生 api 模块（feature = "ffi" 门控）
├── types.rs            全部 JSON 请求/响应结构（镜像 punchffi/main.go，含 omitempty 语义）
├── runtime.rs          全局 tokio 多线程 runtime（支撑阻塞式 C ABI）
├── handles.rs          长生命周期隧道句柄注册表（udp-<unix-nanos>，幂等 stop）
├── platform.rs         平台能力上报 + userspace WireGuard 桩（全部 unsupported）
├── subnet_router.rs    Linux 子网路由：sysctl ip_forward + 引用计数 iptables 链
└── easyp2p/            gonc NAT 穿透引擎移植（核心）
    ├── mod.rs          常量 / 错误 / CancelToken（Go context 替代）/ Scope（deadline 递减）/ 日志
    ├── stun.rs         STUN 探测 + NAT 分类；UdpMux 单 socket 多路复用；TCP/UDP/竞速三种 StunConn
    ├── mqtt_signal.rs  多 broker MQTT 信令会话 + exchange 原语（重连重放、burst、pending 队列）
    ├── crypto.rs       topic 派生 / AES-GCM / P-256 ECDH（与 Go 字节级一致，内置交叉验证向量）
    ├── candidates.rs   候选对构造 / 角色选择 / 排序 / 多出口备选地址
    ├── p2p.rs          打洞总编排（do_auto_p2p_ex2 → easy_p2p_mp，5 轮候选循环）
    ├── punch_udp.rs    UDP 打洞本体（低 TTL + RDP/RDP 600 端口喷雾 + 三连握手）
    ├── lan.rs          LAN 组播发现（四步握手 + HMAC）
    ├── exchange.rs     MQTT_ExchangePayload（WGVPN 密钥/IP 交换，topic salt "wgvpn-kx/"）
    ├── netx.rs         socket 工具（REUSEADDR / SIO_UDP_CONNRESET / TTL / 强制重绑 / 空闲端口）
    ├── udp_tunnel.rs   StartUdpTunnel：模式协调 → 打洞 → 本地 UDP 双向转发
    └── live_tests.rs   实网集成测试（#[ignore]，手动跑）
```

测试与工具目录：

| 目录 | 用途 |
|---|---|
| `tests/ffi_abi.rs` | 18 个离线 FFI 契约测试（镜像 Go punchffi/main_test.go） |
| `tests/go-vector/` | Go 标准库生成密码学交叉验证向量的脚本（`//go:build ignore`） |
| `go-interop/` | Go 侧互通 harness（自包含 module，replace 指向 Go 原仓库） |
| `c-tests/` | C 宿主冒烟测试（zig cc 链 musl） |
| `examples/interop.rs` | 跨实现互通驱动器（exchange / tunnel 对打） |
| `scripts/strip-rustlib.sh` | 从 staticlib 剥离 rustlib，产出 std-external 库 |
| `dist/` | 预构建 musl 静态库（gitignore，仅 master 工作区有） |

## 5. 对外接口

### 5.1 C ABI（`feature = "ffi"`，JSON-in / JSON-out，`char* f(char*)`）

与 Go punchffi 一一对应（详见 BUILD.md 符号清单）：

- **打洞隧道**：`StartUdpTunnel` / `StopUdpTunnel`
- **子网路由**：`StartSubnetRouter` / `StopSubnetRouter` / `GetSubnetRouterStatus`
- **密钥交换**：`Exchange`
- **WG 能力/数据面**：`GetWgCapabilities`（恒 `abi_version=2, userspace_wg=false`）、
  `GenerateWgKeypair`（桩）、`Start/Stop/Get/Allowed/StopEngine/Cleanup` ×
  （WindowsWg 别名 + UserspaceWg 别名，均为桩）
- `FreeCString`、`P2PremotePunchRsAbiVersion()`（恒 2，防与 Go 库双重链接的标记符号）

### 5.2 Rust 原生 API（`pub mod api`，无 C ABI、不嵌套 runtime）

```rust
pub async fn start_udp_tunnel(request: UdpTunnelInput, budget: Duration) -> Result<UdpTunnelResult, String>
pub fn stop_udp_tunnel(handle_id: &str)
pub async fn exchange(request: ExchangeInput, timeout: Duration) -> Result<ExchangeResult, String>
pub fn start_udp_tunnel_json(input: &str) -> String   // JSON 便捷版 ×3
```

## 6. 协议兼容性要点（改动时必须保持）

以下常量/派生链与 Go 端**字节级一致**，是互通的根基（`src/easyp2p/crypto.rs` 有向量锁定）：

- 打洞短 TTL = 5（多出口 10）、随机端口数 = 600、topic 前缀 `nat-exchange/`
- MQTT salt = `mqtt-exchange-gonc-v2.2.0`；exchange topic salt = `wgvpn-kx/`
- `derive_key_for_topic = hex(sha256(salt ‖ md5hex(uid)))[:16]`
- `derive_key_for_payload = sha256("gonc-p2p-payload" ‖ md5hex(uid))[:8]`（打洞包/ACK 内容）
- `derive_key = sha256(sha256("nc-p2p-tool" ‖ salt ‖ uid))`（AES 密钥）
- ECDH：P-256 非压缩 SEC1 公钥，共享密钥 = `sha256(X 坐标去前导零)`
- LAN 发现：magic `GONC-LAN-V1`，密钥 `sha256("gonc-lan-discovery-v1" ‖ key)`
- 4 个 MQTT broker、6 个 STUN 服务器清单与 gonc 相同

客户端间协议的规范真源在 `p2premote-punch/protocol/client-client/`（README + JSON Schema），
字段变更需三端（Go/Rust/Android）对齐。

## 7. 构建与集成（详见 BUILD.md）

- **主路径 = 源码集成**：桌面客户端 Linux 链路以 path 依赖引入本 crate；`ffi` feature
  可关闭以去掉 C ABI 导出。
- **备选 = 静态库交付**：`cargo build --release --lib --target *-musl` 产自包含 `.a`；
  供 Rust 宿主必须先 `scripts/strip-rustlib.sh` 剥离 rustlib，且两端同版本工具链。
- 工具链锁定 1.94.1（与 p2premote-desktop-client 一致）。
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
