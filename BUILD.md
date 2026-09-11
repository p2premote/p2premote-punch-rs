# p2premote-punch-rs 构建与对接说明

`p2premote-punch`（Go / punchffi）的 Rust 重写。目标：替换 Go c-archive，解决
Go 运行时与 musl 静态链接的运行期错误；与 Go 端（Android gomobile AAR / Go
CLI / 桌面客户端 Go 库）**字节级协议互通**。

## 备选 A：与 desktop-client 源码集成（Linux 过渡现状）

**主路径已切换为全平台 cdylib（见下"动态库交付"节）**；源码 path 依赖是 Linux
当前的过渡现状（单一 Rust 世界，无 staticlib 双 std 冲突）：

- `core/Cargo.toml`：`p2premote-punch = { path = "../../p2premote-punch-rs" }`。
- `core/src/gonc_ffi.rs` 顶部一行 `#[cfg(target_os = "linux")] use p2premote_punch as _;`
  ——extern "C" 声明不构成 crate 依赖引用，rustc 不会把未使用的依赖带进链接图。
- `gonc_ffi.rs` 的 15 个 extern 声明与本库 `#[no_mangle]` 导出一一对应，
  客户端其余 Rust 代码零改动；core/build.rs 在 Linux 不再要求预构建 `.a`。
- `build-linux-headless.sh`：service/cli 以
  `cargo build --release --target <arch>-unknown-linux-musl` 构建（默认 thin-LTO），
  musl 静态产物摆脱 glibc 基线；builder 镜像（tag v4）内置 musl rust-std。
- `build-wireguard-go.sh` 未改动：wireguard-go 回退二进制仍从 Go 仓库
  `../p2premote-punch` 构建，Go 仓库仍需在工作区存在。

已验证（WSL Debian）：musl + 默认 LTO 构建通过，`p2premote-service`/`cli`
完全静态（`NEEDED` 条目为 0）、可运行、FFI 符号在位。

## 备选：静态库产物交付（`dist/`，非默认）

如需 Go 式 `.a` 产物（外部消费者、C 宿主冒烟等），本仓库仍可产出：

```bash
# crate 用 rust-toolchain.toml 锁 1.94.1（与客户端一致）
rustup target add x86_64-unknown-linux-musl --toolchain 1.94.1
rustup target add aarch64-unknown-linux-musl --toolchain 1.94.1   # 交叉 arm64 产物

# 自包含版（供 C 宿主）——必须用普通 cargo build
cargo build --release --lib --target x86_64-unknown-linux-musl
# 产物: target/<triple>/release/libp2premote_punch.a
```

**不要用 `cargo rustc --crate-type staticlib`**：实测它会产出内部不自洽的档案
（tokio 引用的 std 内部符号判别符与捆绑的 std 成员不一致，链接期 undefined）。

供 **Rust 宿主**使用的 `.a` 必须先剥离 rustlib 预编译成员（rustc staticlib 会把
rustlib 的 std/core/alloc/compiler_builtins/memchr/ring 的 C 对象等原样打包，
与宿主自己的拷贝强符号冲突）：

```bash
scripts/strip-rustlib.sh <archive.a> <rust-target-triple>
```

`scripts/strip-rustlib.sh` 按目标 rustlib 目录的实际 `<crate>-<hash>` 精确匹配
剥离（punch 自编译的同名 crate 哈希不同、自动保留），并剔除分配器 shim、
compiler-rt 与 ring 的裸对象。剥离版的约束：两端同版本工具链（都锁 1.94.1）、
宿主有同版本 ring、链接时 `--whole-archive` 且关闭 thin-LTO（thin-LTO 会内部化
仅被原生对象引用的符号）。客户端的
`scripts/build-p2premote-punch-rs.sh` 封装了这套流程（当前未被
build-linux-headless.sh 调用，仅作产物路径保留）。`dist/` 下两份 `.a`
为剥离版（客户端文件名约定）。

## C 链接注意事项

静态库带 unwind 表，链接宿主需提供 `_Unwind_*`：

- **Rust 宿主（客户端即此场景）**：rustc 的 musl target 自带 libunwind/libc，
  直接链接即可，无需额外参数。
- **zig cc**：`zig cc -target x86_64-linux-musl app.c libp2premote-punch.a -lunwind -o app`
- **Debian musl-gcc 不建议**：Debian 的 musl-tools 会把 glibc 版 libgcc_eh
  链进来，其 `_dl_find_object` 符号导致链接失败（glibc 私有符号）。C 冒烟测试
  用 zig cc 或 Rust 宿主做。

## ABI 符号

全部 `char* f(char*)` JSON-in/JSON-out，返回串由 `FreeCString` 释放：

```
StartUdpTunnel StopUdpTunnel StartSubnetRouter StopSubnetRouter
GetSubnetRouterStatus GetWgCapabilities GenerateWgKeypair
StartUserspaceWgPeer StopUserspaceWgPeer GetUserspaceWgPeerStatus
SetUserspaceWgPeerAllowed StopUserspaceWgEngine CleanupUserspaceWgPlatform
Exchange FreeCString
```

旧别名（ABI v1 兼容）：`StartWindowsWgPeer StopWindowsWgPeer
GetWindowsWgPeerStatus SetWindowsWgPeerAllowed`。另有链接期冲突标记
`P2PremotePunchRsAbiVersion`（返回 2）。

`GetWgCapabilities` 恒返回 `abi_version=2`。

## 与 Go 版的行为差异

- **Windows/macOS userspace WireGuard 未移植**（boringtun+wintun/utun+smoltcp
  为后续任务）：`StartUserspaceWgPeer` 等函数返回与 Go 在 Linux 上相同的
  unsupported 错误；`GenerateWgKeypair` 同样返回错误（与 Go 在 Linux 上一致）；
  caps 中 `userspace_wg=false`。桌面客户端 win/mac 的 WG 数据面在分工终态下
  继续由 go120 wgonly DLL/dylib 承担（决策记录见 ROADMAP §6）。
- **TCP 打洞已移植（2026-09-11）**：`StartUdpTunnel` 的 `network` 接受 `tcp4`。
  P2P 传输为 TCP 时，本地前转仍是 UDP 口（WG 消费方即 UDP，FFI JSON 契约零变更），
  报文以 2 字节小端长度帧（gonc FramedConn 语义）在打洞出的 TCP 流上承载。
  Go 侧互通经 go-interop `punch-tcp`（底层 `Easy_P2P_MPWithOptions`）实测通过。
  注意：Go punchffi 已停维护，`network=tcp4` 为 Rust 独有扩展。
- 日志：默认静默（Go 侧 FFI 也是把日志写进丢弃的 buffer）；设
  `P2PREMOTE_PUNCH_LOG=1` 输出 easyp2p 诊断日志到 stderr。
- 已知实现细节差异（不影响协议互通）：STUN 重传节奏、随机数源、rumqttc 与
  paho 的重连细节；均有 burst 重发与 QoS1 保证兜底。

## 动态库交付（全平台统一形态，2026-09-11 决策）

**决策：所有平台统一以 cdylib（动态库）+ C ABI JSON 契约交付**，主客户端通过
C 接口调用——与原 Go DLL 模型同构。收益：客户端与打洞库的 Rust 工具链彻底解耦
（客户端可独立升级，无需同版本 std 约束）；Win7 交付简化为"用 1.77 工具链编同
一个 cdylib"；部署形态与现有 Go DLL 一致。源码集成与 std-external 静态库降为
备选路径。

- crate-type 增加 `cdylib`；全部 JSON-in/JSON-out 导出经 panic 防护包装
  （Rust panic 不跨 C ABI 边界，返回内部错误 JSON）；四个忽略输入的导出
  （GetWgCapabilities 等）保持 Go 语义（null 输入仍返回结果）。
- 产物（master `dist/`，dist 不入 git）：
  - `windows-x86_64/p2premote_punch.dll`（+ `.dll.lib` 导入库）——已用 P/Invoke
    实测加载并调用（ABI=2、caps JSON 正确）
  - `linux-x86_64-gnu.2.27/libp2premote_punch.so`——cargo-zigbuild 以
    glibc 2.27 基线链接（实测符号版本上限 GLIBC_2.25），已在 **Ubuntu 18.04.6
    chroot 内 dlopen + 调用**验证
  - musl 静态 `.a` 双架构保留（C 宿主静态链接备选）
- Linux `.so` 构建（WSL）：`cargo zigbuild --release --lib --target
  x86_64-unknown-linux-gnu.2.27`（zig 0.13；注意裸 zig cc 处理 rustc 的
  `-shared -nodefaultlibs` 有 Scrt1 怪癖，必须用 cargo-zigbuild）
- macOS dylib 待 mac 环境产出（同一 crate-type，无代码差异）
- 客户端接入：`P2PremotePunchRsAbiVersion()` 应在加载后校验（期望 2）

## 交付物（2026-09-11 重产）

`dist/{x86_64,aarch64}-unknown-linux-musl/libp2premote-punch.a` 为 std-external
版本（已剥离 rustlib），支持 udp4/tcp4/udp6/tcp6 全网络矩阵与 MQTT 唤醒。
构建链（WSL）：x86_64 用 musl-gcc；aarch64 用 `aarch64-linux-gnu-gcc` 编译 C 依赖
（ring）+ zig 0.13 链接。注意 zig cc 的 `-target` 三元组不接受 `unknown` 段
（用 `x86_64-linux-musl` 而非 `x86_64-unknown-linux-musl`）。
C 宿主冒烟：`zig cc -target x86_64-linux-musl c-tests/harness.c <full .a> -lunwind`。

## 测试

```bash
cargo test                       # 23 lib 单测 + 18 FFI ABI 测试（离线）
cargo test --lib -- --ignored    # 实网测试：STUN 探测（v4/v6）、MQTT Exchange、
                                 # Rust↔Rust 全链路隧道（udp4/tcp4/udp6/tcp6）

# 与 Go 的跨实现互通向量（Go 工具链运行）
go run tests/go-vector/main.go   # 生成向量；Rust 单测内置断言逐字节一致

# 跨实现互通 harness
#   Go 侧（自包含模块，replace 指向 ../p2premote-punch）:
cd go-interop
go run . exchange <exmode> <token> <data>
go run . tunnel <active|passive> <token> [wgPort]
go run . punch-tcp <token> [tcp4|tcp6]      # 底层 Easy_P2P_MPWithOptions 直打
go run . wait <token> / hello <token> [app] [param]   # 唤醒互通
#   Rust 侧:
cargo run --release --example interop -- exchange <exmode> <token> <data>
cargo run --release --example interop -- tunnel <active|passive> <token> [wgPort]
cargo run --release --example interop -- punch-tcp <token> [tcp4|tcp6]
cargo run --release --example interop -- wait <token> / hello <token> [app] [param]
#   两端用同一 token；exchange/tunnel 一端 active 一端 passive

# musl 产物 C 冒烟（WSL 实测通过）
zig cc -target x86_64-linux-musl c-tests/harness.c \
    target/x86_64-unknown-linux-musl/release/libp2premote_punch.a \
    -lunwind -o c-tests/harness-linux
wsl -d Debian -- /path/to/harness-linux
```

## 验证结论（2026-09-06/07 实测）

| 验证项 | 结果 |
|---|---|
| 加密/主题派生向量 vs Go（md5/topic/payload/deriveKey/AES-GCM 互解/ECDH 定标量） | 逐字节一致 |
| FFI ABI 36 项测试（对齐 Go main_test.go） | 全过 |
| 实网 STUN（6 服务器并发） | 5/5 成功，NAT 分类正确 |
| 实网 MQTT Exchange（Rust↔Rust / Go↔Rust 双向 / WSL musl→Go） | 全部互通 |
| 实网打洞隧道（Rust↔Rust 全链路 + Go↔Rust 跨实现） | 打洞+双向转发+幂等停止全通 |
| musl 静态库符号核对（19 导出） | 全部导出 |
| WSL(Debian) C harness 冒烟 + iptables 子网路由实跑（建链/规则/引用计数/清理） | 全过 |
| **客户端实链验证（2026-09-08，WSL Debian）**：源码 path 依赖集成，`p2premote-service`/`p2premote-cli` 以 musl + 默认 thin-LTO 构建 | 构建成功；二进制可运行、FFI 符号在位、`NEEDED` 为 0（完全静态、无 glibc）。产物路径（剥离版 `.a` + whole-archive、LTO off）另经最小 Rust 宿主验证 `GetWgCapabilities` 返回正确 JSON |
| aarch64 musl 产物（WSL 交叉构建 + 剥离） | 21 个导出符号完整（注：历史计数口径；当前 ABI 全集为 22 符号，见上文 ABI 清单） |
| **gonc 实网互通（2026-09-11）**：tcp4 / tcp6（hard×easy，+100 + RSP 生日悖论）/ 唤醒双向 / 单 broker 参数覆盖 | 全通 |
| **动态库（2026-09-11）**：win .dll P/Invoke 实测；linux .so（GLIBC_2.25 上限）在 18.04.6 chroot dlopen 调用 | 全通 |
