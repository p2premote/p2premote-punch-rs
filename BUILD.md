# p2premote-punch-rs 构建与对接说明

`p2premote-punch`（Go / punchffi）的 Rust 重写。目标：替换 Go c-archive，解决
Go 运行时与 musl 静态链接的运行期错误；与 Go 端（Android gomobile AAR / Go
CLI / 桌面客户端 Go 库）**字节级协议互通**。

## 交叉构建

需要 zig 0.13（本机已装 pip 包）与 cargo-zigbuild：

```bash
# zig（任选其一）
export PATH="/c/Users/LN/AppData/Roaming/Python/Python313/site-packages/ziglang:$PATH"
# 或: 任意 zig 0.13 加入 PATH

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# musl 静态库（交付目标）
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl

# glibc 静态库（如需）
cargo zigbuild --release --target x86_64-unknown-linux-gnu
```

产物（已复制到 `dist/`，文件名保持客户端脚本所需）：

- `dist/x86_64-unknown-linux-musl/libp2premote-punch.a`
- `dist/aarch64-unknown-linux-musl/libp2premote-punch.a`
- 原始路径：`target/<triple>/release/libp2premote_punch.a`

musl 目标会警告 `dropping unsupported crate type cdylib`（musl 不支持 cdylib，
我们只需要 staticlib，忽略即可）。

## 与 desktop-client 对接（不改客户端代码）

客户端 `p2premote-desktop-client/core/build.rs` 用
`cargo:rustc-link-lib=static=p2premote-punch` 链接
`src-tauri/resources/libp2premote-punch.a`。切换方式：

1. 用 `dist/<triple>/libp2premote-punch.a` 覆盖
   `p2premote-desktop-client/src-tauri/resources/libp2premote-punch.a`
   （按构建目标架构选择对应 triple 的产物）。
2. 客户端构建脚本不再需要 `go build -buildmode=c-archive`（可删可留，产物已被替换）。
3. 客户端 Linux 构建可切回 musl 静态目标：
   `cargo build --release --target x86_64-unknown-linux-musl`
   （Rust 静态库与 musl 客户端链接不再有 Go 运行时问题）。

gonc_ffi.rs 的 15 个 extern 声明与本库导出符号一一对应，无需改动。

## C 链接注意事项

musl 目标的静态库链接时需要 `-lunwind`（Rust panic_unwind 依赖）：

```bash
zig cc -target x86_64-linux-musl app.c libp2premote-punch.a -lunwind -o app
# 或 musl-gcc: musl-gcc app.c libp2premote-punch.a -lunwind -o app
```

若宿主程序用 `panic=abort` 亦可（库自身不要求 unwinding，但默认构建带 unwind 表）。

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
  caps 中 `userspace_wg=false`。**桌面客户端 win/mac 版继续使用现有 Go
  DLL/dylib。**
- **TCP 打洞未移植**：FFI 路径 `network` 恒为 `udp4`（StartUDPTunnel 校验强制），
  `NetworksForStun("udp4")` 只产生 UDP 候选，TCP 遍历在 Go 版同路径下也不可达
  —— 行为等价。
- 日志：默认静默（Go 侧 FFI 也是把日志写进丢弃的 buffer）；设
  `P2PREMOTE_PUNCH_LOG=1` 输出 easyp2p 诊断日志到 stderr。
- 已知实现细节差异（不影响协议互通）：STUN 重传节奏、随机数源、rumqttc 与
  paho 的重连细节；均有 burst 重发与 QoS1 保证兜底。

## 测试

```bash
cargo test                       # 18 单测 + 18 FFI ABI 测试（离线）
cargo test --lib -- --ignored    # 实网测试：STUN 探测、MQTT Exchange、
                                 # Rust↔Rust 全链路打洞隧道（走公网 broker/STUN）

# 与 Go 的跨实现互通向量（Go 工具链运行）
go run tests/go-vector/main.go   # 生成向量；Rust 单测内置断言逐字节一致

# 跨实现互通 harness
#   Go 侧（自包含模块，replace 指向 ../p2premote-punch）:
cd go-interop
go run . exchange <exmode> <token> <data>
go run . tunnel <active|passive> <token> [wgPort]
#   Rust 侧:
cargo run --release --example interop -- exchange <exmode> <token> <data>
cargo run --release --example interop -- tunnel <active|passive> <token> [wgPort]
#   两端用同一 token，一端 active 一端 passive；交换/打洞/转发全链路互通

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
