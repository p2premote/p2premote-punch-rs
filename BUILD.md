# p2premote-punch-rs 构建与对接说明

`p2premote-punch`（Go / punchffi）的 Rust 重写。目标：替换 Go c-archive，解决
Go 运行时与 musl 静态链接的运行期错误；与 Go 端（Android gomobile AAR / Go
CLI / 桌面客户端 Go 库）**字节级协议互通**。

## 构建

主路径：**WSL Debian 原生构建**（客户端 `scripts/build-p2premote-punch-rs.sh` 用的就是它）。
本 crate 纯 Rust、无 C 依赖、crate-type 仅 `staticlib+rlib`（无 cdylib），
因此任何架构交叉都无需目标链接器：

```bash
# WSL Debian 一次性准备（crate 用 rust-toolchain.toml 锁 1.94.1，与客户端一致）
rustup toolchain install 1.94.1
rustup target add x86_64-unknown-linux-musl --toolchain 1.94.1
rustup target add aarch64-unknown-linux-musl --toolchain 1.94.1   # 交叉 arm64 产物

# musl 静态库（交付目标）——必须用普通 cargo build
cargo build --release --lib --target x86_64-unknown-linux-musl
cargo build --release --lib --target aarch64-unknown-linux-musl
# 产物: target/<triple>/release/libp2premote_punch.a（自包含版，供 C 宿主）
```

**不要用 `cargo rustc --crate-type staticlib`**：实测它会产出内部不自洽的档案
（tokio 引用的 std 内部符号判别符与捆绑的 std 成员不一致，链接期 undefined）。

交付给 Rust 宿主（桌面客户端）的 `.a` 还需剥离 rustlib 预编译成员（见下节）：

```bash
scripts/strip-rustlib.sh dist/x86_64-unknown-linux-musl/libp2premote-punch.a x86_64-unknown-linux-musl
```

`dist/` 下两份 `.a` 均为剥离版（客户端文件名约定不变）。

## Rust 宿主链接模型（为什么剥离）

rustc staticlib 会把工具链 rustlib 里的预编译 rlib（std/core/alloc/
compiler_builtins/std 的依赖 memchr/libc/cfg_if/gimli 等）原样打包进 `.a`。
Rust 宿主自己也链同一批对象，两份强符号（`__RUST_STD_INTERNAL_VAL`、
`__rust_alloc` shim、compiler-rt 内建、ring 的 C 符号等）在链接期冲突。

`scripts/strip-rustlib.sh` 按**目标 rustlib 目录的实际 `<crate>-<hash>` 精确匹配**
剥离这些成员（punch 自己编译的同名 crate 哈希不同，自动保留），同时剔除
分配器 shim、compiler-rt 裸对象和 ring 的裸 C/asm 对象（宿主侧有同版本 ring 提供
`ring_core_` 符号）。剥离后的 `.a` 是 "std-external"：其 std 引用解析到宿主
自己的 std——**因此两端必须使用同一版本工具链**（本仓库与客户端都锁 1.94.1，
升级工具链时需同步重编）。

配套的客户端侧约定（已实装于 p2premote-desktop-client）：

- `core/build.rs` 不再 `cargo:rustc-link-lib`（cargo 会把 static 库折叠进 core 的
  rlib，档案拉取顺序会留下未解析引用），只给 core 自己的测试产物发链接参数。
- `service/build.rs` / `cli/build.rs` 对各自 bin 发
  `-Wl,--whole-archive <.a 绝对路径> -Wl,-no-whole-archive` 三连。
- Linux 构建 `CARGO_PROFILE_RELEASE_LTO=false`：thin-LTO 会内部化"仅被原生对象
  引用"的 std/ring 符号，破坏剥离版 `.a` 的链接。

## 与 desktop-client 对接（切换已落地）

客户端 Linux 链路已切换到本仓库（仅 Linux；Windows/macOS 构建不受影响，
仍用 Go DLL/dylib）：

- `scripts/build-p2premote-punch-rs.sh`（新增）：从本仓库构建 musl staticlib
  并调用 `scripts/strip-rustlib.sh` 产出客户端用 `.a`；
  `build-linux-headless.sh` 已改为调用它（原 Go c-archive 脚本保留未删）。
- `build-linux-headless.sh` 的 service/cli 构建改为
  `CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target <arch>-unknown-linux-musl`。
- `build-wireguard-go.sh` 未改动：wireguard-go 回退二进制仍从 Go 仓库
  `../p2premote-punch` 构建，Go 仓库仍需在工作区存在。
- builder 镜像（`packaging/linux/builder/Dockerfile`）追加
  `rustup target add *-unknown-linux-musl`，镜像 tag v3→v4，首次构建会自动重建。
- 链接模型改动（见上节）：core 不再折叠、service/cli 以 whole-archive 链接。

手动本地构建（不经 headless 脚本）：把 `dist/<triple>/libp2premote-punch.a`
覆盖 `src-tauri/resources/libp2premote-punch.a`，然后
`CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target x86_64-unknown-linux-musl`。

gonc_ffi.rs 的 15 个 extern 声明与本库导出符号一一对应，客户端 Rust 代码零改动。

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
| **客户端实链验证（2026-09-08，WSL Debian）**：剥离版 `.a` 以 whole-archive 链入 `p2premote-service`/`p2premote-cli`（musl、LTO off） | 构建成功，二进制可运行，FFI 符号在位；最小 Rust 宿主 `GetWgCapabilities` 返回正确 JSON |
| aarch64 musl 产物（WSL 交叉构建 + 剥离） | 21 个导出符号完整 |
