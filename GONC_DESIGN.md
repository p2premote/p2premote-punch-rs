# gonc 打洞逻辑详细设计文档

> 参照源码：`D:\work\p2premote-all\3rdsrc\gonc-main\`（gonc v2.6.9）。
> 本文是 gonc **NAT 穿透全部流程**的设计级描述，供 p2premote-punch-rs 复刻使用。
> 不含代码细节；所有时间常量、报文格式、状态转移均为协议行为的一部分，必须精确复刻。
> 各节标注参照文件，便于回溯核对。
>
> **复刻范围注**：中继模式（relay）按决策**不复刻**（2026-09-11）——§14 及全文
> relay 相关段落仅为 gonc 设计记录；p2premote-punch-rs 不实现 SOCKS5 中继，
> FFI 维持 `allow_relay=true` 拒绝。

---

## 目录

1. [总体架构与端到端流程](#1-总体架构与端到端流程)
2. [网络与 NAT 模型](#2-网络与-nat-模型)
3. [MQTT 信令层](#3-mqtt-信令层)
4. [密码学体系](#4-密码学体系)
5. [STUN 探测与 NAT 分类](#5-stun-探测与-nat-分类)
6. [地址交换（Do_autoP2PEx2）](#6-地址交换do_autop2pex2)
7. [候选生成、过滤与排序](#7-候选生成过滤与排序)
8. [角色选择与轮次同步](#8-角色选择与轮次同步)
9. [打洞主循环（Easy_P2P_MPWithOptions）](#9-打洞主循环easy_p2p_mpwithoptions)
10. [UDP 打洞状态机](#10-udp-打洞状态机)
11. [TCP 打洞状态机](#11-tcp-打洞状态机)
12. [LAN 直连模式（-lan）](#12-lan-直连模式-lan)
13. [LAN Probe（公网流程中的内网旁路）](#13-lan-probe公网流程中的内网旁路)
14. [SOCKS5 UDP 中继（relay）](#14-socks5-udp-中继relay)
15. [唤醒机制（mqtt-wait / mqtt-hello）](#15-唤醒机制mqtt-wait--mqtt-hello)
16. [CLI 层编排：P2P 与 LAN 竞速仲裁](#16-cli-层编排p2p-与-lan-竞速仲裁)
17. [打洞成功之后：安全协商的密钥来源](#17-打洞成功之后安全协商的密钥来源)
18. [底层网络原语（netx）设计要点](#18-底层网络原语netx设计要点)
19. [常量速查总表](#19-常量速查总表)
20. [附录：p2premote-punch fork 的偏差](#20-附录p2premote-punch-fork-的偏差)

---

## 1. 总体架构与端到端流程

### 1.1 分层

```
┌─────────────────────────────────────────────────────────┐
│ CLI / 应用层（apps/nc.go）                               │
│  参数解析 · 唤醒串接 · P2P/LAN 竞速仲裁 · relay 装配      │
│  打洞成功后 → secure 协商（TLS/DTLS/KCP/SS）→ 业务       │
├─────────────────────────────────────────────────────────┤
│ 打洞编排层（easyp2p/p2p.go）                             │
│  地址交换 · 候选生成/排序 · 角色选择 · 轮次同步           │
│  UDP 打洞状态机 · TCP 打洞状态机 · 主循环(5 轮)          │
├──────────────────┬──────────────────────────────────────┤
│ 探测层（stun.go） │ 信令层（mqtt_signal.go）              │
│  STUN 探测        │  多 broker MQTT 会话                  │
│  NAT 三分类       │  加密 exchange 原语 · wait/hello      │
├──────────────────┴──────────────────────────────────────┤
│ 网络原语层（netx/）                                      │
│  BoundUDPConn · UDPSession 复用 · DialRace · TTL 控制    │
│  SO_REUSEADDR/REUSEPORT · FramedConn · 可取消 IO         │
└─────────────────────────────────────────────────────────┘
```

LAN 直连（`lan.go`）是独立于 MQTT/STUN 的旁路：组播发现后直接复用 UDP/TCP 打洞状态机。

### 1.2 一次公网 P2P 连接的完整生命周期

```
发起端/接收端（双方对称执行，仅口令相同）
═══════════════════════════════════════════════════════════
[CLI] 解析参数；(-x/-x2 时) 建 SOCKS5 relayConn（可选；不复刻）
[CLI] (-mqtt-wait/-mqtt-hello 时) 唤醒握手，得 topicSalt（可选，§15）
[CLI] sessionUid = p2pSessionKey + topicSalt（无唤醒时 salt 为空）
        │
        ▼
[编排] Easy_P2P_MPWithOptions(ctx, network, sessionUid, options)
        │  network 展开（any → tcp6,tcp4,udp4）
        │  建/复用 MQTT 信令会话（4 broker 并发，首个连上即用）
        ▼
[交换] Do_autoP2PEx2（预算 25s，§6）
        │  ① 订阅 gonc-exchange-address / gonc-exchange-sync
        │  ② STUN 探测（每轮 2828ms；relay 场景两轮，§5）
        │  ③ 生成 P-256 ECDH 密钥对
        │  ④ MQTT 加密交换地址载荷 {addrs, pk, caps}
        │  ⑤ sharedKey = sha256(ECDH 共享点 X 坐标)
        │  ⑥ 候选构造 + LAN probe 候选 + 多出口填充 + 排序（§7）
        │  ⑦ OnAddressExchangeDone 回调（CLI 竞速仲裁用，§16）
        ▼
[主循环] 遍历排序后候选，最多 5 轮（§9）
        │  round += 1；round > 0 → 先做轮次同步（25s，§8）
        │  tcp* → TCP 打洞（§11）；udp* → UDP 打洞（§10）
        │  成功 → P2PConnInfo；失败 → 歇 1s 换下一候选
        ▼
[CLI] p2pSecureNegotiation（TLS/DTLS/KCP/SS，§17）→ 应用层服务
```

结果对象 `P2PConnInfo`：连接列表、`SharedKey`（32 字节）、`IsClient`、`RelayMode/RelayUsed`、
`NetworksUsed`、对端地址。

---

## 2. 网络与 NAT 模型

### 2.1 网络类型与展开规则（`easyp2p/stun.go:29`）

| 输入 | 展开为 | 说明 |
|---|---|---|
| `any` | `tcp6, tcp4, udp4` | 默认；**不含 udp6**；TCP 优先 |
| `any6` / `any4` | `tcp6` / `tcp4, udp4` | 单栈 |
| `tcp` / `udp` | `tcp6, tcp4` / `udp6, udp4` | 双栈 |
| 具体网络 | 自身 | |

### 2.2 NAT 三分类（`easyp2p/stun.go:536`，判定算法见 §5.6）

| 类型 | 含义 | 打洞难度 |
|---|---|---|
| `easy` | 映射端口 = 本地端口且固定（EIM + 端口保持） | ⭐ |
| `hard` | 映射端口被改写但固定（EIM） | ⭐⭐ |
| `symm` | 对称：不同目的 → 不同映射端口 | ⭐⭐⭐ |
| `relay` | 经 SOCKS5 中继探测得到的地址（非真实 NAT，强制标记） | — |

### 2.3 成功率先验（docs/guide/p2p.md）

| 组合 | 成功率 |
|---|---|
| easy × easy | ~100% |
| easy × hard | 极高 |
| easy/hard × hard/symm | 中等，靠生日悖论（600 随机端口碰撞 ≈90%） |
| symm × symm | 放弃公网直打 → 仅保留 LAN probe / relay |

---

## 3. MQTT 信令层

参照：`easyp2p/mqtt_signal.go`、`easyp2p/p2p.go`（exchange 部分）。

### 3.1 Broker 与会话生命周期

- 内置 4 个公共 broker（明文 TCP 1883）：`broker.hivemq.com`、`broker.emqx.io`、
  `test.mosquitto.org`、`mqtt.gonc.cc`（guest:guest）。
- **并发连接全部 broker，任一连上即会话可用**，其余后台继续连；全部失败才报错。
- 单 broker 参数：连接超时 5s、拨号超时 30s、自动重连 + 每 3s 重试；重连成功后
  **重放全部订阅集**。
- ClientID：`"SG-" + deriveKeyForTopic("mqtt-topic-gonc-cid", uid)[:8] + "-" + 8位随机串`
  （≤23 字符；前两段同会话稳定，随机段防多实例冲突）。
- 支持可选 `localIP` 绑定出口。

### 3.2 Topic 体系

所有 topic = `TopicExchange 前缀 + deriveKeyForTopic(salt, uid)`：

| 用途 | salt | topic |
|---|---|---|
| 地址交换 | `"gonc-exchange-address"` | `nat-exchange/<16hex>` |
| 轮次同步 | `"gonc-exchange-sync"` | `nat-exchange/<16hex>` |
| 唤醒通道 | `"nat-exchange-wait/" + deriveKeyForTopic("mqtt-topic-gonc-wait", uid)` | `nat-exchange/<16hex>` |

双方由同一 sessionUid 推出相同 topic，无需服务器分配。

### 3.3 exchange 原语（所有信令交换的统一底座）

**加密信封**：载荷先 JSON，再 AES-256-GCM（nonce 随机），输出
`{"nonce":"<b64>","data":"<b64>"}`；密钥 = `deriveKey("mqtt-exchange-gonc-v2.2.0", uid)`（§4）。
解密失败提示 "possible version incompatibility with the peer"。

**QoS 1**。发布节奏（后台 publisher）：

```
T+0        初始发布（任一 broker ACK 即止）
T+200ms ┐
T+800ms ├ burst 补发 3 次
T+2s    ┘
之后     每 2s ticker 重发，直到停止条件
```

**停止条件**：mutual 模式收到对端消息后**再补发一次**并继续广播 5s（保活，让对方也能
收到）；publishOnly 成功后同样保活 5s；waitOnly 收到即停。

**自回声过滤**：等待者携带本端发送内容，收到的消息与自己的 payload 完全相等则丢弃
（因此 burst 重发不会误匹配自己）。

**等待者与 pending**：每 topic 可注册多个等待者；消息先到、等待者未注册时存入该 topic
的**单槽 pending**（后到覆盖前到）；注册时立即投递。

**三种 exmode**：

| exmode | 行为 |
|---|---|
| `mutual` (0) | 立即向全部 broker 发布 + burst/ticker 后台重发，阻塞等待 |
| `waitOnly` (1) | 完全不发布，仅订阅等待 |
| `publishOnly` (2) | 不订阅；优先发到指定 broker（800ms 窗口），失败回退全 broker（500ms settle）；用于"回 ACK 到收到 SYN 的那台 broker" |

超时错误携带 broker 统计：`timeout waiting for remote data exchange on topic %s (brokers=%d/%d subscribed=%d)`。

---

## 4. 密码学体系

全部派生链（**复刻必须逐字节一致**，p2premote-punch-rs 的 crypto.rs 已有交叉验证向量）：

| 派生 | 公式 | 用途 |
|---|---|---|
| `deriveKey(salt, uid)` | `sha256(sha256("nc-p2p-tool" ‖ salt ‖ uid))` | MQTT 信封 AES-256-GCM 密钥 |
| `deriveKeyForTopic(salt, uid)` | `hex(sha256(salt ‖ hex(md5(uid))))[:16]` | topic 名（16 hex 字符） |
| `deriveKeyForPayload(uid, ascii)` | `sha256("gonc-p2p-payload" ‖ hex(md5(uid)))` 前 8 字节 | UDP 打洞包 = hex 前 8 字符（ASCII）；TCP punch-ACK = 原始 8 字节（二进制） |
| ECDH | P-256；公钥 = 未压缩 SEC1 65 字节 b64；共享密钥 = `sha256(X 坐标去前导零)` 32 字节 | 打洞后 secure 层密钥材料 |
| LAN 发现密钥 | `sha256("gonc-lan-discovery-v1" ‖ sessionKey)` | LAN 消息 HMAC-SHA256 |
| LAN SessionID | `b64(sha256("gonc-lan-session-id-v1" ‖ sessionKey)[:12])` | responder 过滤无关 Beacon |
| LAN 共享密钥 | `sha256("gonc-lan-shared-" ‖ sessionKey)` | LAN 模式 PSK |

设计要点：口令（sessionKey）同时是**发现凭证**（topic/加密信封都由它派生）与**认证
凭证**（对端拿不到口令就解不开信封、发不出合法打洞包）。

---

## 5. STUN 探测与 NAT 分类

参照：`easyp2p/stun.go`。

### 5.1 服务器列表与 URL 格式

内置 6 个（均可被 CLI 覆盖）：

| 服务器 | 传输 |
|---|---|
| `tcp://turn.cloudflare.com:80` | TCP |
| `udp://turn.cloudflare.com:53?3478` | UDP，53/3478 双端口竞速 |
| `udp://stun.l.google.com:19302` | UDP |
| `stun.gonc.cc:3478` | 跟随当前网络协议 |
| `global.turn.twilio.com:3478` | 跟随 |
| `stun.nextcloud.com:443` | 跟随 |

URL 规则：`tcp://`/`udp://` 显式指定协议（与当前网络协议不符则跳过该服务器）；无
scheme 跟随当前协议；`?端口2?端口3` 后缀 = 同主机多端口**竞速**（应对端口劫持/屏蔽）。

### 5.2 共享本地端口（NAT 分类的正确性根基）

NAT 分类的核心问题是"**同一 (本地IP, 本地端口) 向不同目的地发包，映射是否一致**"。
因此：

- **UDP**：一次探测内所有 STUN 会话共用**同一个本地 UDP socket**。用 UDPSession
  复用器（§18.2）在该 socket 上为每个服务器虚拟出独立连接，按远端地址分发回包。
- **TCP**：多条 TCP 连接绑定**同一 LocalAddr**，靠 SO_REUSEADDR/SO_REUSEPORT 并发同绑。
- 多网络并发时（如 any → tcp6+tcp4+udp4）：每个 UDP 网络各用一个新空闲端口
  （同 family 端口会冲突）；bind 为空时先选一个 TCP+UDP 都可绑的空闲端口
  （最多尝试 100 次）。

### 5.3 单次探测时序

- 6 服务器**全部并发**，无顺序分批。
- STUN 客户端 RTO = **120ms**（重传退避由库内部策略）。
- 总超时兜底：探测预算（编排层给 **2828ms/轮**）到期直接强制关闭客户端中断阻塞。
- 请求：标准 Binding Request；应答先取 XOR-MAPPED-ADDRESS，失败回退 MAPPED-ADDRESS。
- TCP 连接 `SetLinger(0)`（关闭不等 FIN，避免端口占用残留）。

### 5.4 多端口竞速（DialRace）

UDP：对每个候选端口各建一条会话连接，全部并发读；**第一个收到数据的连接成为赢家**
（CAS 抢占），此后只有赢家的数据上送，其余静默丢弃；无赢家时写操作向所有连接群发。
TCP：所有端口并发拨号，第一个成功者返回，其余取消。

### 5.5 地址有效性校验

映射地址 IP 命中任一条即判无效：私网/环回/链路本地组播/未指定地址（说明 STUN 服务
器在局域网内或应答被劫持）；或与 STUN 服务器自身 IP 相同（防服务器把自己的地址当
映射返回）。

### 5.6 NAT 分类算法

输入过滤：只统计成功结果。分组维度 = **(网络, 本地IP:port, NAT公网IP)**——多出口
IP 天然各自成组，每个组合输出一条独立结论：

| 组内成功观测 | NAT 映射端口 | 本地端口 vs 映射端口 | 结论 |
|---|---|---|---|
| 1 条 | — | 相等 | easy |
| 1 条 | — | 不等 | hard |
| 多条 | 全部相同（EIM） | 相等 | easy |
| 多条 | 全部相同 | 不等 | hard |
| 多条 | ≥2 个不同 | — | symm |

relay 场景：探测走中继时结果 NatType 强制为 `"relay"`。

### 5.7 relay 双轮探测（编排层，`p2p.go:432`；不复刻）

- 无 relayConn：仅直连探测一轮。
- 有 relayConn 且非 Fallback 模式（`-x`）：仅经中继探测一轮。
- Fallback 模式（`-x2`）：**两轮——先直连后中继**，合并结果，任一有结果即不算失败。

---

## 6. 地址交换（Do_autoP2PEx2）

参照：`easyp2p/p2p.go:512`。总预算 **25s**。逐步：

1. 解析 bind → 本地出口 IP；无信令会话则新建（复用调用方传入的会话）。
2. 预订阅两个 topic（地址交换 + 轮次同步，QoS1）。
3. **STUN 探测**（§5）：按 §5.7 的三种模式；本步错误被吞掉，后续以地址为空判定。
4. **能力声明**：`caps = ["lan-probe", "lan-probe-canonical-v2", "multi-exit-udp-punch"]`
   （环境变量 `CAP_MEP_DEBUG=0` 可自我禁用多出口能力，前缀 `!`）。
5. **ECDH**：生成 P-256 密钥对（仅当需要共享密钥且本端有地址）。
6. **地址交换**：`exchangeAddressPayload` 经 MQTT 加密信封 mutual 交换：

```json
{ "addrs": [ {"network":"udp4","nattype":"easy","lan":"ip:port","nat":"ip:port"}, ... ],
  "pk": "<b64 未压缩 P-256 公钥>",
  "caps": ["lan-probe", ...] }
```

（`caps` omitempty，老版本自动忽略 → 视为全部不支持。）

7. 任一侧地址为空 → 失败 `"no common usable network types with peer"`。
8. **共享密钥**：`sharedKey = sha256(ECDH(本端私钥, 对端公钥).X)`；对端无公钥 → 报错。
9. **多出口统计**：按 v4/v6 分别统计两端唯一公网出口 IP 数（排除 relay）；
   `relayAvailable = 任一端存在 relay IPv4 地址`。
10. 候选构造/填充/排序（§7）→ 组装会话上下文（sharedKey、信令会话、出口计数、
    双端 caps）→ 触发 `OnAddressExchangeDone` 回调。

---

## 7. 候选生成、过滤与排序

参照：`easyp2p/p2p.go:322-428, 612-677, 2649`。

### 7.1 配对（笛卡尔积）

本地地址 × 远端地址，**仅同网络配对**。前置丢弃：任一侧 NAT 类型未知。

同网判定原语：
- `sameNAT` = 两端 NAT IP 相等，或两 NAT IP 属同一内网段。
- `similarLAN` = 两 LAN IP 属同一内网段（`IsSameLAN`：双 loopback；10.x 比 /8；
  172.16-31 与 192.168 比 /16；其余 v4 比 /24；IPv6 比 /64）。

### 7.2 过滤规则

| 组合 | 处置 |
|---|---|
| symm × symm，且非（sameNAT 且 similarLAN） | **丢弃**；例外：对端支持 LAN probe + tcp 网络 + 双方 LAN 均私网 → 转 **LANProbeOnly** 候选 |
| tcp × 任意，非同 NAT/LAN，且**双端都非 easy** | **丢弃**（TCP 打洞需至少一端 easy）；例外同上 → LANProbeOnly |
| 其余（UDP 全部、TCP 同 NAT/LAN、TCP 有一侧 easy） | 进入主列表 |

### 7.3 LANProbeOnly 候选的唯一化选择

从 lanProbeCandidates 中**只选一个** append 到主列表尾部：
- 对端支持 `lan-probe-canonical-v2`：用**方向无关 key**（两端点字符串
  `nattype+lan+nat` 排序后拼接）取字典序最小 → 双端独立计算也收敛到同一候选。
- 不支持：按 (远端序, 本端序) 最小（老版本兼容，可能不一致）。

### 7.4 多出口备选地址

对每个 udp4、非 LANProbeOnly、双端非 relay 的候选：收集全体远端 NAT 地址集合，
每个候选的备选集合 = 集合中除自身外的所有地址（多出口并行打洞目标）。

### 7.5 tcp4 剔除（多出口 UDP 优先）

同时满足才剔除非 LANProbeOnly 的 tcp4 候选：双端都声明 `multi-exit-udp-punch`；
非双端都有 IPv6；任一端 IPv4 出口数 > 1；存在有效 udp4 候选。

### 7.6 排序（SortP2PAddressInfos）

三级比较，降序：

1. **网络**：tcp6(4) > tcp4(3) > udp6(2) > udp4(1)
2. **NAT 组合分**：easy(4) hard(3) symm(2) relay(1)，比较**两端分之和**
3. **方向无关 tiebreaker**：每个候选取两端 `(NAT|LAN)` 字符串对**排序后**的有序对
   比较——两端看到的同一候选互换本/对后得到相同有序对，故两端排序结果完全一致
   （这是无中心协调下双端遍历相同候选顺序的关键）。

---

## 8. 角色选择与轮次同步

参照：`easyp2p/p2p.go:814, 1778`。

### 8.1 角色选择（SelectRole）

返回 Client（先发方）/ Server（监听方）。矩阵（本端 × 对端 → 本端角色）：

| 本端\对端 | easy | hard | symm | relay/其他 |
|---|---|---|---|---|
| easy | MD5 | **S** | **S** | MD5 |
| hard | **C** | MD5 | **C** | MD5 |
| symm | **C** | **S** | MD5 | MD5 |
| relay/其他 | MD5 | MD5 | MD5 | MD5 |

原则：非 easy 的一侧当 Client（主动打出开映射）；hard-symm 组合 hard 侧当 C。
MD5 tiebreak：`md5(本端LAN+NAT) ≤ md5(对端LAN+NAT)` → Client，两端互补恰一 C 一 S。
环境变量 `ROLE_DEBUG=C/S` 可强制覆盖（调试）。

### 8.2 轮次语义

- 公网打洞从 round=1 开始（每个候选尝试前自增），主循环上限 5 轮。
- **round=0 仅出现在 LAN 直连模式**：四步握手本身就是同步，跳过轮次同步
  （此时没有 MQTT 会话）。

### 8.3 轮次同步（round > 0 时，UDP/TCP 打洞前执行）

Client 发 `"C<n>"` 等 `"S<n>"`；Server 反之。经 MQTT 加密信封 mutual 交换，**超时 25s**。
收到后二次校验内容（不等则报错）。失败包装为**不可重试错误**，整个打洞立即终止
（对端已不在，重试无意义）。

---

## 9. 打洞主循环（Easy_P2P_MPWithOptions）

参照：`easyp2p/p2p.go:963`。

```
准备：展开网络 → 建/复用信令会话 → Do_autoP2PEx2（25s）
      → OnAddressExchangeDone 回调
状态：maxRounds=5；role 首次成功时锁定；relayModeAttempted 计数

遍历排序后候选：
  ① relay 插入时机（不复刻）：relayAvailable 且从未试过 relay 且已到最后一轮预算
     → 跳过所有非 relay 候选（保证 relay 在轮次耗尽前至少被尝试一次）
  ② round += 1；round > 0 → 轮次同步（25s，失败即整体终止）
  ③ tcp* → TCP 打洞；否则 → UDP 打洞
  ④ 成功：记录连接/角色/网络；非 multipath 立即返回
  ⑤ 失败：打印错误；不可重试 或 round ≥ 5 → 终止；否则歇 1s 试下一候选
```

全败返回 `direct P2P connection failed`。

---

## 10. UDP 打洞状态机

参照：`easyp2p/p2p.go:1126-1735`（`Auto_P2P_UDP_NAT_Traversal`）。

### 10.1 入口决策

1. 角色选择（§8.1）。
2. `sameNAT && similarLAN` → 直接打**对端 LAN 地址**（"same LAN" 路径）；
   否则打对端 NAT 地址。
3. **round=1 且满足 LAN probe 条件**（§13.1）→ 附加一个 LAN 探测目标
   （只是额外发包目标，不改变主目标）。

### 10.2 策略选择矩阵（非同 LAN 时）

| 本端\对端 | RDP（随机目的端口） | RSP（随机源端口） |
|---|---|---|
| easy / 非 easy | ✅ | — |
| 非 easy / easy | — | ✅ |
| easy / easy | 普通 | 普通 |
| 双非 easy | Client 启用 RDP | Server 启用 RSP |

**短 TTL**：仅 Client 使用（先发方的包死在对端 NAT 门口，开映射而不入内网）——
`TTL = 5`；多 IPv4 出口时 `TTL = 10`；Server / relay 模式 `TTL = 64`。

**窗口**（也是握手总超时）：参与方有非 easy → **18s**（= 4 + 2×7）；同 LAN 或双
easy → **8s**。

**Socket**：本端是 relay → 直接复用中继连接（不重建）；否则绑定 LocalLAN 新建 UDP
socket。任一端 relay → relay 模式：TTL=64、禁用全部随机端口策略。

### 10.3 reader（收包侧）

- 读缓冲 1024 字节，**接受任意来源**（对端 NAT 主地址 / 多出口 / LAN probe / RSP-RDP
  竞争对端的任意端口都可能回包）。
- **载荷匹配**：整包与 8 字节 ASCII 打洞载荷**精确相等**，不匹配丢弃继续读。
- 命中后（模拟 TCP 三次握手）：
  1. 停止 writer；
  2. 把连接远端绑定为**最后一包的实际来源地址**；TTL 恢复 64；立即回发一个载荷；
  3. **静默 250ms**（等对端完成对称确认、NAT 映射稳定）；
  4. **再发一个载荷**（双保险确认）；
  5. 上报成功。

### 10.4 writer（发包侧）时间表

```
Client：立即开始          Server：先等 2s（让 Client 先打出映射）
for i in 0..count(18 或 8):
    i > 0 时轮间隔 1s
    i < 3 : sendPing —— 仅普通 ping（先试直连）
    i >= 3:
        Client 且 TTL < 64：TTL += 1（逐轮摸 NAT 跳数）
        RSP 模式  : sendRSPPing(7s)（阻塞，§10.6）
        RDP 模式  : sendRDPPing()，然后额外等 3s（防止下一批打爆对端 NAT 映射表）
        对端 relay: sendPingOnNewPort（换随机源端口，§10.8）
        其余      : sendPing
```

**sendPing**（普通 ping）：向主目标发 1 包；成功后**附加**：向每个多出口备选地址各发
1 包；有 LAN probe 目标则再发 1 包。
`BIPA_DEBUG=1` 调试开关可让 ping 不真发（测生日悖论路径）。

### 10.5 RDP（随机目的端口，birthday attack）

- 目标 IP 集合 = 主 NAT IP + 全部多出口备选 IP。
- 每轮生成 600 个随机目的端口（范围 1024–65534，去重），发送前重设 TTL。
- 总发包量 = 600 × IP 数；**源端口固定**为本端打洞 socket 端口。
- 原理：对端 easy NAT 会为每个新目的地址开新映射，赌撞上对方已有的监听映射。

### 10.6 RSP（随机源端口，生日悖论）

1. 生成 650 个候选随机端口，逐个绑定本地 socket，**凑满 600 个即止**；每个设 TTL。
2. 每个绑定 socket 向**所有远端地址**（主 + 多出口备选）各发 1 包载荷。
3. 每个绑定 socket 一个监听任务（缓冲 32 字节，5s 读超时），只接受载荷精确匹配的包。
4. **第一个收到有效包的任务独占 claim**（once 语义）：
   - TTL 恢复 64 → 立即回发载荷 → 等 250ms → 再发（与 §10.3 相同的三连确认）；
   - **先关闭该 socket 再上报**（保证主流程能重新绑回该端口）；
   - 上报成功（本地地址 + 对端地址对）。
5. 其余任务空转退出；外层等待 7s（兜底 7.5s）后清理全部 socket。

### 10.7 EPERM/EACCES 处理（macOS 防火墙）

对端打洞包先到、被 macOS 应用防火墙拦截后，本 socket 会被限制向该地址发包
（发送返回权限错误）。处理：
- **路径 A（重建）**：用**同一本地地址**关闭并重建 socket（触发系统重新弹防火墙
  授权并立刻主动发包打通），重建后重发一次。
- **路径 B（重建失败）**：标记强制重绑，直接进入 finalize——用"只带端口不带 IP"的
  通配重绑方式拿回端口。

### 10.8 relay 模式的收发差异（不复刻）

- **本端 relay、对端公网**：不向对端 NAT 发任何打洞包（relay 在公网可直接收包，
  主动发反而触发对端 NAT 防火墙）。改为起独立任务：**每 2s 经中继连接向
  `127.0.0.1:65535` 发 1 字节 `"\n"`**——唯一目的是让本机系统防火墙放行该 socket
  的出站，使中继转入的包能到达。
- **本端公网、对端 relay**：正常 ping 3 轮后改用**换新源端口**探测：每次新建随机
  源端口 socket 向对端发 1 包，挂 5s 读超时监听；命中执行与 RSP 相同的 claim。

### 10.9 finalize（成功后的收尾）

- 拿到成功的地址对（主 socket 路径或 RSP/换端口路径）：
  - 关闭打洞期 socket；本端是 relay → 把中继连接包装为 net.Conn 复用；
  - 否则用（本地地址, 对端地址）**重新拨号建立 connected UDP socket**；
  - **新 socket 立即补发一个载荷**——打通本机防火墙。
- 超时/错误路径统一包装为 `P2P UDP hole punching failed: <原因>`。

### 10.10 时序图（easy × hard，Client = hard 侧…示例取 hard 为 C）

```
hard侧(C)                    各NAT                    easy侧(S)
  │                           │                          │
  │ (i=0..2) ping TTL=5 ─────▶ 死在easy侧NAT门口          │
  │                           │      （开映射）            │
  │                           │                          │ 等2s
  │                           │                          │
  │ (i>=3) RDP: 600随机目的端口▶▶▶                        │ ping(对hard侧NAT映射)
  │                           │   某包撞上easy侧监听映射 ──▶│
  │                           │◀────── 载荷(easy侧NAT源) ──│ ping 到达
  │ reader命中: 绑定来源,TTL=64│                          │
  │ 回发载荷 ────────────────────────────────────────────▶ │
  │ 静默250ms                  │                          │
  │ 再发载荷 ────────────────────────────────────────────▶ │ reader命中(对称)
  │ ◀──────────────────────────── 对端回发 ×2 ────────────│
  │ finalize: 重绑connected socket + 补发1包               │
```

---

## 11. TCP 打洞状态机

参照：`easyp2p/p2p.go:1808-1885, 1886-2391`（`Auto_P2P_TCP_NAT_Traversal`）。

### 11.1 前提与参数

- 角色/地址决策同 UDP（§10.1）；策略矩阵同 §10.2（TCP 版 RDP/RSP）。
- **硬前提**：非同 LAN 且**双端都非 easy** → 直接失败（"TCP 打洞需至少一端 easy"）；
  `lanProbeEnabled`（LAN probe 或 LANProbeOnly 候选）可绕过。
- **端口 +100 约定**（非同 LAN 时）：双方对称地把**四个地址**（本端 LAN、本端 NAT、
  对端 LAN、对端 NAT）的端口全部 +100（超 65535 回卷为 1024+余数），再用新端口
  listen/dial。动机：STUN 探测原端口的映射可能被 STUN 服务器的 FIN/RST 波及。
  原 LAN 端口与原远端 NAT 端口记录下来，后续随机端口时**跳过**。
- **主动拨号延迟**：Client / 同 LAN / LANProbeOnly → 0；否则（被动 S）**2s**。
- **总超时**：LANProbeOnly → 5s；round=0 且同 LAN → 8s；否则 25s。
- 单连接拨号超时 6s（LAN probe 例外 3s）。

### 11.2 listen 侧

- 绑定（+100 后的）本端 LAN 地址；socket 选项：Unix = SO_REUSEADDR + SO_REUSEPORT，
  Windows = 仅 SO_REUSEADDR（REUSEPORT 是同端口并发拨号与对端 listen 共存的关键）。
- accept 循环带总超时 deadline。
- **accept 来源校验**（peer IP 必须满足其一，否则拒绝该连接）：
  1. 等于选定路由的对端 IP；
  2. 同 NAT 且同内网段；
  3. 同 NAT 且等于对端 LAN IP；
  4. LAN probe 启用时：等于对端 LAN IP 或与本端同网段（放宽）。
- 校验通过 → 进入 ACK 握手（§11.4）→ 尝试提交。

### 11.3 dial 侧

并发信号量上限 **800** worker。节奏：

```
1. 被动侧先等 2s（activeDialDelay）
2. LAN probe：拨对端 LAN 地址（3s，reuseaddr）——LANProbeOnly 模式只做这一步
3. 直连尝试（同 LAN 或 easy×easy）：拨对端 NAT 地址（6s，reuseaddr）
   - round=0 且同 LAN（无轮同步）：每 250ms 重试直到超时
   - 失败升级：Client 再等 3s 后启用 RDP；Server 直接启用 RSP
4. 生日悖论循环：最多 3 大轮，每轮等全部在途任务收敛：
   - RDP：600 个随机目的端口（跳过对端原端口），本地复用主监听端口 + reuseaddr，6s
   - RSP：600 个随机本地源端口（跳过本端原端口），拨同一对端地址；
     其中第一个先当普通直连试（最多等 1500ms，防对端其实无 NAT）
```

### 11.4 punch ACK 协议

- 载荷 = 8 字节**二进制**（`deriveKeyForPayload(uid, ascii=false)`）。
- 每步 I/O 超时 5s，250ms 轮询粒度（可取消的完整读写，不截断半包）。
- 方向：**C 主动发，S 回**：
  - C：写 8 字节 → 读满 8 字节并校验相等 → 抢占本端唯一名额；
  - S：读满 8 字节并校验 → 抢占名额（抢占成功才回写 8 字节）。

### 11.5 连接收敛算法（ACK 选择器）

多条 TCP 连接可能同时打通（双向 accept/dial + RDP/RSP 并发），双方必须收敛到**唯一
一条**。三层机制：

1. **端内互斥**：每端一个"已选中"标志 + 锁。S 侧只有第一条完成读校验的连接能拿到
   名额并回写 ACK（回写失败**不消耗名额**，下一条还有机会）；其余连接直接淘汰关闭。
2. **C 侧闭环**：只有收到 S 回 ACK 的那条连接能通过 C 侧名额抢占。
3. **提交互斥**：整个打洞过程只允许一条连接提交成功；提交成功即取消全部在途尝试，
   落选连接随后被关闭。
- 两端选择可能短暂不对称（S 选了连接 a、C 的连接 b 先收到回包）——不对称的连接会
  因对端关闭而读写失败被淘汰，最终存活恰是"S 回过 ACK 且 C 收到并提交"的那一对。

### 11.6 错误宽限与失败路径

- dial/accept 侧的终结性错误先**等 1s 宽限**（可被取消）再上报——让"已完成 ACK 但
  尚未提交"的成功连接赢得竞态。
- 主 select：成功连接 / 错误 / 父 ctx 取消 / 总超时（"Timeout"）。
- 轮同步失败 → 不可重试，整体终止（同 §8.3）。

---

## 12. LAN 直连模式（-lan）

参照：`easyp2p/lan.go`。不依赖 STUN/MQTT，纯组播发现 + 直连。

### 12.1 组播层

- 组播组 `239.255.255.250:19730`（SSDP 同款），magic `"GONC-LAN-V1"`，组播 TTL=2
  （可跨一层路由），允许本机回环（配合自滤）。
- 加入全部 Up+Multicast 接口，全失败回退系统默认接口。
- 每条消息：外层 JSON `{m: magic, t: 类型, p: base64(内层JSON), mac: HMAC}`，
  HMAC-SHA256 覆盖 `类型 + "|" + payload`（类型参与 MAC 防混淆）；密钥/SessionID
  派生见 §4。
- **单读协程分发模型**：唯一 goroutine 读 socket，按类型分发到 4 个带缓冲(32)通道，
  满则丢弃——消除 initiator/responder 同进程双角色争抢 socket 的问题。

### 12.2 四步握手（B→R→C→A）

双方**同时运行 initiator 和 responder**，谁先完成用谁的结果。

**Initiator**：

```
生成 nonceA(16B) → 组播 Beacon{sid, nonceA, transport}
  beacon 节奏：主动=前30s每1.5s，之后每5s；被动=启动突发250ms/750ms/4s/10s，之后每15s
等 Response：校验 NonceA 回显
  → localIP=到对端出口IP；transport 协商；punchPort=惰性分配的空闲端口(进程级一次)
发 Confirm{nonceB回显, transport, 本端IP, punchPort}：立即3轮×50ms，之后每300ms重发
等 Ack：校验 NonceA 回显 → 完成（本端端口=punchPort，对端地址取自 Response）
```

**Responder**：

```
等 Beacon：校验 SessionID + 非自己回环 + 非同机（对端IP==本机出口IP 则跳过）
生成 nonceB → 发 Response{nonceA回显, nonceB, transport, 本端IP, punchPort}：3轮×50ms
每300ms重发 Response，同时等 Confirm（校验 nonceB 回显；10s 超时→回到 Beacon 监听）
发 Ack{nonceA回显}：8轮×100ms → 完成（对端地址取自 Confirm 消息体）
```

认证三道闸：每条消息的 magic+HMAC；SessionID 匹配；每步 nonce 回显。
只有持同一口令的对端能通过。

**transport 协商**：任一方偏好 udp 即 udp，否则 tcp。
**punchPort 惰性分配**：进程级仅一次空闲端口探测，且只在认证后的对端出现后才分配
（避免无谓占用、避免端口号泄露给未认证方）。

### 12.3 发现后转打洞

- 候选构造为**全 easy**：LocalLAN=LocalNAT=本端地址、RemoteLAN=RemoteNAT=对端地址
  → 下游判定"同 LAN"，直接走内网直连路由。
- `sharedKey = sha256("gonc-lan-shared-" + sessionKey)` 作为后续 PSK。
- 调用 UDP/TCP 打洞状态机，**round=0**（跳过轮次同步——四步握手已同步双方时机）。
- 被动模式（`-lan-passive`）：低频 beacon（15s）适合长期值守端。

---

## 13. LAN Probe（公网流程中的内网旁路）

参照：`easyp2p/lan_probe.go`、`p2p.go` 相关段。

**动机**：双方实际在同一物理内网，但因多出口 IP 或跨子网被误判为"不同网络"时，
用一次真实的直连探测来验证。

### 13.1 触发判定（shouldTryLANProbe，全部满足）

1. 当前未被判定同 LAN；
2. **round == 1**（仅首轮）；
3. 双方 LAN IP 均可解析；
4. **网关+内网场景**直接触发：双方 NAT IP 相同，且恰一方"运行在网关上"
   （LAN==NAT）、另一方 LAN 为私网地址；
5. 否则要求双方 LAN IP 均为私网地址；
6. 双方都直接持有公网 IP（都 LAN==NAT）→ 不触发（无 NAT 无需旁路）。

### 13.2 两种形态

- **附加目标**（UDP，round=1）：主 NAT 打洞的同时额外向对端 LAN 地址发探测包。
- **LANProbeOnly 候选**（§7.2）：symm×symm / TCP 双非 easy 被丢弃时降级生成的
  "仅内网探测"候选：
  - TCP：绕过"至少一端 easy"硬检查；总超时 5s；只拨对端 LAN 地址（3s）；
    失败报 "LAN probe failed, no other punching method available"；
    accept 侧来源校验放宽到"与本端同网段"。
  - 能力开关：对端须声明 `lan-probe`；唯一候选选择须 `lan-probe-canonical-v2`
    才能双端一致（§7.3）。

---

## 14. SOCKS5 UDP 中继（relay）

> **不复刻**：p2premote-punch-rs 按决策不实现中继（FFI 的 `allow_relay` 维持拒绝）。
> 本章仅作为 gonc 完整设计记录保留。

参照：`apps/socks5u.go`（客户端）、`apps/proxyclient.go`、`p2p.go` relay 部分。
gonc 不设内置中转服务器——用一台公网 VPS 跑 gonc 的 SOCKS5 服务（支持 UDP
ASSOCIATE），P2P 失败时一端经它中转，相当于把本端 NAT 行为变成 easy。

### 14.1 relayConn 来源

- CLI `-x`（前置代理，全程生效）或 `-x2`（**仅 P2P 失败后降级**，Fallback 模式）。
- 仅支持 socks5 协议；解析为代理客户端后，以目标 `":0"` 发起 **UDP ASSOCIATE**，
  得到一个 `net.PacketConn`（中继 UDP 通道），包装为 `RelayPacketConn` 注入打洞选项。

### 14.2 UDP ASSOCIATE 客户端流程

```
① TCP 控制连接拨到 SOCKS5 服务器（可选先做安全协商，导出密钥材料加密后续 UDP）
② SOCKS5 握手：方法协商（无认证 0x00 / 用户密码 0x02）
③ 发 UDP ASSOCIATE 命令(0x03)：VER 05 CMD 03 RSV 00 ATYP DST.ADDR DST.PORT
④ 读响应得 BND.ADDR/BND.PORT（中继 UDP 端点）
   BND 为 0.0.0.0 或私网 IP 时 → 改用 TCP 控制连接的对端 IP（标准修正）
⑤ 本地 UDP socket 连接到中继端点；此后所有 UDP 数据报前加 RFC1928 头部：
   RSV(2B=0) FRAG(1B=0) ATYP DST.ADDR DST.PORT | DATA
   读方向按 ATYP 还原真实源地址（域名以 NameUDPAddr 保留）
⑥ TCP 控制连接存活期间 UDP 关联才有效：挂监视任务，TCP 断开即关 UDP
```

### 14.3 relay 在打洞中的接入

- **探测**：§5.7——中继 STUN 得 `nattype="relay"` 的候选地址。
- **候选排序**：relay 参与优先级（分值 1，最低）。
- **主循环**：relayAvailable 时保证最后一轮前至少尝试一次 relay 候选（§9 ①）。
- **UDP 打洞行为**（§10.8）：本端 relay 复用中继连接、TTL 64、无生日悖论、只向
  `127.0.0.1:65535` 每 2s 发 1 字节打通本机防火墙；对端 relay 时本端 3 轮普通 ping
  后换随机源端口探测。relay 只挂 UDP 路径（TCP 分支不传中继连接）。

---

## 15. 唤醒机制（mqtt-wait / mqtt-hello）

参照：`easyp2p/p2p.go:2393-2613`。用途：等待端长期挂机（如 `-mqtt-wait -k`），
发起端用 hello 唤醒后再打洞；同时携带控制参数（如加密套件建议）。

### 15.1 通道与消息

- topic salt = `"nat-exchange-wait/" + deriveKeyForTopic("mqtt-topic-gonc-wait", uid)`。
- 消息（经 MQTT 加密信封）：
  - 发起端 → `"SYN@" + tid + HelloPayload字符串`
  - 等待端 → `"ACK@" + tid`
  - `tid` = 10 随机字符（关联与去重）。
- **HelloPayload 序列化**：`";k1=v1;k2=v2|App::Param"`——Control 段整体以 `;` 开头
  （下标 0 留给真实 salt，解析时跳过）；App 段 `::` 分隔。控制值大小写不敏感。

### 15.2 会话语义

- **MqttWaitSession（等待端）**：waitOnly 只收 `SYN@` 前缀；收到后**回 ACK 到收到
  SYN 的那台 broker**（首选 broker 发布，15s 超时；失败回退全 broker）。
- **MQTTHelloSession（发起端）**：mutual 模式持续 burst 重发 SYN，等 `ACK@tid`
  **逐字节相等**。
- 便捷包装函数在返回后 5s 才关会话（供迟到的 ACK/重发）。
- CLI 层：wait 挂 **30 分钟**，hello **15s**；唤醒返回的 topicSalt 拼进
  `sessionUid = p2pSessionKey + topicSalt`（与该对端独享 topic，避免多端点错乱）；
  hello 载荷的 `cs` 控制值可覆盖加密套件（仅接受 ss/tls）。

---

## 16. CLI 层编排：P2P 与 LAN 竞速仲裁

参照：`apps/p2p_candidate.go`、`apps/nc.go:3505-3711`。

场景：`-p2p-with-lan`（+ `-mqtt-wait` + `-k`）时公网 P2P 与 LAN 直连**并发竞速**。

### 16.1 pendingP2PCandidate（"夺取所有权"原语）

- `arm(cancel)`：注册新取消函数，**立刻以 "superseded" 取消上一个**（同路径重试砍旧上下文）。
- `disarm(token)`：token 匹配才清空——确认所有权。
- `cancelCurrent(superseded)`：LAN 成功后调用，砍掉挂起中的公网 P2P。

### 16.2 定牌时机（取决于有无确定性握手边界）

| 情形 | 定牌时机 |
|---|---|
| 加密套件有确定握手边界（tls；ss+强制 UDP；plain+KCP） | 等 `Easy_P2P_MPWithOptions` **完整返回**后 disarm（竞速窗口可安全覆盖到连接建立） |
| 无边界 | **MQTT 地址交换完成时**（`OnAddressExchangeDone` 回调）即 disarm——此后 LAN 抢到也不能取代，避免对端已投入打洞却被单方面放鸽子 |

### 16.3 双道闸

1. 打洞返回后若所有权已被 LAN 夺走：关闭全部连接与 relayConn，返回 superseded
   （该错误不上报为普通失败；`-k` 模式继续下一轮等待）。
2. secure 协商完成后再查一次取消原因——覆盖"协商期间被 LAN 抢先"的竞态。

主动双路径（`runP2PAndLanActiveMode`）结构类似：先完成者胜，失败重试间隔 10s。

---

## 17. 打洞成功之后：安全协商的密钥来源

打洞产出 `P2PConnInfo`（含 `SharedKey`、`IsClient`），CLI 层按加密套件装配密钥：

| 套件 | 密钥 | 传输栈 |
|---|---|---|
| 默认（tls） | **用户口令** 作 PSK | TCP → TLS 1.3；UDP → KCP + DTLS |
| ss | `SharedKey`（ECDHE 派生）；LAN 模式用 LAN 派生密钥 | TCP → ss 流加密；UDP → KCP + dss |
| plain（+autoPSK） | `SharedKey`；LAN→PSK 型，公网→ECDHE 型 | 无加密（可选自动 PSK） |

（p2premote-punch fork 已删除 secure 栈并固定明文 UDP——见 §20。）

---

## 18. 底层网络原语（netx）设计要点

### 18.1 BoundUDPConn（绑定单远端的 UDP conn）

- 把 PacketConn 收窄为"只与一个固定远端对话"的 net.Conn 语义；**raddr 为空 = 接受
  任意来源**（打洞 reader 依赖此行为）。
- 读循环 250ms 轮询 deadline；可选空闲超时回收。
- `Rebuild`：同本地地址关旧建新 socket——macOS 防火墙 EPERM 处理（§10.7）的核心。
- 共享 socket 场景（relay）`keepOpen`：Close 不真关底层。

### 18.2 UDPSession（单 socket 1→N 会话复用）

- 一个本地 UDP socket 上按**远端地址**维护多条虚拟会话连接（map，同远端可挂多条）；
  读循环统一 ReadFrom → 引用计数包 → 按远端广播到各会话通道（满则丢包）。
- 未知远端的首包 → 创建 accepted 会话并上送 accept 通道。
- 10s 内刚关闭远端的新包直接丢弃（防残留包干扰）；30s 周期清理该表。
- **意义**：STUN 多服务器探测共享同一本地端口（NAT 分类正确性，§5.2）、
  relay 场景复用中继 socket。

### 18.3 DialRace（同主机多端口竞速）

UDP：每端口一条会话连接并发读，首包者 CAS 称王，此后只上送赢家、写只写赢家
（无赢家时群发）；TCP：并发拨号首成者胜。用于 STUN 多端口与打洞多候选端口。

### 18.4 socket 选项与 TTL 控制

| | Unix | Windows |
|---|---|---|
| ControlTCP（listen/dial 并发同绑） | SO_REUSEADDR + SO_REUSEPORT | 仅 SO_REUSEADDR |
| ControlUDP | 仅 SO_REUSEADDR | 仅 SO_REUSEADDR |
| SetUDPTTL | `setsockopt(IPPROTO_IP, IP_TTL)` | 同（WinSock） |

低 TTL 包"只到网关不出公网"，用于敲门/防火墙打通；64 为恢复正常值。

### 18.5 FramedConn（帧协议）

- 2 字节小端长度前缀 + 载荷，最大帧 65535；**长度 0 的帧 = EOF**（半关闭语义）。
- 用途：把流式连接（TCP/中继）包出报文边界，使 KCP 等"每次 Read 恰好一个包"的
  协议可跑；优雅关闭时保证 EOF 帧发出（至少等 1500ms）。

### 18.6 contextio（可取消的完整读写）

在"必须精确读写 N 字节"的循环中，每次底层 IO 的 deadline = min(轮询粒度, 总超时,
ctx 截止)——取消延迟上界 = 轮询粒度，同时保持整包语义。TCP punch-ACK 握手用它
（5s 超时 / 250ms 粒度）。

### 18.7 udp_bridge（转发器热切换）

本机回环建一对互联 UDP（A↔B）：B 给 KCP 当底层，A 在 B 与"可替换的外部转发连接 C"
之间搬运；`SetForwarder(newC)` 热切换（新 C 专属读循环，非 UDP 先包 FramedConn；
旧 C 踢出）。支持"打洞成功后业务流从旧路径切到新直连路径"。

---

## 19. 常量速查总表

| 类别 | 常量 | 值 |
|---|---|---|
| **打洞** | 打洞短 TTL | 5（多 IPv4 出口时 10；relay/Server 恢复 64） |
| | 随机端口数 | 600（RSP 绑定候选 650；端口范围 1024–65534） |
| | Client TTL 递增 | 每轮 +1 至 64（第 4 轮起） |
| | UDP 窗口 | 18s（有非 easy 参与） / 8s（同 LAN 或双 easy） |
| | UDP 轮间隔 / Server 启动延迟 | 1s / 2s |
| | 普通 ping 轮数（前 N 轮只用 ping） | 3 |
| | RDP 后等待 | 3s（RPP_TIMEOUT=7 的一半） |
| | RSP 超时 / 兜底 | 7s / 7.5s；单 socket 读超时 5s |
| | 三连握手静默 | 250ms |
| | 主循环轮次上限 / 失败歇 | 5 轮 / 1s |
| | 轮同步超时 | 25s |
| **TCP** | 端口偏移 | +100（超界回卷 1024+余数） |
| | 并发 worker 上限 | 800 |
| | 生日悖论大轮数 | 3（每轮全量收敛） |
| | 总超时 | 25s / 8s（round0 同 LAN）/ 5s（LANProbeOnly） |
| | 单连接拨号超时 | 6s（LAN probe 3s） |
| | ACK 握手 | 载荷 8B 二进制；单步 5s / 轮询 250ms |
| | 错误宽限 / 非同步同 LAN 重试 | 1s / 250ms |
| | 直连失败升级前 Client 等待 | 3s |
| **STUN** | 服务器数 / RTO / 每轮预算 | 6 / 120ms / 2828ms |
| | 空闲端口探测尝试 | 100 次（TCP+UDP 均可绑） |
| **MQTT** | broker 数 / 连接超时 / 重连间隔 | 4 / 5s / 3s |
| | exchange QoS | 1 |
| | 发布 burst / ticker / 保活 / settle / 首选窗口 | 200ms,800ms,2s / 2s / 5s / 500ms / 800ms |
| | 地址交换预算 | 25s |
| **LAN** | 组播 | 239.255.255.250:19730，TTL 2 |
| | beacon：主动/被动 | 前 30s 每 1.5s 后每 5s ／ 突发 250ms,750ms,4s,10s 后每 15s |
| | Confirm 重发 | 3 轮×50ms + 每 300ms |
| | Ack 重发 / Confirm 超时 | 8 轮×100ms / 10s |
| | nonce 长度 / 分发通道缓冲 | 16B / 各 32 |
| **唤醒** | wait 挂机 / hello 超时 / ACK 发布超时 | 30min / 15s / 15s |
| | tid 长度 / 会话兜底关闭 | 10 字符 / 5s |
| **其他** | UDP 读缓冲（reader / RSP 监听） | 1024B / 32B |
| | relay 防火墙敲门 | 每 2s 向 127.0.0.1:65535 发 1 字节 `"\n"` |

---

## 20. 附录：p2premote-punch fork 的偏差

p2premote-punch（Rust 复刻的接口蓝本）相对 gonc v2.6.9 的主要改动，复刻时以**协议
行为**为准、以 fork 的**接口形态**为蓝本：

| 改动 | 说明 |
|---|---|
| 删除 secure 协商栈 | 固定**明文 UDP** 传输（打洞产物直接做 UDP 转发，不做 TLS/DTLS/KCP/SS） |
| LAN + Internet 联合穿越 | `udp_tunnel.go`：`traversal_mode = auto/lan/internet` 双端经 MQTT 协商，LAN 失败回退公网 |
| 被动端流量审批（approval gate） | 被动端可要求放行后才转发流量 |
| `MQTT_ExchangePayload` | 新增 FFI 用的密钥/地址交换原语（topic 前缀 `wgvpn-kx/`） |
| punchffi C ABI | 桌面客户端 JSON-in/JSON-out 接口（22 符号，p2premote-punch-rs 已 1:1 镜像） |
| 协议规范 | `protocol/client-client/` 为 Go/Rust/Android 三端对齐的契约真源 |
| userspace WireGuard 数据面 | wintun/utun + 用户态 TCP 栈（p2premote 扩展，非 gonc 范畴） |
