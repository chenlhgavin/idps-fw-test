# 用 fw-verify 测试 idps-fw 全部功能

本文以 **`fw-verify.exe` 编排器**为主线，逐项验证 `idps-fw` 的全部功能。每个用例就是**一条命令**：

```bat
fw-verify.exe --config fw-verify.conf run default-deny-carveout
```

`fw-verify` 会自己**下发该用例规则 → 起监听 → 取水位线 → 发流量 → 判 enforcement + 事件 + 上报**，最后打印 `PASS`/`FAIL`。你不需要手动 `echo`/`push`/`provision-rule`/`traffic`/`dump-events`。

> 每个用例后面都附一段「**内部原理 / 手动复现**」——把那条 `run` 拆成等价的 `fw-agent` + adb 单步命令。**正常测试用不到它**；只有当某条用例 `FAIL`、需要逐步定位时，才照着手工复现。设备侧 `fw-agent` 子命令与编排设计的完整说明见 [`fw-verify-design.md`](./fw-verify-design.md)。

约定（按你的环境替换，写进 `fw-verify.conf`，见 §2.1）：

| 角色 | adb 序列号 | wlan0 IP | 说明 |
|---|---|---|---|
| TARGET（A 机） | `79MV5T5D85RSINQG` | `172.20.10.3` | 跑 idps-fw + idps-server，被测对象 |
| PEER（B 机） | `XGRWZXVSUKXW7XMF` | `172.20.10.2` | 对端流量收发方 |

下文命令以 **Windows cmd** 为准；手动复现块里的 `fw-agent`/adb 字面量已写成上表的序列号/IP，拷贝即可执行（换设备时全局替换这四个值）。Linux/macOS/Git-Bash 的等价写法见 §3 末尾。

---

## 1. fw-verify 命令速查

所有日常命令都带 `--config fw-verify.conf`。设备、IP、接口、超时、上报确认等高级配置写在配置文件里，普通命令行不再展开这些参数。

| 命令 | 作用 |
|---|---|
| `preflight` | 校验两机在线、idps-fw 可响应、两机都有 fw-agent |
| `list` | 列出全部 case-id 及其分组 |
| `run <id>` | **跑单条用例**：下发规则→起监听→发流量→判 enforcement + 事件 + 上报→`PASS`/`FAIL` |
| `run-group <组>` | 跑整组（`ingress\|default\|egress\|app\|match\|detection\|traffic`），每个 bundle 只下发一次 |
| `run-all` | 按 bundle 批量跑完整目录 |

高级/准备/排障命令仍可直接执行，但不会出现在默认 `-h` 里：

| 命令 | 作用 |
|---|---|
| `apply-fast-profile` | **一次性准备**：注入 keystore + `identity_overrides` + 短轮询配置并重启 idps-fw/idps-server |
| `restore-profile` | 从 `/etc/idd/idps-fw.yaml.fwv-bak` 还原配置并重启 idps-fw |
| `ensure-keystore [--vin V --dsn D]` | 仅补运行时 keystore（`apply-fast-profile` 已含此步，单独用得少） |
| `provision <规则文件> [--traffic-cycle N]` | 手动下发一份明文规则（+可选把 fun=4 周期设为 N 秒） |
| `reset-rules` | 删除已下发的 depot 规则，回退默认 |
| `health` | 打印 TARGET 的 `idps-fw health` 快照 |
| `stats` | 打印 TARGET 的 `idps-fw statistics` 快照 |

典型流程：`preflight` →（一次性准备时）`apply-fast-profile` → `list` 看清 case-id → `run <id>` / `run-group <组>` / `run-all` → 完事按需 `restore-profile` + `reset-rules`（§7）。

---

## 2. 准备（一次性）

### 2.1 写 `fw-verify.conf`

拷贝 [`fw-verify/fw-verify.conf.example`](../fw-verify/fw-verify.conf.example) 为 `fw-verify.conf`，至少填两机序列号；IP 留空会自动从网卡探测，建议显式写死：

```ini
target_serial = 79MV5T5D85RSINQG
peer_serial   = XGRWZXVSUKXW7XMF
target_ip     = 172.20.10.3
peer_ip       = 172.20.10.2
# 应用/UID 用例（§4.4）的映射，apply-fast-profile 会按此注入 identity_overrides
app_uid          = 2000
app_identity_key = com.demo.browser
# 上报确认方式：local（默认，查设备 report_state=sent）| server（查 idps-server 日志）| vsoc
# report_confirm = local
```

### 2.2 两机装好 fw-agent + 依赖库，再 preflight

`fw-agent` 复用 idps-core，需要 `libidps_device_provider.so`。用包里的 `install.bat` 对**两台**各装一次（缺失时会自动补 `/system/lib64/libidps_device_provider.so`）。然后用 `preflight` 一次性确认两机连通、idps-fw 可响应、两机都有 fw-agent：

```bat
fw-verify.exe --config fw-verify.conf preflight
:: 全绿才往下走；若某机报 fw-agent/.so 缺失，回到 install.bat 重装那台
```

### 2.3 apply-fast-profile —— 一步搞定 keystore + 身份 + 短轮询

默认 idps-fw 每 60s 才拉一次规则、流量窗口 1800s 才关一次，手动测会等很久；depot 规则加解密又依赖 keystore；应用策略还要 `identity_overrides`。这些 `apply-fast-profile` **一条命令全包**：

```bat
fw-verify.exe --config fw-verify.conf apply-fast-profile
```

它做完后即可直接跑 §4 的任意 `run`。

> **内部原理 / 手动复现**——`apply-fast-profile` 等价于下面三件事，平时无需手动做：
>
> 1. **补 keystore**（=`ensure-keystore`）。depot 规则加解密依赖 `/data/idd/keys/aes.keystore`，它由 idps-server 从 VIN+DSN 派生。台架 provider 不给 VIN/DSN 时，写一对 debug 文件喂进去（值任意，只要一致），重启 idps-server 让它自己派生：
>    ```bat
>    adb -s 79MV5T5D85RSINQG shell "echo FWVERIFYTEST00001 > /data/idd/vin_debug; chmod 644 /data/idd/vin_debug; restorecon /data/idd/vin_debug 2>/dev/null"
>    adb -s 79MV5T5D85RSINQG shell "echo FWVERIFYTESTDSN01 > /data/idd/dsn_debug; chmod 644 /data/idd/dsn_debug; restorecon /data/idd/dsn_debug 2>/dev/null"
>    adb -s 79MV5T5D85RSINQG shell "stop idps-server; start idps-server"
>    adb -s 79MV5T5D85RSINQG shell ls -l /data/idd/keys/aes.keystore   :: 应出现该文件
>    ```
>    > 身份解析优先级：config > debug(`/data/idd/<field>_debug`) > provider；fw-agent 与 idps-server 读同一身份，于是用同一把 key。
> 2. **写短轮询配置并重启 idps-fw**。备份 `/etc/idd/idps-fw.yaml` 到 `.fwv-bak`，整文件覆盖成短间隔版（`rule_poll_interval_secs: 3`、`traffic_cycle_secs: 5`、`event_poll_interval_ms: 100` 等），并注入 §4.4 用的 `identity_overrides`（`com.demo.browser` → uid 2000），再 `stop idps-fw; start idps-fw`，等到 health `connected=true`。
> 3. **无需手动下发首批规则**：每条 `run`/`run-group`/`run-all` 内部都会先写 fun=4 流量策略（cycle=5），idps-fw 才能离开 `RuleSyncing`；fun=1 防火墙规则随用例 bundle 一起下发。所以你不用像纯手动那样先垫一条基线规则。

确认就绪（可选）：

```bat
fw-verify.exe --config fw-verify.conf health
::  -> phase:"Running"(或 DataPlaneReady)、connected:true、traffic_cycle_secs:5
```

---

## 3. 一条用例怎么跑（`run` 的内部模型）

理解下面这套步骤，所有 §4 的「手动复现」块就都看得懂了。

**普通用例（enforcement + 事件类）**，`fw-verify ... run <id>` 内部依次做：

1. **下发规则**：先写 fun=4 流量策略（cycle=5s），再把该用例所属 *bundle* 的 fun=1 防火墙规则下发到 depot（等价手动 `echo` 规则 → `adb push` → `fw-agent provision-rule --fun 1`）。一组用例共享同一 bundle，`run-group` 只下发一次。
2. **起监听**：仅「放行类」用例需要——在收包侧 `fw-agent listen`，绑定后等 0.5s（否则连接会 `refused`，被误判成失败）。
3. **取水位线**：`fw-agent now` 的 `now_ms`，作为本用例事件起点。
4. **发流量**：从发起侧 `fw-agent traffic ...`（应用/UID 用例用 `su <uid>` 发），超时 1500ms。
5. **沉淀**约 `event_settle`（默认 1500ms）后 `fw-agent dump-events --since 水位线`。
6. **判定**（三者全过才 `PASS`）：enforcement 与期望（`blocked`/`allowed`）一致；事件的 `kind/action/proto/src_ip/dst_port/rule_id` 与期望一致；产生事件时 `report_state=sent`（已上报 idps-server）。

**流量统计类用例（§4.7）** 走另一条路：发流量前后各取一次 `idps-fw statistics`，发完等 7s 让窗口（cycle=5s）关闭，比对 `ingress_bytes/global_traffic_windows`（global）或 `egress_bytes/app_traffic_windows`（per-app）是否增长。

> **规则文本格式**（手动复现块里 `echo` 出来的内容）：每行一条，无空行/注释，`rule_id = 行号`（靠后优先）。
> - 默认入向：`chain=localin,action=P|LP|LD|NLD`
> - 应用策略：`prog=<key>,action=LP|LD`
> - 五元组：`sip=..,dip=..,sport=..,dport=..,proto=tcp|udp|icmp|*,action=P|LP|LD|NLD,chain=localin|output`
>
> **动作语义（与 vendor 对齐）**：`P`=放行(无事件)；`NLD`=静默拦截(无事件)；
> - **入向 `LP`/`LD`**：`LP` 放行、`LD` 拦截，但**单连接都不产逐条事件**——它们只把入站新连接首包喂给**全局端口扫描检测器**；只有判为 `PortScan`(≥3 个不同目的端口/≈1s) 或 `ConnectionAbnormal`(同一目的端口被 ≥4 个**不同流**命中) 才产事件。
> - **出向 `LP`**=放行**无事件**（vendor 出向无 LPASS 日志）；**出向 `LD`**=拦截 + `NetworkBlock` 事件。
>
> **事件来源只剩四类**：入向 `PortScan` / `ConnectionAbnormal`（全局检测）、出向 `LD` 的 `NetworkBlock`、应用拒绝 `PolicyDeny`。**入向永不产 `NetworkBlock`/100**。
> **事件字段**：`dump-events` 输出 `event_type∈{NetworkBlock,PortScan,ConnectionAbnormal,PolicyDeny}`、`action∈{Pass,Alert,Block,BlockSilent}`，以及 `detail` 文案（如 `"tcp portscan attack"`、`"tcp fin portscan attack"`、`"translation layer --tcp state unnormal"`、`"connection state invalid attack"`）。连接异常的协议事件号为 **221(TCP)/222(UDP)**，由 `event_type`+`proto` 区分。

> **手动复现的通用骨架**（Windows cmd；把规则/端口/proto/发起方换成各用例值）：
> ```bat
> :: ①下发规则  ②查 health 确认 firewall_rule_ver 变大  ③放行类才起 listen
> :: ④取水位线   ⑤发流量   ⑥dump-events --since 水位线
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --dport <PORT> --timeout-ms 1500
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ```
> Linux/macOS/Git-Bash：`listen` 末尾加 `&` 放后台；水位线用 ``NOWMS=$(adb -s 79MV5T5D85RSINQG shell fw-agent now | sed 's/[^0-9]//g')``，`dump-events` 用 `--since $NOWMS`。`.bat` 里 `for /f` 的 `%A` 写成 `%%A`。

---

## 4. 逐功能用例

每节先给 `fw-verify` 命令（主线），再给期望表，最后附「内部原理 / 手动复现」。`list` 可随时列出全部 case-id。

### 4.1 入向五元组四种动作（P / LP / LD / NLD）

```bat
fw-verify.exe --config fw-verify.conf run ingress-tuple-pass
fw-verify.exe --config fw-verify.conf run ingress-tuple-alert
fw-verify.exe --config fw-verify.conf run ingress-tuple-block
fw-verify.exe --config fw-verify.conf run ingress-tuple-blocksilent
:: 或一次跑完本节四条
fw-verify.exe --config fw-verify.conf run-group ingress
```

| 用例（case-id） | 期望 enforcement | 期望事件 |
|---|---|---|
| `ingress-tuple-pass`（5001） | allowed | 无 |
| `ingress-tuple-alert`（5002） | allowed | **无事件**（入向 LP 单连接不产事件） |
| `ingress-tuple-block`（5003） | blocked（超时） | **无事件**（入向 LD 单连接不产事件，仅扫描才产） |
| `ingress-tuple-blocksilent`（5004） | blocked | 无事件 |

> **内部原理 / 手动复现**——`ingress` bundle 下发的规则与各 case 的发流量：
> ```bat
> (
> echo chain=localin,action=P
> echo sip=172.20.10.2,dip=172.20.10.3,dport=5001,proto=tcp,action=P,chain=localin
> echo sip=172.20.10.2,dip=172.20.10.3,dport=5002,proto=tcp,action=LP,chain=localin
> echo sip=172.20.10.2,dip=172.20.10.3,dport=5003,proto=tcp,action=LD,chain=localin
> echo sip=172.20.10.2,dip=172.20.10.3,dport=5004,proto=tcp,action=NLD,chain=localin
> )>ingress.rule
> adb -s 79MV5T5D85RSINQG push ingress.rule /data/local/tmp/rule.txt
> adb -s 79MV5T5D85RSINQG shell fw-agent provision-rule --fun 1 --input /data/local/tmp/rule.txt
> adb -s 79MV5T5D85RSINQG shell idps-fw health | findstr firewall_rule_ver
>
> :: Block(5003) —— 拦截类，无需监听
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --dport 5003 --timeout-ms 1500
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> verdict=blocked，但 dump-events 无新事件（入向 LD 单连接不产事件）
> ::  BlockSilent(5004)：--dport 改 5004，verdict=blocked 且无事件
>
> :: Alert(5002)/Pass(5001) —— 放行类，先在 TARGET 后台起监听
> start /b adb -s 79MV5T5D85RSINQG shell fw-agent listen tcp --port 5002 --duration-secs 30
> timeout /t 1 /nobreak >nul
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --dport 5002 --timeout-ms 1500
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> allowed 且无事件（入向 LP 单连接不产事件）；Pass(5001) 同法换端口，allowed 且无事件
> ```

### 4.2 默认入向策略（deny / allow）

```bat
fw-verify.exe --config fw-verify.conf run default-deny-blocks
fw-verify.exe --config fw-verify.conf run default-deny-carveout
fw-verify.exe --config fw-verify.conf run default-allow
:: 或一次跑完
fw-verify.exe --config fw-verify.conf run-group default
```

| 用例（case-id） | 含义 | 期望 |
|---|---|---|
| `default-deny-blocks`（5102） | 默认拒绝下，未列端口 | blocked，**无事件**（入向单连接不产事件） |
| `default-deny-carveout`（5101） | 默认拒绝下，放行例外端口 | allowed，无事件 |
| `default-allow` | 默认放行 | allowed，无事件 |

> **内部原理 / 手动复现**——`default_deny` bundle 下发「默认拒绝 + 放行 5101」一条规则，两 case 共享：
> ```bat
> (
> echo chain=localin,action=LD
> echo sip=172.20.10.2,dip=172.20.10.3,dport=5101,proto=tcp,action=P,chain=localin
> )>default-deny.rule
> adb -s 79MV5T5D85RSINQG push default-deny.rule /data/local/tmp/rule.txt
> adb -s 79MV5T5D85RSINQG shell fw-agent provision-rule --fun 1 --input /data/local/tmp/rule.txt
>
> :: default-deny-blocks：未列端口(5102) → 被默认拒绝
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --dport 5102 --timeout-ms 1500
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> blocked，且无事件（入向单连接不产事件）
> ```
> - `default-deny-carveout`：TARGET 起 `listen tcp 5101` 后，PEER 连 5101 → `allowed`，无事件。
> - `default-allow`：规则只写一行 `echo chain=localin,action=P`，TARGET 监听任一端口，PEER 连 → `allowed`，无事件。

### 4.3 出向五元组（egress，由 TARGET 发起、PEER 收）

```bat
fw-verify.exe --config fw-verify.conf run egress-tcp-block
fw-verify.exe --config fw-verify.conf run egress-tcp-alert
fw-verify.exe --config fw-verify.conf run egress-udp-block
fw-verify.exe --config fw-verify.conf run-group egress
```

| 用例（case-id） | 含义 | 期望 |
|---|---|---|
| `egress-tcp-block`（6001） | 出向 TCP 拦截 | blocked + NetworkBlock/Block，detail `"connection state invalid attack"` |
| `egress-tcp-alert`（6002） | 出向 TCP 放行 | allowed，**无事件**（出向 LP 不产事件） |
| `egress-udp-block`（6003） | 出向 UDP 拦截 | blocked（无回显）+ NetworkBlock/Block，detail `"connection state invalid attack"` |

> **内部原理 / 手动复现**——`egress` bundle 规则 + 各 case 由 TARGET 发起、PEER 收：
> ```bat
> (
> echo chain=localin,action=P
> echo sip=172.20.10.3,dip=172.20.10.2,dport=6001,proto=tcp,action=LD,chain=output
> echo sip=172.20.10.3,dip=172.20.10.2,dport=6002,proto=tcp,action=LP,chain=output
> echo sip=172.20.10.3,dip=172.20.10.2,dport=6003,proto=udp,action=LD,chain=output
> )>egress.rule
> adb -s 79MV5T5D85RSINQG push egress.rule /data/local/tmp/rule.txt
> adb -s 79MV5T5D85RSINQG shell fw-agent provision-rule --fun 1 --input /data/local/tmp/rule.txt
>
> :: egress-tcp-block(6001)：PEER 监听、TARGET 发起
> start /b adb -s XGRWZXVSUKXW7XMF shell fw-agent listen tcp --port 6001 --duration-secs 30
> timeout /t 1 /nobreak >nul
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s 79MV5T5D85RSINQG shell fw-agent traffic tcp --to 172.20.10.2 --dport 6001 --timeout-ms 1500
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> blocked + NetworkBlock/Block，detail "connection state invalid attack"
> ```
> - `egress-tcp-alert`：同上换 6002（PEER 监听 6002）→ allowed，**无事件**（出向 LP 不记录）。
> - `egress-udp-block`：PEER 起 `listen udp 6003`，TARGET 发 `traffic udp --to 172.20.10.2 --dport 6003 --await-reply` → blocked（无回显）+ NetworkBlock/Block。

### 4.4 应用 / UID 联网策略

依赖 `identity_overrides` 把 `identity_key` 映射到真实 uid——`apply-fast-profile` 已按 `fw-verify.conf` 的 `app_uid/app_identity_key` 注入（默认 `com.demo.browser` → uid 2000）。

```bat
fw-verify.exe --config fw-verify.conf run app-policy-deny
fw-verify.exe --config fw-verify.conf run app-policy-allow
fw-verify.exe --config fw-verify.conf run-group app
```

| 用例（case-id） | 含义 | 期望 |
|---|---|---|
| `app-policy-deny`（prog LD） | 应用拒绝，以映射 uid 发起 | blocked（cgroup connect4 = EPERM）+ PolicyDeny/Block |
| `app-policy-allow`（prog LP） | 应用放行 | allowed，无 PolicyDeny |

> **内部原理 / 手动复现**——规则按 `prog=<key>` 命中，发流量用 `su <uid>`：
> ```bat
> (
> echo chain=localin,action=P
> echo prog=com.demo.browser,action=LD
> )>app.rule
> adb -s 79MV5T5D85RSINQG push app.rule /data/local/tmp/rule.txt
> adb -s 79MV5T5D85RSINQG shell fw-agent provision-rule --fun 1 --input /data/local/tmp/rule.txt
> start /b adb -s XGRWZXVSUKXW7XMF shell fw-agent listen tcp --port 6101 --duration-secs 30
> timeout /t 1 /nobreak >nul
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s 79MV5T5D85RSINQG shell su 2000 -c "fw-agent traffic tcp --to 172.20.10.2 --dport 6101 --timeout-ms 1500"
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> blocked + PolicyDeny/Block（带 app_id）
> ```
> 把第二行改成 `prog=com.demo.browser,action=LP` 重新下发即测放行（allowed，无 PolicyDeny）。

### 4.5 完整五元组匹配（CIDR / 端口区间 / 协议）

```bat
fw-verify.exe --config fw-verify.conf run match-sip-host
fw-verify.exe --config fw-verify.conf run match-sip-cidr
fw-verify.exe --config fw-verify.conf run match-dport-range-lo
fw-verify.exe --config fw-verify.conf run match-dport-range-hi
fw-verify.exe --config fw-verify.conf run match-dport-range-out
fw-verify.exe --config fw-verify.conf run match-sport-range
fw-verify.exe --config fw-verify.conf run match-proto-icmp
fw-verify.exe --config fw-verify.conf run match-proto-any-tcp
fw-verify.exe --config fw-verify.conf run match-proto-any-udp
fw-verify.exe --config fw-verify.conf run-group match
```

> 这些都是**入向 `LD`** 规则。入向单连接不再产事件，故 match-* 改为**纯 enforcement 验证**：bundle 默认 `chain=localin,action=P`（放行），只有命中具体 `LD` 规则才会 `blocked`——所以 `blocked` 即证明该五元组规则命中（不再校验 `rule_id`）。

| 用例（case-id） | 匹配项 | 期望 |
|---|---|---|
| `match-sip-host`（7001） | 精确 /32 源 | blocked（无事件） |
| `match-sip-cidr`（7002） | CIDR /24 源 | blocked（无事件） |
| `match-dport-range-lo`（7100） | 目的端口区间下界 | blocked（无事件） |
| `match-dport-range-hi`（7110） | 目的端口区间上界 | blocked（无事件） |
| `match-dport-range-out`（7111） | 区间外（反例） | allowed，无事件 |
| `match-sport-range`（7200 UDP，sport 8000） | 源端口区间 + UDP | blocked（无回显=超时；无事件） |
| `match-proto-icmp` | ICMP 协议 | blocked（无回应），proto=icmp（无事件） |
| `match-proto-any-tcp` / `match-proto-any-udp`（7300） | 协议通配 | 均 blocked（UDP 用 `--await-reply` 超时判 blocked；无事件） |

> **内部原理 / 手动复现**——`match_fields` bundle 一份规则覆盖全部子项：
> ```bat
> (
> echo chain=localin,action=P
> echo sip=172.20.10.2/32,dip=172.20.10.3,dport=7001,proto=tcp,action=LD,chain=localin
> echo sip=172.20.10.0/24,dip=172.20.10.3,dport=7002,proto=tcp,action=LD,chain=localin
> echo sip=*,dip=172.20.10.3,dport=7100-7110,proto=tcp,action=LD,chain=localin
> echo sip=*,sport=8000-8005,dip=172.20.10.3,dport=7200,proto=udp,action=LD,chain=localin
> echo sip=*,dip=172.20.10.3,proto=icmp,action=LD,chain=localin
> echo sip=*,dip=172.20.10.3,dport=7300,proto=*,action=LD,chain=localin
> )>match.rule
> adb -s 79MV5T5D85RSINQG push match.rule /data/local/tmp/rule.txt
> adb -s 79MV5T5D85RSINQG shell fw-agent provision-rule --fun 1 --input /data/local/tmp/rule.txt
> :: 每个子项同一套：取水位线 → 跑对应 traffic（从 PEER）→ dump-events --since
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --dport 7001 --timeout-ms 1500
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ```
> 各子项把上面的 `traffic` 换成：`--dport 7002`（/24 源）；`--dport 7100`/`7110`（区间内）；先 `listen tcp 7111` 再 `--dport 7111`（区间外反例，allowed）；`traffic udp --dport 7200 --sport 8000 --await-reply`（源端口区间）；`traffic icmp --to 172.20.10.3`（ICMP）；`--dport 7300` 的 tcp 与 udp 各一遍（协议通配）。

### 4.6 端口扫描 / 连接异常检测

```bat
fw-verify.exe --config fw-verify.conf run detect-portscan-tcp
fw-verify.exe --config fw-verify.conf run detect-portscan-udp
fw-verify.exe --config fw-verify.conf run detect-portscan-tcp-fin
fw-verify.exe --config fw-verify.conf run detect-conn-abnormal
fw-verify.exe --config fw-verify.conf run detect-below-threshold
fw-verify.exe --config fw-verify.conf run-group detection
```

| 用例（case-id） | 触发 | 期望 |
|---|---|---|
| `detect-portscan-tcp` | 1s 内 TCP 打 3 个不同端口 | PortScan（proto=tcp），detail `"tcp portscan attack"` |
| `detect-portscan-udp` | 1s 内 UDP 打 3 个不同端口 | PortScan（proto=udp），detail `"udp portscan attack"`（UDP fire-and-forget，verdict=`sent`，靠事件判定） |
| `detect-portscan-tcp-fin` | 1s 内对 3 个不同端口发**纯 FIN** 包 | PortScan（proto=tcp），detail `"tcp fin portscan attack"`（raw socket，需 root；verdict=`sent`） |
| `detect-conn-abnormal` | 1s 内用 **≥4 个不同流（不同源端口）** 打同一端口 | ConnectionAbnormal，detail `"translation layer --tcp state unnormal"` |
| `detect-below-threshold` | 只打 2 个端口（反例） | blocked，**无事件**（子阈值不升级，不再产 NetworkBlock） |

> 检测要点：突发须 **≤1 秒**、规则为入向 `LD`（使流量进检测路径）。端口扫描计数是**全局**的（按目的端口、不分源 IP）。`ConnectionAbnormal` 现按**流**计数——同一目的端口需被 **≥4 个不同流（不同源端口）** 命中；`fw-agent traffic --count N`（不带 `--sport`）每次新建 socket，天然产生 N 个不同源端口，正好满足。

> **内部原理 / 手动复现**——`detection` bundle 规则只一行（入向全拦）：
> ```bat
> echo chain=localin,action=LD>detect.rule
> adb -s 79MV5T5D85RSINQG push detect.rule /data/local/tmp/rule.txt
> adb -s 79MV5T5D85RSINQG shell fw-agent provision-rule --fun 1 --input /data/local/tmp/rule.txt
>
> :: detect-portscan-tcp：1 秒内打 3 个不同端口 → PortScan
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --dports 9001,9002,9003 --timeout-ms 250
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> event_type=PortScan
>
> :: detect-conn-abnormal：1 秒内用 5 个不同流（--count 5 → 5 个不同源端口）打同一端口 → ConnectionAbnormal
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --dport 9100 --count 5 --timeout-ms 200
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> event_type=ConnectionAbnormal，detail "translation layer --tcp state unnormal"
>
> :: detect-portscan-tcp-fin：1 秒内对 3 个不同端口发纯 FIN 包（raw socket，需 root）→ FIN PortScan
> for /f "tokens=2 delims=:}" %A in ('adb -s 79MV5T5D85RSINQG shell fw-agent now') do set "NOWMS=%A"
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic tcp --to 172.20.10.3 --fin-only --dports 9011,9012,9013 --timeout-ms 250
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent dump-events --since %NOWMS%
> ::  -> event_type=PortScan，detail "tcp fin portscan attack"
> ```
> - `detect-portscan-udp`：第一段换 `traffic udp --dports 9001,9002,9003 --timeout-ms 250`（UDP 无握手，verdict=`sent`，靠 PortScan 事件判定）。
> - `detect-below-threshold`：只打 2 个端口（`--dports 9201,9202`）→ blocked 但**无事件**（子阈值不升级）。

### 4.7 流量统计（global + per-app）

```bat
fw-verify.exe --config fw-verify.conf run traffic-global
fw-verify.exe --config fw-verify.conf run traffic-per-app
fw-verify.exe --config fw-verify.conf run-group traffic
```

| 用例（case-id） | 含义 | 期望 |
|---|---|---|
| `traffic-global` | 全局统计 | ingress_bytes↑、global_traffic_windows↑ |
| `traffic-per-app` | 按应用统计（以映射 uid 出向发） | egress_bytes↑、app_traffic_windows↑ |

> `run` 会自己把流量周期 fun=4 设为 5s，发流量后等窗口关闭再比对统计。

> **内部原理 / 手动复现**：
> ```bat
> :: ①把流量策略周期调短（fun=4）
> (echo {"cycle":5})>traffic.json
> adb -s 79MV5T5D85RSINQG push traffic.json /data/local/tmp/traffic.json
> adb -s 79MV5T5D85RSINQG shell fw-agent provision-rule --fun 4 --input /data/local/tmp/traffic.json
> :: 防火墙规则用 §4.2 默认放行，或含放行 5301 的规则
>
> :: traffic-global：放行流量，比统计前后
> adb -s 79MV5T5D85RSINQG shell idps-fw statistics
> adb -s XGRWZXVSUKXW7XMF shell fw-agent traffic udp --to 172.20.10.3 --dport 5301 --count 200 --timeout-ms 50
> timeout /t 7 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell idps-fw statistics
> ::  -> ingress_bytes↑、global_traffic_windows↑
>
> :: traffic-per-app：以映射 uid 在 TARGET 向 PEER 发 UDP（出向）
> adb -s 79MV5T5D85RSINQG shell idps-fw statistics
> adb -s 79MV5T5D85RSINQG shell su 2000 -c "fw-agent traffic udp --to 172.20.10.2 --dport 5301 --count 200 --timeout-ms 50"
> timeout /t 7 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell idps-fw statistics
> ::  -> egress_bytes↑、app_traffic_windows↑
> ```

---

## 5. 确认事件已上报 idps-server

`run` 默认已校验上报：产生事件的用例，事件入库后经 outbox flush 上报 idps-server，收到 ACK 后 `report_state=sent`——这一项不过 `run` 就判 `FAIL`。校验严格度由 `fw-verify.conf` 的 `report_confirm` 控制：

- `local`（默认）：查设备 `report_state=sent`。
- `server`：再查 idps-server 日志 `received report`。
- `vsoc`：再查 VSOC（需配 `vsoc_url`）是否收到本机 IP 的事件。

> **内部原理 / 手动复现**——沿用该用例的 `%NOWMS%`：
> ```bat
> timeout /t 1 /nobreak >nul
> adb -s 79MV5T5D85RSINQG shell fw-agent report-status --since %NOWMS%
> ::  -> {"events_total":N,"events_sent":N,"events_pending":0,"outbox":[{"state":"sent",...}]}
> ```
> - `events_sent == events_total` 且 `outbox.state=sent` ⇒ 已送达 idps-server。
> - 仍 `pending` 且 `retry_count` 增长 ⇒ 上报失败（看 idps-server 是否在跑）。
> - 服务端佐证：`adb -s 79MV5T5D85RSINQG shell logcat -d | findstr "received report"`。

---

## 6. 观测与排错要点

- **某条 `run` FAIL**：照该节「内部原理 / 手动复现」逐步跑，看是哪一步偏离——enforcement 判据 `blocked`=超时/EPERM、`allowed`=成功、`refused`=没监听/配置错。
- **规则没生效**：`fw-verify ... health` 看 `firewall_rule_ver` 是否在下发后变大；手动 `provision-rule` 时返回的 `key_present` 必须为 `true`（false 说明 keystore 缺失，重跑 `apply-fast-profile` 或 `ensure-keystore`）。
- **放行类一直 refused**：监听没起来或起晚了；`run` 内部已留 0.5s 绑定窗口，手动复现时务必先 `listen` 再发流量。
- **检测窗口**：端口扫描/连接异常突发须 ≤1s、规则为入向 `LD`。端口扫描按目的端口全局计数；`ConnectionAbnormal` 须 ≥4 个不同流（不同源端口）打同一端口（`--count N` 即产生 N 个不同源端口）。入向单连接的拦截/放行**不产逐条事件**，只有扫描/异常判定才产事件。
- **水位线**：手动复现时每个用例发流量前先取 `fw-agent now` 的 `now_ms` 作 `--since`，避免混入旧事件。
- **JSON 引号列**：`dump-events` 已把 `event_type/action` 还原成 `NetworkBlock`/`Block` 等干净名（DB 里其实存带引号的 `"Block"`）。
- **PEER 上 fw-agent 报 `library "libidps_device_provider.so" not found`**：该 `.so` 没装到 PEER，重跑 `install.bat`（缺失时会补到 `/system/lib64`），再 `preflight`。

---

## 7. 还原

```bat
:: 1) 还原 idps-fw 配置（从 .fwv-bak 恢复并重启 idps-fw）。只还原配置，不动 keystore/身份。
fw-verify.exe --config fw-verify.conf restore-profile
:: 2) 删除下发的 depot 规则，回退默认
fw-verify.exe --config fw-verify.conf reset-rules
```

> **内部原理 / 手动复现**——若要连注入的测试身份与 keystore 一并清掉，恢复真机身份：
> ```bat
> adb -s 79MV5T5D85RSINQG shell "rm -f /data/idd/vin_debug /data/idd/dsn_debug /data/idd/keys/aes.keystore; stop idps-server; start idps-server"
> adb -s 79MV5T5D85RSINQG shell "rm -f /data/idd/rule/depot/1-1-*.rule* /data/idd/rule/depot/1-4-*.rule*"
> :: 配置则等价于 cp /etc/idd/idps-fw.yaml.fwv-bak /etc/idd/idps-fw.yaml; stop idps-fw; start idps-fw
> ```

> **覆盖映射**：本文逐项覆盖了 idps-fw 的 入向五元组(P/LP/LD/NLD)、默认入向策略、出向规则、应用/UID 策略、完整五元组(CIDR/端口区间/协议)、端口扫描（含 **FIN 扫描**）与连接异常检测（含 `detail` 文案校验）、流量统计(global+per-app)，以及事件上报 idps-server 的确认——即 idps-fw 的全部功能，对应 `fw-verify run-all` 的完整目录。
>
> **与 vendor 对齐的关键变化**：入向单连接的 `LD`/`LP` 与出向 `LP` **不再产逐条事件**；事件只来自入向 `PortScan`/`ConnectionAbnormal`、出向 `LD` 的 `NetworkBlock`、应用 `PolicyDeny`。连接异常事件号为 221/222，detail 文案与 vendor 一致。
