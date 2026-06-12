# 用 fw-verify 测试 idps-fw 全部功能

`fw-verify` 是 idps-fw 的**单二进制**功能测试工具:编排器与设备侧 worker 合二为一。它**在被测设备上本地运行**(host 或 Android 同一套用法),自己搭拓扑、下发规则、发流量、判 enforcement + 事件 + 上报,最后打印 `PASS`/`FAIL`。

每个用例就是一条命令:

```bash
fw-verify --config /etc/idd/fw-verify.conf run default-deny-carveout
```

`fw-verify` 会自己**下发该用例规则 → 起监听 → 取水位线 → 发流量 → 判定 enforcement + 事件 + 上报**。你不需要手动 `provision-rule`/`traffic`/`dump-events`。

---

## 1. 架构总览

测试始终是**单设备**:`fw-verify` 在本机建一对 veth,把 PEER 端放进 network namespace,让 TARGET ↔ PEER 的流量穿过 idps-fw 监控的接口。

```
   设备(host 或 Android),fw-verify 以 root 本地运行
   ┌──────────────────────────────────────────────┐
   │  root netns (TARGET)         netns fwpeer      │
   │   idps-fw + idps-server       (PEER)           │
   │   fwt0 10.123.0.1/24  <─veth─> fwp0 10.123.0.2 │
   └──────────────────────────────────────────────┘
```

- **编排器**:本机 root,直接读 idps-fw 状态、在 TARGET 侧加密写 depot(进程内)。
- **worker**:需要进 netns / 降 uid / 后台监听的步骤,通过重执行自身
  `fw-verify agent <子命令>` 完成——PEER 侧用 `nsenter --net=/run/netns/fwpeer`
  (不可用时回退 `ip netns exec fwpeer`)进入命名空间。

host 与 Android **唯一的区别是规则如何下发**;拓扑、执行、用例目录完全一致:

| | host | Android |
|---|---|---|
| 规则下发 | VSOC `PUT /api/rules/{acd}/{fun}`(mTLS) → idps-server 云同步进 depot | 直接把加密规则写入 `/data/idd/rule/depot`(复用 idps-server `RuleDepot`) |
| keystore | idps-server 启动时由 mock VIN/DSN 自派生 | `setup-env` 注入 `/data/idd/{vin,dsn}_debug` 后由 idps-server 派生 |
| 服务管理 | systemd(`systemctl`) | Android init(`stop`/`start`) |
| 选择方式 | `--mode host`(默认) | `--mode android` |

设备侧 worker 子命令(`fw-verify agent ...`)的完整列表见 `fw-verify agent --help`。

---

## 2. 安装

### 2.1 host

从 workspace 根目录起齐 VSOC + idps-server + idps-fw + fw-verify:

```bash
# 1) mock VSOC(host 模式经它下发规则)
cd /home/ubuntu/workspace/idps/vsoc && make deploy && make status
ss -ltnp | grep ':8443'        # 8443 应在监听
curl -k --cert certs/rsa/client.crt --key certs/rsa/client.key \
  -I https://127.0.0.1:8443/api/vsoc/front/secure/time   # 期望 200,头里有 auth-ts

# 2) idps-server / idps-fw 运行时 + provider 动态库
cd /home/ubuntu/workspace/idps        && make install   # idps-server + libidps_device_provider.so
cd /home/ubuntu/workspace/idps/idps-fw && make install   # idps-fw + idps-fw.bpf.o + 服务

# 3) fw-verify
cd /home/ubuntu/workspace/idps/idps-fw-test && make install   # /usr/local/bin/fw-verify
```

前置:Linux + `sudo`、docker、Rust `1.93.0`、`iproute2`(`ip netns`/veth)、
可加载 eBPF/tc 且 `/sys/fs/cgroup` 可用。

### 2.2 Android

在控制 PC 上打包,adb **仅用于把二进制装到设备**(测试本身在设备上跑):

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make package-android        # 生成 out/idps-fw-test/{system.zip, install.bat, fw-verify.conf}
# 或直连一台设备直接安装:
make push-fwverify DEVICE=<adb-serial>
```

`install.bat`(Windows)经 adb 把 `fw-verify` 装到 `/system/bin`,缺失时补
`/system/lib64/libidps_device_provider.so`。装完后**登录设备**操作,不再用 adb 驱动测试:

```bash
adb -s <serial> shell           # 进入设备 shell
# 设备上(root):
fw-verify --mode android setup-env
fw-verify --config /etc/idd/fw-verify.conf run-all
```

> 设备的 `/etc/idd` 若只读,先 `adb remount`(`install.bat` 已做);`setup-env` 写
> 配置失败时会提示。

---

## 3. 环境搭建:setup-env / clean-env

两个平台用**同一条命令**搭/拆环境。它创建 veth/netns 拓扑、写 idps-fw 短轮询配置
(备份原配置到 `.fwv-bak`)和 `/etc/idd/fw-verify.conf`。

```bash
# host(经 make 包装,带上 VSOC mTLS 证书路径与 NO_PROXY):
cd /home/ubuntu/workspace/idps/idps-fw-test && make setup-dev

# 或直接调:
sudo fw-verify --mode host \
  --vsoc-cert .../client.crt --vsoc-key .../client.key setup-env

# Android(设备上):
fw-verify --mode android setup-env          # 额外注入 keystore 并自动重启 idps-fw/idps-server
```

它生成的拓扑与配置:

| 角色 | 位置 | 接口 | IP |
|---|---|---|---|
| TARGET | root namespace | `fwt0` | `10.123.0.1/24` |
| PEER | netns `fwpeer` | `fwp0` | `10.123.0.2/24` |

- `/etc/idd/idps-fw.yaml`:监控 `fwt0`、缩短 rule/event/report/traffic 周期、注入
  app/UID 映射 `com.demo.browser` → uid `2000`。
- `/etc/idd/fw-verify.conf`:`mode`、接口/IP/netns、`idps_fw`、`state_db`、app 映射;
  host 模式追加 `vsoc_url`(及证书)。

> **host 与 Android 的服务重启差异**:Android 的 `setup-env` 会 `stop/start idps-fw`
> 并等待健康(失败自动回滚配置);host 的 `make setup-dev` 会在 systemd 可用时自动
> 重启 `idps-fw.service`。直接调用 `fw-verify --mode host setup-env` 时仍需手动重启。

拆环境(拆 veth/netns、还原 idps-fw 配置、删 fw-verify.conf):

```bash
make clean-dev                       # host
fw-verify --mode android clean-env   # Android(设备上)
```

---

## 4. 命令速查

日常命令都带 `--config /etc/idd/fw-verify.conf`(由 `setup-env` 生成)。host 下命令前
缀 `sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib`(下方省略)。

| 命令 | 作用 |
|---|---|
| `setup-env` / `clean-env` | 搭/拆 veth/netns 拓扑 + 配置(§3) |
| `preflight` | 校验 idps-fw 可响应、depot 目录、PEER worker 重执行、PEER→TARGET 连通(host 另查 VSOC) |
| `list` | 列出全部 case-id 及分组 |
| `run <id>` | 跑单条用例 |
| `run-group <组>` | 跑整组(`ingress\|default\|egress\|app\|match\|detection\|traffic`),每个 bundle 只下发一次 |
| `run-all` | 按 bundle 批量跑完整目录 + 监控用例 |

隐藏的高级/排障命令(不在默认 `-h`):`health`、`stats`、`provision <文件> [--traffic-cycle N]`、
`reset-rules`、`agent <子命令>`(worker,正常无需手动调)。

---

## 5. 运行测试

```bash
# host(也可直接 make test-host)
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-all

# Android(设备上)
fw-verify --config /etc/idd/fw-verify.conf run-all
```

`run-all` 覆盖:`ingress`(P/LP/LD/NLD)、`default`(拒绝/例外/放行)、`egress`(TCP/UDP)、
`app`(应用/UID 策略)、`match`(源 IP/CIDR/端口区间/协议)、`detection`(端口扫描/连接异常)、
`traffic`(全局 + per-app 统计),以及监控用例(ICMP 时间戳、连接计数、ARP 欺骗)。每条产生
事件的用例都会校验 `report_state=sent`(已上报 idps-server)。

> host 下务必带 `NO_PROXY=127.0.0.1,localhost`,否则本机 HTTP 代理会劫持到 VSOC/idps-server
> 的 localhost 请求。

按组、单条与重置:

```bash
fw-verify --config /etc/idd/fw-verify.conf list
fw-verify --config /etc/idd/fw-verify.conf run-group detection
fw-verify --config /etc/idd/fw-verify.conf run ingress-tuple-block
fw-verify --config /etc/idd/fw-verify.conf reset-rules
```

---

## 6. 用例目录(各功能期望)

下列用例与模式无关;`list` 可随时列出全部 case-id。规则文本与触发细节见 §7。

**入向五元组 `ingress`**(P/LP/LD/NLD):

| 用例 | 端口 | 期望 |
|---|---|---|
| `ingress-tuple-pass` | 5001 | allowed,无事件 |
| `ingress-tuple-alert` | 5002 | allowed,**无事件**(入向 LP 单连接不产事件) |
| `ingress-tuple-block` | 5003 | blocked(超时),**无事件**(入向 LD 单连接不产事件) |
| `ingress-tuple-blocksilent` | 5004 | blocked,无事件 |

**默认入向策略 `default`**:`default-deny-blocks`(5102,blocked 无事件)、
`default-deny-carveout`(5101,allowed)、`default-allow`(allowed)。

**出向 `egress`**(TARGET 发起、PEER 收):`egress-tcp-block`(6001,blocked +
NetworkBlock/Block)、`egress-tcp-alert`(6002,allowed 无事件)、`egress-udp-block`
(6003,blocked + NetworkBlock/Block)。

**应用/UID `app`**(以映射 uid 发起):`app-policy-deny`(blocked,cgroup connect4 EPERM
+ PolicyDeny/Block)、`app-policy-allow`(allowed,无 PolicyDeny)。

**五元组匹配 `match`**(均入向 `LD`,纯 enforcement 验证,`blocked` 即命中):
`match-sip-host`(/32)、`match-sip-cidr`(/24)、`match-dport-range-lo/hi`(区间内 blocked)、
`match-dport-range-out`(区间外 allowed)、`match-sport-range`(UDP 源端口区间)、
`match-proto-icmp`、`match-proto-any-tcp/udp`(协议通配)。

**检测 `detection`**(突发须 ≤1s、规则入向 `LD`):

| 用例 | 触发 | 期望事件 |
|---|---|---|
| `detect-portscan-tcp` | 1s 内 TCP 打 3 个不同端口 | PortScan/tcp,detail `"tcp portscan attack"` |
| `detect-portscan-udp` | 1s 内 UDP 打 3 个不同端口 | PortScan/udp(verdict=`sent`) |
| `detect-portscan-tcp-fin` | 1s 内对 3 端口发纯 FIN | PortScan/tcp,detail `"tcp fin portscan attack"` |
| `detect-conn-abnormal` | ≥4 个不同流打同一端口 | ConnectionAbnormal,detail `"translation layer --tcp state unnormal"` |
| `detect-below-threshold` | 只打 2 端口(反例) | blocked,**无事件** |

**流量统计 `traffic`**:`traffic-global`(ingress_bytes↑、global_traffic_windows↑)、
`traffic-per-app`(以映射 uid 出向发,egress_bytes↑、app_traffic_windows↑)。

> **动作语义(与 vendor 对齐)**:事件只来自入向 `PortScan`/`ConnectionAbnormal`、出向
> `LD` 的 `NetworkBlock`、应用 `PolicyDeny`。入向单连接的 `LD`/`LP` 与出向 `LP`
> **不产逐条事件**;入向永不产 `NetworkBlock`。连接异常协议事件号 221(TCP)/222(UDP)。

---

## 7. 用例生命周期与手动复现

理解这套步骤,任何 `FAIL` 都能逐步定位。普通用例(enforcement + 事件类),`run <id>` 内部:

1. **下发规则**:先写 fun=4 流量策略(cycle=5s,idps-fw 才能离开 `RuleSyncing`),再把该
   用例 bundle 的 fun=1 防火墙规则下发。host 经 VSOC,Android 直写 depot。
2. **起监听**:仅放行类用例——在收包侧 `agent listen`,等 0.5s 绑定(否则被误判 `refused`)。
3. **取水位线**:`agent now` 的 `now_ms` 作本用例事件起点。
4. **发流量**:从发起侧 `agent traffic ...`(应用/UID 用例加 `--uid <uid>` 降权),超时 1500ms。
5. **沉淀** `event_settle`(默认 1500ms)后 `agent dump-events --since 水位线`。
6. **判定**(三者全过才 PASS):enforcement 与期望一致;事件 `kind/action/proto/src_ip/
   dst_port/rule_id` 与期望一致;产生事件时 `report_state=sent`。

流量统计类走另一条:发流量前后各取一次 `idps-fw statistics`,发完等 7s 让窗口(cycle=5s)
关闭后比对字节/窗口增量。

**规则文本格式**(每行一条,无空行/注释,`rule_id = 行号`,靠后优先):

- 默认入向:`chain=localin,action=P|LP|LD|NLD`
- 应用策略:`prog=<identity_key>,action=LP|LD`
- 五元组:`sip=..,dip=..,sport=..,dport=..,proto=tcp|udp|icmp|*,action=..,chain=localin|output`

**手动复现**(在设备上以 root 直接调 worker 子命令;以 `ingress-tuple-block` 为例):

```bash
# ① 下发规则(Android 直写 depot;host 改用 VSOC,见下)
cat > /data/local/tmp/rule.txt <<'EOF'
chain=localin,action=P
sip=10.123.0.2,dip=10.123.0.1,dport=5001,proto=tcp,action=P,chain=localin
sip=10.123.0.2,dip=10.123.0.1,dport=5002,proto=tcp,action=LP,chain=localin
sip=10.123.0.2,dip=10.123.0.1,dport=5003,proto=tcp,action=LD,chain=localin
sip=10.123.0.2,dip=10.123.0.1,dport=5004,proto=tcp,action=NLD,chain=localin
EOF
fw-verify agent provision-rule --acd 1 --fun 1 --input /data/local/tmp/rule.txt
idps-fw health | grep firewall_rule_ver        # 确认版本变大

# ② 取水位线、③ 从 PEER(netns)发流量、④ 读事件
NOWMS=$(fw-verify agent now | sed 's/[^0-9]//g')
nsenter --net=/run/netns/fwpeer fw-verify agent traffic tcp --to 10.123.0.1 --dport 5003 --timeout-ms 1500
sleep 1
fw-verify agent dump-events --since "$NOWMS"
#  -> verdict=blocked,且无新事件(入向 LD 单连接不产事件)
```

- **放行类**(如 5001/5002):先在 TARGET 后台 `fw-verify agent listen tcp --port 5002 --duration-secs 30 &`,再发流量。
- **出向类**:PEER 监听、TARGET 发起——`nsenter --net=/run/netns/fwpeer fw-verify agent listen tcp --port 6001 ... &` 后 `fw-verify agent traffic tcp --to 10.123.0.2 --dport 6001`。
- **应用/UID 类**:发流量加 `--uid 2000`(worker 入口降权,等价旧 host `setpriv`/Android `su`)。
- **host 下发规则**改为 VSOC:`curl -k --noproxy '*' --cert client.crt --key client.key -X PUT -H 'Content-Type: application/json' -d '{"content":"<规则文本>","enabled":true}' https://127.0.0.1:8443/api/rules/1/1`,再等 idps-server 同步、idps-fw 加载。
- PEER 侧若 `nsenter` 不可用,把前缀换成 `ip netns exec fwpeer`。

---

## 8. 确认事件已上报 idps-server

`run` 默认已校验上报:产生事件的用例,事件入库后经 outbox flush 上报 idps-server,收 ACK
后 `report_state=sent`——不过则判 `FAIL`。严格度由 `fw-verify.conf` 的 `report_confirm` 控制:

- `local`(默认):查设备 `report_state=sent`。
- `server`:再查 idps-server 日志 `received report`(仅 Android logcat 有效)。
- `vsoc`:再查 VSOC(需配 `vsoc_url`)是否收到本机 IP 的事件。

手动核对:`fw-verify agent report-status --since <NOWMS>`,期望
`events_sent == events_total` 且 outbox `state=sent`。

---

## 9. 故障排查

- **某条 `run` FAIL**:照 §7 手动复现逐步跑。enforcement 判据:`blocked`=超时/EPERM、
  `allowed`=成功、`refused`=没监听/配置错。
- **规则没生效**:`fw-verify ... health` 看 `firewall_rule_ver` 是否在下发后变大;Android
  手动 `provision-rule` 返回的 `key_present` 必须为 `true`(false 说明 keystore 缺失,重跑
  `setup-env`)。host 则确认 VSOC 健康、idps-server 云端认证成功并已同步。
- **VSOC 8443 不通**(host):`cd vsoc && make status && docker compose ps`;恢复
  `docker compose up -d --wait mysql && make db-migrate && docker compose up -d --wait backend frontend`。
- **idps-fw 没监控 fwt0**:`grep -n 'fwt0\|rule_poll_interval_secs\|identity_overrides'
  /etc/idd/idps-fw.yaml`;不对则重跑 `setup-env` 并重启 idps-fw。
- **veth/netns 残留**:`clean-env` 后重跑 `setup-env`。
- **PEER worker 起不来**:`preflight` 的 "peer worker re-exec" 项失败,通常是 netns 未建好
  或设备缺 `nsenter`/`ip netns`——确认 `/run/netns/fwpeer` 存在;两种进入方式有自动回退。
- **放行类一直 refused**:监听没起或起晚;`run` 内部留了 0.5s 绑定窗口,手动复现务必先 listen。
- **找不到 `libidps_device_provider.so`**:host 确认 root `make install` 装了 provider 库并
  `ldconfig`,运行带 `LD_LIBRARY_PATH=/usr/local/lib`;Android 重跑 `install.bat`(会补
  `/system/lib64`)。
- **app/UID 用例失败**:确认 `/etc/idd/idps-fw.yaml` 有 `identity_overrides`
  (`com.demo.browser`→2000);改 uid/key 后重跑 `setup-env`。
- **检测窗口**:扫描/异常突发须 ≤1s、规则入向 `LD`。端口扫描按目的端口全局计数;
  `ConnectionAbnormal` 须 ≥4 个不同流(不同源端口)打同一端口。

---

## 10. 还原

```bash
fw-verify --config /etc/idd/fw-verify.conf reset-rules   # 删下发的 depot 规则,回退默认
# host:
make clean-dev
# Android(设备上):
fw-verify --mode android clean-env
```

`clean-env` 会拆 netns/veth、从 `.fwv-bak` 还原 idps-fw 配置、删 `/etc/idd/fw-verify.conf`。
若要连注入的测试身份与 keystore 一并清掉(Android):
`rm -f /data/idd/vin_debug /data/idd/dsn_debug /data/idd/keys/aes.keystore; stop idps-server; start idps-server`。

---

## 11. 最短可复制流程

```bash
# host
cd /home/ubuntu/workspace/idps/vsoc && make deploy
cd /home/ubuntu/workspace/idps && make install
cd /home/ubuntu/workspace/idps/idps-fw && make install
cd /home/ubuntu/workspace/idps/idps-fw-test && make install && make setup-dev
make test-host

# Android(打包后在设备上)
fw-verify --mode android setup-env
fw-verify --config /etc/idd/fw-verify.conf run-all
```
