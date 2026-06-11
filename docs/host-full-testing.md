# Host 下用 idps-fw-test 完成 idps-fw 全功能测试

本文说明如何在 **Linux host** 上用 `idps-fw-test` 跑完 `idps-fw` 的完整功能测试目录。Host 模式不需要两台 Android 设备：`fw-verify` 会在本机创建一对 veth，把 PEER 端放进 network namespace，让 TARGET ↔ PEER 的流量穿过 `idps-fw` 监控的 host 接口。

Host 模式的测试链路是生产式的：

1. `fw-verify` 通过 VSOC dashboard API 下发规则。
2. `idps-server` 从 VSOC 云端同步规则到本机 depot。
3. `idps-fw` 轮询规则、加载 eBPF/tc/cgroup 策略。
4. `fw-agent` 在本机和 netns 中发流量、读 `idps-fw` 状态库。
5. `fw-verify` 判断 enforcement、事件、上报状态和流量统计。

Android / Windows 控制机的两机测试流程见 [`fw-verify-testing.md`](./fw-verify-testing.md)。本文只讲 Host 模式。

---

## 1. 覆盖范围

`make test-host` 等价于：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-all
```

`run-all` 会按 bundle 跑完整目录，覆盖：

| 分组 | 覆盖内容 |
|---|---|
| `ingress` | 入向五元组规则：`P`、`LP`、`LD`、`NLD` |
| `default` | 默认入向策略：默认拒绝、例外放行、默认放行 |
| `egress` | 出向 TCP/UDP 阻断和告警 |
| `app` | 应用 / UID 策略：指定 app 拒绝与放行 |
| `match` | 源 IP、CIDR、源/目的端口区间、ICMP、任意协议、规则优先级 |
| `detection` | TCP/UDP/FIN 端口扫描、异常连接、阈值以下不告警 |
| `traffic` | 全局流量统计与 per-app 流量统计 |

每条产生事件的用例都会校验本地 outbox 上报状态；默认以 `report_state=sent` 作为上报确认。

---

## 2. 前置条件

从 workspace 根目录 `/home/ubuntu/workspace/idps` 执行下文命令，除非命令里显式 `cd` 到子目录。

需要具备：

- Linux host，能使用 `sudo`。
- Docker / docker compose，用于 VSOC mock 云端。
- Rust toolchain `1.93.0` 和 nightly fmt toolchain。
- `iproute2`：需要 `ip netns`、veth。
- `setpriv`：应用 / UID 用例会用它把 `fw-agent traffic` 降到指定 UID。
- 本机可加载 eBPF/tc 程序，且 `/sys/fs/cgroup` 可用。
- `/usr/local/bin`、`/usr/local/lib` 可安装测试二进制和 provider 动态库。

快速确认：

```bash
command -v docker
command -v ip
command -v setpriv
rustup run 1.93.0 cargo --version
```

---

## 3. 启动 VSOC

Host 模式通过 VSOC API 下发规则，所以先启动 mock VSOC。

```bash
cd /home/ubuntu/workspace/idps/vsoc
make deploy
make status
```

期望 `mysql`、`backend`、`frontend` 都是 healthy，并且 8443 已监听：

```bash
ss -ltnp | grep ':8443'
```

用 mTLS 直接探测 time endpoint：

```bash
curl -k \
  --cert certs/rsa/client.crt \
  --key certs/rsa/client.key \
  -I https://127.0.0.1:8443/api/vsoc/front/secure/time
```

期望返回 `HTTP/1.1 200 OK`，响应头里有 `auth-ts`。

---

## 4. 安装 host runtime

### 4.1 安装 idps-server

在 workspace 根目录执行：

```bash
cd /home/ubuntu/workspace/idps
make install
```

这个目标会构建并安装：

- `/usr/local/bin/idps-server`
- `/usr/local/bin/idps-cli`
- `/usr/local/bin/idps-tools`
- `/usr/local/lib/libidps_device_provider.so`
- `/usr/local/lib/libbydauto.so`
- `idps-server.service`

同时会执行 root `clean-dev`、`setup-dev`，并启动或重启 `idps-server.service`。

确认：

```bash
systemctl status idps-server.service --no-pager -l
journalctl -u idps-server.service -n 80 --no-pager
```

健康状态应是 `active (running)`。如果 VSOC 已正常，日志里应能看到：

- `cloud time synced`
- `cloud auth token received and verified`
- `cloud session established`

### 4.2 安装 idps-fw

```bash
cd /home/ubuntu/workspace/idps/idps-fw
make install
```

这个目标会安装 `/usr/local/bin/idps-fw`、`/etc/idd/idps-fw.yaml`、`/etc/idd/idps-fw.bpf.o`，并启动或重启 `idps-fw.service`。

先确认服务存在；此时配置还不是 Host 测试拓扑专用配置，后面 `idps-fw-test setup-dev` 会覆盖 `/etc/idd/idps-fw.yaml`，所以最后还要再重启一次 `idps-fw`。

```bash
systemctl status idps-fw.service --no-pager -l
```

### 4.3 安装 idps-fw-test

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make install
```

这个目标会把下面两个二进制安装到 `/usr/local/bin`：

- `fw-verify`
- `fw-agent`

`fw-agent` 会被 `fw-verify` 同时用于 TARGET 侧和 PEER netns 侧。

---

## 5. 准备 Host 测试拓扑

在 `idps-fw-test` 下执行：

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make clean-dev
make setup-dev
```

`setup-dev` 会创建默认拓扑：

| 角色 | 位置 | 接口 | IP |
|---|---|---|---|
| TARGET | host root namespace | `fwt0` | `10.123.0.1/24` |
| PEER | netns `fwpeer` | `fwp0` | `10.123.0.2/24` |

它还会生成：

- `/etc/idd/idps-fw.yaml`
  - 监控 `fwt0`
  - 缩短 rule/event/report/traffic 周期
  - 配置 app/UID 测试映射：`com.demo.browser` → UID `2000`
- `/etc/idd/fw-verify.conf`
  - `mode = host`
  - TARGET/PEER 接口和 IP
  - VSOC mTLS 证书路径
  - `fw_agent = fw-agent`
  - `idps_fw = idps-fw`

因为 `setup-dev` 改写了 `idps-fw` 配置，必须重启 `idps-fw`：

```bash
sudo systemctl restart idps-fw.service
systemctl status idps-fw.service --no-pager -l
```

确认拓扑：

```bash
ip addr show dev fwt0
sudo ip netns exec fwpeer ip addr show dev fwp0
ping -c 2 10.123.0.2
sudo ip netns exec fwpeer ping -c 2 10.123.0.1
```

确认 `fw-verify` 配置：

```bash
sudo sed -n '1,120p' /etc/idd/fw-verify.conf
```

---

## 6. 预检

先跑 `preflight`，确认 `fw-verify` 能在 host 和 netns 两侧执行 `fw-agent`，也能读取 `idps-fw` 状态：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf preflight
```

Host 模式下这一步不会走 adb。TARGET 是本机，PEER 是 `ip netns exec fwpeer ...`。

需要进一步确认 `idps-fw` 运行状态时，可用隐藏的高级诊断命令查看 health：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf health
```

期望至少满足：

- `idps-fw` 能返回 JSON。
- 监控接口包含 `fwt0`。
- eBPF object 路径是 `/etc/idd/idps-fw.bpf.o`。

Host 模式不需要跑 `apply-fast-profile`；短轮询配置已经由 `make setup-dev` 写入。

---

## 7. 跑完整目录

推荐直接使用 Makefile 包装：

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make test-host
```

它会执行：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  /usr/local/bin/fw-verify --config /etc/idd/fw-verify.conf run-all
```

每条用例会输出 `PASS` 或 `FAIL`。`run-all` 会按 bundle 批量下发规则，避免每条 case 重复 provision。

跑完后如需排障，可以用隐藏的高级诊断命令查看统计：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf stats
```

也可以查看服务日志：

```bash
journalctl -u idps-fw.service -n 160 --no-pager
journalctl -u idps-server.service -n 160 --no-pager
```

---

## 8. 分组和单项调试

列出全部用例：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf list
```

按组跑：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-group ingress

sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-group default

sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-group egress

sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-group app

sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-group match

sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-group detection

sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run-group traffic
```

跑单条：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf run ingress-tuple-block
```

高级维护/排障命令仍可直接执行，但不出现在默认 `fw-verify -h` 中。

重置测试下发的规则：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf reset-rules
```

手动 provision 一份规则文件：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf provision /path/to/rule.txt --traffic-cycle 5
```

---

## 9. Host 模式内部执行模型

Host 模式和 Android 模式复用同一套 case catalog，但执行端点不同：

- TARGET：本机 root namespace，命令直接本地执行。
- PEER：`ip netns exec fwpeer ...` 包住同一个 `fw-agent` 命令。
- App/UID 用例：`setpriv --reuid 2000 --regid 2000 --clear-groups ...` 发起流量，让 eBPF cgroup hook 看到指定 socket uid。

一条普通用例内部流程：

1. `fw-verify` 通过 `PUT /api/rules/{acd}/{fun}` 向 VSOC 下发 fun=4 流量策略和 fun=1 防火墙规则。
2. `idps-server` 从 VSOC 同步规则。
3. `idps-fw` 轮询并加载新规则。
4. 放行类用例先在收包侧启动 `fw-agent listen`。
5. 发包侧执行 `fw-agent traffic ...`。
6. `fw-verify` 读取 `fw-agent dump-events --since <watermark>`。
7. 校验 enforcement、事件字段和 report 状态。

流量统计类用例会在发流量前后读取 `idps-fw statistics`，比较窗口内字节数增长。

---

## 10. 常见故障定位

### VSOC 8443 不通

症状：

- `idps-server` 日志反复出现 `cloud time sync failed`。
- `curl https://127.0.0.1:8443/...` connection refused。
- `fw-verify` 下发规则失败。

排查：

```bash
cd /home/ubuntu/workspace/idps/vsoc
make status
docker compose ps
docker logs --tail 120 vsoc-backend
docker logs --tail 120 vsoc-mysql
```

恢复：

```bash
cd /home/ubuntu/workspace/idps/vsoc
docker compose up -d --wait mysql
make db-migrate
docker compose up -d --wait backend frontend
```

### idps-server 没有云端认证成功

确认服务和日志：

```bash
systemctl status idps-server.service --no-pager -l
journalctl -u idps-server.service -n 120 --no-pager
```

如果 VSOC 已恢复但 server 还没重试到成功，可以重启：

```bash
sudo systemctl restart idps-server.service
```

### idps-fw 没有监控 fwt0

确认 `/etc/idd/idps-fw.yaml` 是 Host 测试配置：

```bash
sudo grep -n 'fwt0\|rule_poll_interval_secs\|identity_overrides' /etc/idd/idps-fw.yaml
```

如果不是，重新生成并重启：

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make setup-dev
sudo systemctl restart idps-fw.service
```

### veth 或 netns 残留

清理后重建：

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make clean-dev
make setup-dev
sudo systemctl restart idps-fw.service
```

### `/etc/idd/fw-verify.conf` 缺失

重新跑：

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make setup-dev
```

### `fw-agent` 找不到动态库

症状通常是 `libidps_device_provider.so` 找不到。确认 root `make install` 已安装 provider：

```bash
ls -l /usr/local/lib/libidps_device_provider.so /usr/local/lib/libbydauto.so
sudo ldconfig
```

运行 `fw-verify` 时带上：

```bash
LD_LIBRARY_PATH=/usr/local/lib
```

`make test-host` 已经自动带了这个环境变量。

### app / UID 用例失败

确认 `setpriv` 存在：

```bash
command -v setpriv
```

确认 `/etc/idd/idps-fw.yaml` 里有默认映射：

```yaml
identity_overrides:
  - identity_key: "com.demo.browser"
    uid: 2000
    pkg_name: "com.demo.browser"
    app_name: "Browser"
```

改了 `HOST_APP_UID` 或 `HOST_APP_KEY` 后，需要重新：

```bash
make setup-dev HOST_APP_UID=<uid> HOST_APP_KEY=<identity>
sudo systemctl restart idps-fw.service
```

### 规则没有生效

看 `fw-verify health` 里的规则版本是否变化，并检查 `idps-fw` 日志：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf health

journalctl -u idps-fw.service -n 160 --no-pager
```

常见原因：

- VSOC 不健康，规则没有进云端。
- `idps-server` 云端认证失败，没有同步规则。
- `idps-fw` 没有重启到 Host 测试配置。
- `idps-fw` 仍在等待初始规则或 eBPF 加载失败。

### 事件没有出现或上报未 sent

先确认发流量前后确实穿过 `fwt0`：

```bash
ip -s link show dev fwt0
```

再看事件和 report 状态：

```bash
sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf stats

journalctl -u idps-fw.service -n 200 --no-pager
journalctl -u idps-server.service -n 200 --no-pager
```

---

## 11. 清理和恢复

清理 Host 测试拓扑和 `fw-verify` 配置：

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make clean-dev
```

这会删除：

- netns `fwpeer`
- veth `fwt0`
- `/etc/idd/fw-verify.conf`

如果要恢复普通 `idps-fw` host 配置：

```bash
cd /home/ubuntu/workspace/idps/idps-fw
make setup-dev
sudo systemctl restart idps-fw.service
```

如果想重新跑完整测试，直接回到 §5：

```bash
cd /home/ubuntu/workspace/idps/idps-fw-test
make clean-dev
make setup-dev
sudo systemctl restart idps-fw.service
make test-host
```

---

## 12. 最短可复制流程

下面是从干净 host runtime 到完整测试的一条命令线：

```bash
cd /home/ubuntu/workspace/idps/vsoc
make deploy

cd /home/ubuntu/workspace/idps
make install

cd /home/ubuntu/workspace/idps/idps-fw
make install

cd /home/ubuntu/workspace/idps/idps-fw-test
make install
make clean-dev
make setup-dev
sudo systemctl restart idps-fw.service

sudo NO_PROXY=127.0.0.1,localhost LD_LIBRARY_PATH=/usr/local/lib \
  fw-verify --config /etc/idd/fw-verify.conf preflight

make test-host
```

全部通过时，`run-all` 会给出完整目录的 `PASS` 结果；失败时优先按 §10 查 VSOC、`idps-server` 云端认证、`idps-fw` Host 配置和 veth/netns 拓扑。
