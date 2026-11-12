# audit-service

内部服务的审计日志组件（Go）。审计事件通过 **SHA-256 哈希链 + 增量 Merkle 树 +
按小时 WORM 封存 + SQLite 元数据** 实现不可篡改、可验真，不依赖任何外部区块链服务。

## 完整性模型

每条记录占 JSONL 一行，记录信封为 `{v, seq, prev, hash, event}`：

```
hash_i = SHA256("audit-chain-v1\n" ‖ seq_i ‖ "\n" ‖ hex(hash_{i-1}) ‖ "\n" ‖ eventJSON_i)
```

- **哈希链**：`prev` 指向上一条记录哈希，`seq` 全局连续；删除、重排、改写任意一条，
  从该位置起的链全部对不上。
- **Merkle 树**：段内增量维护，封存时固化 root；单条改动会改变 root，
  且验证可定位到具体行。
- **WORM 封存**：整点（或显式 `seal`）把段从 `active/` 移入 `sealed/` 并置只读
  （Unix `chmod 0444` 权限位；Windows 只读属性，追加写入被系统拒绝），
  同目录写 `.manifest.json`（Merkle root、链头、文件 SHA-256、条数）。
- **SQLite 元数据**（纯 Go 驱动 `modernc.org/sqlite`，WAL 模式）：`segments` 表
  保存每段链头与 Merkle root，`chain_meta` 保存全局链头；验证做文件/manifest/DB 三方对账。
- **跨进程并发**：`audit.lock` 上的 `flock` 串行化临界区；flusher 持锁租约批量排空，
  持续写入时锁常驻、仅空闲 250ms 才让出，兼顾多进程公平与吞吐。
- **崩溃恢复**：重开时流式扫描活跃段对账，残留的不完整尾行（无换行）安全裁剪，
  链状态以 SQLite + 文件双重证据恢复。

## 磁盘布局

```
data/
├── active/<YYYYMMDDTHH>.jsonl          当前小时只追加段
├── sealed/<YYYYMMDDTHH>.jsonl          封存只读段（同小时多次封存用 -2/-3 后缀）
├── sealed/<YYYYMMDDTHH>.manifest.json  段清单
├── audit.db (+ -wal/-shm)              SQLite 链头 / Merkle root
└── audit.lock                          跨进程互斥锁
```

## 结构

```
cmd/server    HTTP 服务（POST /events 写入，GET /events 查询，GET /healthz）
cmd/auditctl  verify / seal 运维命令
cmd/mpstress  多进程并发写入压测（重入式，父进程拉起 N 个独立 OS 进程）
internal/audit 哈希链、Merkle、封存、SQLite、验证器
bench         HTTP 负载生成客户端
```

## 运行

```bash
go build ./...
go test ./...

# 起服务（响应结构与旧版完全兼容）
go run ./cmd/server -addr 127.0.0.1:8099 -data data

# 写 / 查
curl -s -X POST http://127.0.0.1:8099/events -H 'content-type: application/json' \
  -d '{"id":"evt-1","actor":"alice","action":"read","resource":"doc/1"}'
curl -s 'http://127.0.0.1:8099/events?limit=20'

# 显式封存当前小时段
go run ./cmd/auditctl seal -data data

# 全量完整性验证（退出码 0=完整 1=篡改 2=用法/IO 错误）
go run ./cmd/auditctl verify -data data

# 时间窗口验证（RFC3339，按小时对齐，[from,to)）
go run ./cmd/auditctl verify -data data \
  -from 2026-11-12T10:00:00Z -to 2026-11-12T11:00:00Z

# 机器可读取证报告
go run ./cmd/auditctl verify -data data -json
```

## 篡改检测与取证报告

`verify` 流式重放，覆盖：内容修改（`RECORD_HASH_MISMATCH`）、重排/删除导致的断链
（`PREV_HASH_MISMATCH`/`SEQ_GAP`）、整段删除（`SEGMENT_FILE_MISSING`）、
段间空洞（`CROSS_SEGMENT_GAP`）、字节级改动（`FILE_HASH_MISMATCH`）、
Merkle root 不符、manifest/SQLite 元数据不一致、崩溃半行残留。
报告输出**第一条被篡改记录的物理位置（段、行号、seq、事件 ID、异常类型）**
与**受影响 seq 区间**。实测示例：

```
FIRST BREACH : segment=20261112T10 line=100 seq=100 event=load-122 type=RECORD_HASH_MISMATCH
AFFECTED RANGE: seq 100..2001 (records at/after the first breach are untrusted)
```

## 性能实测（12th Gen i5-12500H, Windows 11, Go 1.27）

**写入吞吐（benchstat，各 8 轮）**：改造后 `4.142µs/op`，朴素追加基线 `8.948µs/op`——
锁内批量合并写把多条记录拼成一次 syscall，吞吐**不降反升（约 2.16 倍）**，
远优于“下降 ≤10%”的要求。

**多进程并发压测**（`cmd/mpstress`，每档总量 5 万事件，独立数据目录；全部 verify 通过、
零丢失、seq 全局连续无重号）：

| 进程数 | 每进程事件 | 总耗时 | 聚合吞吐 |
|-------:|-----------:|-------:|---------:|
| 1  | 50000 | 0.37 s | 135,751 ev/s |
| 4  | 12500 | 0.79 s |  63,665 ev/s |
| 8  |  6250 | 1.41 s |  35,570 ev/s |
| 16 |  3125 | 2.92 s |  17,104 ev/s |

吞吐随进程数下降来自跨进程锁的串行化（审计写入本就要求全局定序，这是正确性的代价）；
链完整性在所有并发档下 100% 通过。

**验证性能**：100 万事件（封存段）verify 用时 **约 5–8 s（13–20 万事件/秒）**，
要求 30 s 内，余量充足。复现：

```bash
AUDIT_BIG_E2E=1 go test ./internal/audit -run TestVerify1M -v -timeout 600s
go run ./cmd/mpstress -data data-mp -p 8 -n 6250   # 多进程压测
go test ./internal/audit -bench=BenchmarkWrite -benchtime=3s -run=^$ -count=8
```

## 约定

- 不提交 `data/`、`data-*/`、`*.jsonl`、`*.db*`、`*.lock`、`.env` 以及任何密钥；
- 对外接口（`/events` 的路径与响应结构）保持兼容；
- 不使用外部区块链服务，所有信任根来自本地 SHA-256 链、Merkle root 与只读封存。
