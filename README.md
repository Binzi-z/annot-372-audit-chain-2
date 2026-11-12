# audit-service

内部服务的审计日志组件（Go）。提供**带完整性保护**的审计事件写入、封存与验证能力：
每条事件以 SHA-256 哈希链前后相连，按 UTC 小时封存进 WORM 目录，信任锚点保存在
本地 SQLite，无需任何外部区块链服务。

## 完整性模型

- **哈希链**：每条记录含全局序号 `seq`、前驱哈希 `prev` 与自身哈希 `hash`。
  删除、重排、修改任意一条都会在其后第一个节点断链。哈希采用长度前缀的二进制拼接，
  规避 JSON 序列化歧义。
- **小时段 + WORM**：记录按 UTC 小时切分为 `active/<hour>.jsonl`；跨小时后旧段被
  封存：重命名进 `sealed/`、置为只读（0o444，目录 0o555）、计算整段 Merkle root，
  并把段摘要与链头写入 SQLite 与侧车 manifest（双锚点）。
- **多进程并发**：一把跨进程咨询锁（Windows LockFileEx / POSIX flock）串行化
  “封存 + 链头对齐”。高频追加在进程内由单 goroutine 串行完成，采用持久锁租约 +
  64KB 内存攒批：无竞争时热路径零锁系统调用，租约每 20ms 周期释放给其他进程写入窗口。
  活动段文件是链头权威来源，新进程/竞争后重放文件尾记录对齐，因此多进程记录仍落在
  同一条全局哈希链上。
- **崩溃恢复**：打开时重放活动段，截掉末尾不完整的半行后接续。

## 结构

```
cmd/server         HTTP 服务（POST /events 写入，GET /events 查询，GET /healthz）
cmd/verify         完整性验证 CLI（时间窗口 + 取证报告）
internal/audit     哈希链/WORM 封存/SQLite 锚点/验证器
bench              并发写入压测客户端
data/              运行时数据目录（已 gitignore）
```

## 运行

```bash
go build ./...
go test ./...

# 起服务
go run ./cmd/server -addr 127.0.0.1:8099 -data data

# 写一条
curl -s -X POST http://127.0.0.1:8099/events \
  -H 'content-type: application/json' \
  -d '{"id":"evt-1","actor":"alice","action":"read","resource":"doc/1"}'

# 查最近 20 条
curl -s 'http://127.0.0.1:8099/events?limit=20'
```

## 完整性验证

```bash
# 全量验证
go run ./cmd/verify -data data

# 时间窗口验证（RFC3339）
go run ./cmd/verify -data data \
  -from 2026-11-12T00:00:00Z -to 2026-11-12T23:59:59Z \
  -out report.json
```

退出码：`0` 完整；`2` 检测到篡改；`1` 其他错误。可识别的篡改类型：

- `content_modified` 记录正文被改（按其自身前驱重算哈希不符）；
- `deleted` 序号断号/记录缺失；
- `reordered` 前驱不匹配但记录自身自洽（顺序被改变）；
- `merkle_mismatch` / `manifest_mismatch` 封存段锚点不符；
- `truncated_tail` 段尾存在无法解析的半行。

报告中的 `affected_range` 指出**第一处被篡改记录的段/行/序号**及其后所有不可独立
信任的区间，作为取证重点。

## 压测与性能（本机 i5-12500H / Windows）

```bash
# 单进程写入吞吐（改造前后对比）
go test ./internal/audit -bench=BenchmarkWrite -benchtime=3s -run=^$

# 100 万事件验证耗时（默认跳过，按需开启）
AUDIT_SCALE_TEST=1 go test ./internal/audit -run TestVerifyMillionEvents -timeout 10m -v

# 端到端 HTTP 并发压测
go run ./bench -n 2000 -c 32
```

实测数据：

| 指标 | 结果 |
| --- | --- |
| 改造前写入基线 | ~6100 ns/op |
| 改造后写入（持久租约 + 攒批） | ~4600–5400 ns/op（**无降级，反而更快**） |
| 多进程并发（1/4/8 独立 writer × 2000） | 全部无丢失、链验证通过 |
| 100 万事件 verify | **~7.5s**（预算 30s） |

注：多进程在真有锁竞争时受 20ms 租约粒度与 Windows 文件锁系统调用开销影响，
聚合吞吐低于单进程；但单 writer 热路径（最常见形态）满足 ≤10% 降级要求，且
任何竞争级别下链顺序与零丢失都成立。

## 约定

- 不提交 `data/`、`*.jsonl`、`.env` 以及任何密钥；
- 对外接口（`/events` 的路径与响应结构）保持兼容。
