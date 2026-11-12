// Package audit 提供带哈希链与封存（WORM）能力的审计事件写入、
// 封存与完整性验证能力。
//
// 磁盘布局：
//
//	<data>/active/<YYYYMMDDTHH>.jsonl        当前小时的只追加段
//	<data>/sealed/<YYYYMMDDTHH>.jsonl        封存后的只读段（WORM）
//	<data>/sealed/<YYYYMMDDTHH>.manifest.json 段清单（Merkle root 等）
//	<data>/audit.db                          SQLite 元数据（链头 / Merkle root）
//	<data>/audit.lock                        跨进程互斥锁
//
// 每条记录占一行（JSONL），记录之间通过 SHA-256 哈希链首尾相接：
//
//	hash_i = SHA256("audit-chain-v1\n" ‖ seq_i ‖ "\n" ‖ hex(hash_{i-1}) ‖ "\n" ‖ eventJSON_i)
//
// 段内同时维护增量 Merkle 树，封存时落盘 Merkle root，使任意单条记录的
// 删除、重排、内容修改都可在验证时被定位。
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// RecordVersion 是记录信封格式版本，格式演进时递增。
const RecordVersion = 1

// 域分隔前缀，避免不同用途的哈希之间被混用构造碰撞。
const (
	domainChain = "audit-chain-v1\n"
	domainLeaf  = "audit-leaf-v1\n"
	domainNode  = "audit-node-v1\n"
)

// GenesisHash 是创世记录（seq=1）的 prev 哈希：64 个零。
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record 是 JSONL 中的记录信封。字段顺序固定，保证序列化结果确定。
type Record struct {
	V     int             `json:"v"`
	Seq   int64           `json:"seq"`
	Prev  string          `json:"prev"`
	Hash  string          `json:"hash"`
	Event json.RawMessage `json:"event"`
}

// ChainHash 计算一条记录的链哈希。eventJSON 必须是事件的规范序列化原文
// （encoding/json 对 struct 按字段序、对 map 按 key 排序，输出确定）。
func ChainHash(seq int64, prevHex string, eventJSON []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domainChain))
	var num [20]byte
	h.Write(strconv.AppendInt(num[:0], seq, 10))
	h.Write([]byte{'\n'})
	h.Write([]byte(prevHex))
	h.Write([]byte{'\n'})
	h.Write(eventJSON)
	return h.Sum(nil)
}

// LeafHash 是 Merkle 叶子哈希，输入为整条记录行（含换行符以外的原文）。
func LeafHash(recordLine []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domainLeaf))
	h.Write(recordLine)
	return h.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domainNode))
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func toHex(b []byte) string { return hex.EncodeToString(b) }

// merkleBuilder 增量维护 Merkle 树：栈中保存若干棵大小互异的完美子树，
// 相邻同大小子树立即合并。Root 用右折叠得到，与全量重算结果一致。
type merkleBuilder struct {
	stack [][]byte
	sizes []int64
	count int64
}

func (m *merkleBuilder) add(recordLine []byte) {
	cur := LeafHash(recordLine)
	size := int64(1)
	for len(m.sizes) > 0 && m.sizes[len(m.sizes)-1] == size {
		top := m.stack[len(m.stack)-1]
		m.stack = m.stack[:len(m.stack)-1]
		m.sizes = m.sizes[:len(m.sizes)-1]
		// top 是更早的叶子，始终作为左子树。
		cur = nodeHash(top, cur)
		size *= 2
	}
	m.stack = append(m.stack, cur)
	m.sizes = append(m.sizes, size)
	m.count++
}

// root 返回当前 Merkle root；空树返回 nil。
func (m *merkleBuilder) root() []byte {
	if len(m.stack) == 0 {
		return nil
	}
	r := m.stack[len(m.stack)-1]
	for i := len(m.stack) - 2; i >= 0; i-- {
		r = nodeHash(m.stack[i], r)
	}
	return r
}

// merkleRootBruteForce 是独立的参考实现，仅用于测试对齐增量实现。
// 约定与增量栈一致：从左到右两两配对，落单的节点作为右子树折叠。
func merkleRootBruteForce(lines [][]byte) []byte {
	if len(lines) == 0 {
		return nil
	}
	nodes := make([][]byte, len(lines))
	for i, l := range lines {
		nodes[i] = LeafHash(l)
	}
	for len(nodes) > 1 {
		var next [][]byte
		i := 0
		for ; i+1 < len(nodes); i += 2 {
			next = append(next, nodeHash(nodes[i], nodes[i+1]))
		}
		if i < len(nodes) {
			next = append(next, nodes[i])
		}
		nodes = next
	}
	return nodes[0]
}
