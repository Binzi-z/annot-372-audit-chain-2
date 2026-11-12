package audit

import (
	"crypto/sha256"
	"encoding/binary"
)

// HashAlgo 是链上使用的哈希算法标识。
const HashAlgo = "sha256"

// chainGenesis 是链的创世前驱哈希（第一条记录的 prev）。
var chainGenesis = make([]byte, sha256.Size)

// RecordHash 计算一条记录的哈希。
//
// 哈希输入采用长度前缀的二进制拼接，而不是 JSON 文本，避免键序、空白、
// Unicode 转义等编码差异导致同一事件算出不同摘要：
//
//	H(prev || u64(seq) || u32(len(id)) || id ||
//	   u64(time_unix) || u32(len(actor)) || actor ||
//	   u32(len(action)) || action || u32(len(resource)) || resource ||
//	   u32(len(extra_json)) || extra_json)
//
// extra 直接使用落盘的规范化 JSON（map 键已排序），保证"磁盘内容即哈希内容"。
func RecordHash(prev []byte, seq uint64, e Event, extraJSON []byte) []byte {
	h := sha256.New()
	writeBytes(h, prev)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], seq)
	h.Write(buf[:])
	writeStr(h, e.ID)
	binary.BigEndian.PutUint64(buf[:], uint64(e.Time.UnixNano()))
	h.Write(buf[:])
	writeStr(h, e.Actor)
	writeStr(h, e.Action)
	writeStr(h, e.Resource)
	writeBytes(h, extraJSON)
	return h.Sum(nil)
}

func writeStr(h interface{ Write([]byte) (int, error) }, s string) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	h.Write(l[:])
	h.Write([]byte(s))
}

func writeBytes(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

// MerkleRoot 计算一个封存段内所有记录哈希的 Merkle root。
//
// 规则（Bitcoin 风格，结果稳定可复现）：
//   - 空列表返回全零；
//   - 单节点的 root 即其自身；
//   - 每层奇数节点时，复制最后一个节点再两两配对；
//   - 父节点 = sha256(left || right)。
func MerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, sha256.Size)
	}
	layer := make([][]byte, len(leaves))
	copy(layer, leaves)
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, layer[len(layer)-1])
		}
		next := make([][]byte, 0, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			h := sha256.New()
			h.Write(layer[i])
			h.Write(layer[i+1])
			next = append(next, h.Sum(nil))
		}
		layer = next
	}
	return layer[0]
}
