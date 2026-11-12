package audit

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// manifest 是每个封存段旁边的只读取证清单（<hour>.manifest.json）。
// 它与 SQLite 中的 segments 行互为冗余：即使数据库被删，验证器仍可仅凭
// WORM 目录完成链与 Merkle 校验。
type manifest struct {
	Version    int    `json:"version"`
	Hour       string `json:"hour"`
	Segment    string `json:"segment"`
	Count      int    `json:"count"`
	StartSeq   uint64 `json:"start_seq"`
	EndSeq     uint64 `json:"end_seq"`
	MerkleRoot string `json:"merkle_root"`
	HeadHash   string `json:"head_hash"`
	HashAlgo   string `json:"hash_algo"`
}

func writeManifest(dir, hour, base string, count int, startSeq, endSeq uint64, root, head []byte) error {
	m := manifest{
		Version: envelopeVersion, Hour: hour, Segment: base, Count: count,
		StartSeq: startSeq, EndSeq: endSeq,
		MerkleRoot: hex.EncodeToString(root), HeadHash: hex.EncodeToString(head),
		HashAlgo: HashAlgo,
	}
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, hour+".manifest.json")
	if err := os.WriteFile(path, buf, 0o444); err != nil {
		return err
	}
	return os.Chmod(path, 0o444)
}

func readManifest(dir, hour string) (*manifest, error) {
	buf, err := os.ReadFile(filepath.Join(dir, hour+".manifest.json"))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
