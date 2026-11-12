package audit

import (
	"encoding/hex"
	"encoding/json"
)

// envelopeVersion 是落盘记录信封的格式版本。
const envelopeVersion = 1

// envelope 是一条审计记录在段文件中的落盘形态（每行一个 JSON）。
//
// 链字段（seq/prev/hash）与事件正文放在一起：验证时无需依赖任何外部状态，
// 仅凭段文件即可重放整条哈希链。extra_raw 保存 Extra 的规范化 JSON，
// 哈希直接覆盖这串字节，避免 map 反序列化再序列化带来的数字精度/键序漂移。
type envelope struct {
	Version  int             `json:"v"`
	Seq      uint64          `json:"seq"`
	PrevHash string          `json:"prev"`
	Hash     string          `json:"hash"`
	Event    Event           `json:"event"`
	ExtraRaw json.RawMessage `json:"extra_raw,omitempty"`
}

// marshalExtra 将 Extra 规范化为 JSON（encoding/json 对 map 键按字典序输出，
// 同一输入永远得到同一字节串）。空 Extra 返回 nil。
func marshalExtra(e Event) (json.RawMessage, error) {
	if len(e.Extra) == 0 {
		return nil, nil
	}
	return json.Marshal(e.Extra)
}

// buildEnvelope 在给定前驱与序号下构造一条带哈希的记录信封。
func buildEnvelope(prev []byte, seq uint64, e Event, extraRaw json.RawMessage) envelope {
	h := RecordHash(prev, seq, e, extraRaw)
	return envelope{
		Version:  envelopeVersion,
		Seq:      seq,
		PrevHash: hex.EncodeToString(prev),
		Hash:     hex.EncodeToString(h),
		Event:    e,
		ExtraRaw: extraRaw,
	}
}
