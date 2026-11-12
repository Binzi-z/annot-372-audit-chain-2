package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ReadAll 按链顺序读取全部事件（sealed + active），兼容旧的查询接口。
func ReadAll(dir string) ([]Event, error) {
	buckets := scanDiskBuckets(dir)
	var names []string
	for b := range buckets {
		names = append(names, b)
	}
	sort.Strings(names)

	var out []Event
	for _, b := range names {
		path, _ := locateSegment(dir, b)
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		err = scanLines(f, func(line []byte) error {
			var rec Record
			if err := json.Unmarshal(line, &rec); err != nil {
				return fmt.Errorf("corrupt record in %s: %w", b, err)
			}
			var e Event
			if err := json.Unmarshal(rec.Event, &e); err != nil {
				return fmt.Errorf("corrupt event in %s: %w", b, err)
			}
			out = append(out, e)
			return nil
		})
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
