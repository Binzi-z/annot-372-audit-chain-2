package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// ReadAll 按链顺序读取全部事件（封存段 + 当前活动段）。
// 保持与旧版相同的函数签名，供查询接口与测试使用。
func ReadAll(dir string) ([]Event, error) {
	var paths []string

	sealed, err := listSegments(filepath.Join(dir, sealedDirName))
	if err != nil {
		return nil, err
	}
	paths = append(paths, sealed...)

	active, err := listSegments(filepath.Join(dir, activeDirName))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	paths = append(paths, active...)

	sort.Strings(paths)

	var out []Event
	for _, p := range paths {
		evs, err := readEvents(p)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	return out, nil
}

func listSegments(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var paths []string
	for _, en := range entries {
		if filepath.Ext(en.Name()) == ".jsonl" {
			paths = append(paths, filepath.Join(dir, en.Name()))
		}
	}
	return paths, nil
}

func readEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, err
		}
		out = append(out, env.Event)
	}
	return out, sc.Err()
}
