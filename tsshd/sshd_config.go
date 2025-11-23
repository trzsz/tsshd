/*
MIT License

Copyright (c) 2024-2025 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

import (
	"bufio"
	"os"
	os_user "os/user"
	"path/filepath"
	"runtime"
	"strings"
)

var sshdConfigPath string
var sshdConfigMap map[string]string
var sshdSubsystemMap map[string]string

func getSshdConfigPath() string {
	if runtime.GOOS == "windows" {
		if path := os.Getenv("ProgramData"); path != "" {
			path = filepath.Join(path, "ssh", "sshd_config")
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		return "C:\\ProgramData\\ssh\\sshd_config"
	}

	for _, path := range []string{
		"/etc/ssh/sshd_config",
		"/usr/local/etc/ssh/sshd_config",
		"/usr/local/ssh/etc/sshd_config",
		"/opt/ssh/etc/sshd_config",
		"/opt/openssh/etc/sshd_config",
		"/usr/pkg/etc/ssh/sshd_config",
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return "/etc/ssh/sshd_config"
}

func getSshdConfig(key string) string {
	if val, ok := sshdConfigMap[strings.ToLower(key)]; ok {
		return val
	}
	return ""
}

func getSshdSubsystem(name string) string {
	if val, ok := sshdSubsystemMap[strings.ToLower(name)]; ok {
		return val
	}
	return ""
}

func initSshdConfig() {
	sshdConfigPath = getSshdConfigPath()

	var user string
	var groups []string
	if currentUser, err := os_user.Current(); err == nil {
		user = currentUser.Username
		if idx := strings.LastIndexByte(user, '\\'); idx >= 0 {
			user = user[idx+1:]
		}
		if gids, err := currentUser.GroupIds(); err == nil {
			for _, gid := range gids {
				if g, err := os_user.LookupGroupId(gid); err == nil {
					groups = append(groups, g.Name)
				}
			}
		}
	}

	parseSshdConfig(sshdConfigPath, user, groups)
}

func parseSshdConfig(path, user string, groups []string) {
	sshdConfigMap = make(map[string]string)
	sshdSubsystemMap = make(map[string]string)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	inMatch := false
	userMatch := false

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value := splitKeyValue(line)
		if value == "" {
			continue
		}

		if key == "match" {
			inMatch = true
			userMatch = evalMatchLine(value, user, groups)
			continue
		}

		if inMatch && !userMatch {
			continue
		}

		if key == "subsystem" {
			name, path := splitKeyValue(value)
			if name != "" && path != "" {
				sshdSubsystemMap[name] = path
			}
			continue
		}

		sshdConfigMap[key] = value
	}
}

func splitKeyValue(line string) (string, string) {
	pos := strings.IndexRune(line, '=')
	if pos >= 0 {
		p := strings.IndexAny(strings.TrimRight(line[:pos], " \t"), " \t")
		if p > 0 {
			pos = p
		}
	} else {
		pos = strings.IndexAny(line, " \t")
	}

	if pos < 0 {
		key := strings.ToLower(strings.TrimSpace(line))
		return key, ""
	}

	key := strings.ToLower(strings.TrimSpace(line[:pos]))
	value := strings.TrimSpace(line[pos+1:])
	return key, value
}

func wildcardMatch(pattern, value string) bool {
	matched, _ := filepath.Match(pattern, value)
	return matched
}

func evalMatchLine(line, user string, groups []string) bool {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return false
	}

	conds := map[string][]string{}
	addCondValue := func(key, vals string) {
		for v := range strings.SplitSeq(vals, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				conds[key] = append(conds[key], v)
			}
		}
	}

	for i := 0; i < len(tokens); i++ {
		token := tokens[i]

		// case 1: token contains "=" (e.g. "User=john", "User= john")
		if strings.Contains(token, "=") {
			kv := strings.SplitN(token, "=", 2)
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.TrimSpace(kv[1])
			// handle: "User= john" (next token is extra value part)
			if val == "" && i+1 < len(tokens) {
				i++
				val = tokens[i]
			}
			addCondValue(key, val)
			continue
		}

		// case 2: token is just "=" (means previous token is key) (e.g. "User = john")
		if token == "=" {
			if i-1 >= 0 && i+1 < len(tokens) {
				key := strings.ToLower(tokens[i-1])
				val := tokens[i+1]
				i++ // skip value token
				addCondValue(key, val)
			}
			continue
		}

		// case 3: token is KEY but next token starts with "=" (e.g. "User =john")
		if i+1 < len(tokens) && strings.HasPrefix(tokens[i+1], "=") {
			key := strings.ToLower(token)
			val := strings.TrimPrefix(tokens[i+1], "=")
			i++ // skip "=john"
			if val == "" && i+1 < len(tokens) {
				// case: "User =" "john"
				i++
				val = tokens[i]
			}
			addCondValue(key, val)
			continue
		}

		// case 4: KEY VALUE
		key := strings.ToLower(token)
		if i+1 < len(tokens) {
			i++
			addCondValue(key, tokens[i])
			continue
		}
	}

	return evalMatchConditions(conds, user, groups)
}

func evalMatchConditions(conds map[string][]string, user string, groups []string) bool {
	if pats, ok := conds["user"]; ok {
		if !matchList(user, pats) {
			return false
		}
	}

	if pats, ok := conds["group"]; ok {
		groupOK := false
		for _, g := range groups {
			if matchList(g, pats) {
				groupOK = true
				break
			}
		}
		if !groupOK {
			return false
		}
	}

	return true
}

func matchList(value string, patterns []string) bool {
	hasPositive := false
	positiveMatch := false

	for _, p := range patterns {
		pat := p
		neg := strings.HasPrefix(p, "!")
		if neg {
			pat = strings.TrimSpace(p[1:])
		}

		if wildcardMatch(pat, value) {
			if neg {
				return false
			}
			hasPositive = true
			positiveMatch = true
		} else {
			if !neg {
				hasPositive = true
			}
		}
	}

	if hasPositive {
		return positiveMatch
	}

	return true
}
