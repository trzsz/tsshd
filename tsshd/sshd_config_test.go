/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSshdConfig(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "sshd_config_*.conf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	sshdConfigContent := `# This is a test sshd_config
Port 22
PORT 2222
# Port 3333

LogLevel 			INFO
AddressFamily any
AcceptEnv LANG LC_ALL

AllowAgentForwarding yes
AllowTcpForwarding No
X11Forwarding Yes

Subsystem sftp	/usr/lib/openssh/sftp-server
Subsystem Asvr	/tmp/bin/asvr

Match User mary
		LogLevel 		ERROR
    AllowAgentForwarding no

Match Group admin
    AllowTcpForwarding Yes
	AcceptEnv LANG LC_*
Subsystem Asvr	/usr/bin/asvr

Match User bob Group=users
		AcceptEnv LC_*
		AddressFamily inet
    AllowTcpForwarding no
`
	if _, err := tmpFile.WriteString(sshdConfigContent); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	_ = tmpFile.Close()

	assert := assert.New(t)
	parseSshdConfig(tmpFile.Name(), "john", []string{"admin", "users"})

	assert.Equal("2222", getSshdConfig("Port"))
	assert.Equal("INFO", getSshdConfig("LogLevel"))
	assert.Equal("any", getSshdConfig("addressfamily"))
	assert.Equal("yes", getSshdConfig("AllowAgentForwarding"))
	assert.Equal("Yes", getSshdConfig("AllowTcpForwarding"))
	assert.Equal("Yes", getSshdConfig("X11Forwarding"))
	assert.Equal("/usr/lib/openssh/sftp-server", getSshdSubsystem("sftp"))
	assert.Equal("/usr/bin/asvr", getSshdSubsystem("ASVR"))
}

func TestSplitKeyValue(t *testing.T) {
	assert := assert.New(t)

	assertSplitEqual := func(line, key, value string) {
		k, v := splitKeyValue(line)
		assert.Equal(key, k)
		assert.Equal(value, v)
	}

	assertSplitEqual("Key=Value", "key", "Value")
	assertSplitEqual("Key =Value", "key", "Value")
	assertSplitEqual("Key= Value", "key", "Value")
	assertSplitEqual("Key = Value", "key", "Value")
	assertSplitEqual("Key  = Value", "key", "Value")
	assertSplitEqual("Key  =  Value", "key", "Value")
	assertSplitEqual("Key \t= \tValue", "key", "Value")

	assertSplitEqual("Key Value", "key", "Value")
	assertSplitEqual("Key\tValue", "key", "Value")
	assertSplitEqual("Key \tValue", "key", "Value")
	assertSplitEqual("Key\t Value", "key", "Value")
	assertSplitEqual("Key \t Value", "key", "Value")
	assertSplitEqual("Key \t\t Value", "key", "Value")
	assertSplitEqual("Key \t \t Value", "key", "Value")

	assertSplitEqual("Key", "key", "")
	assertSplitEqual("Key ", "key", "")
	assertSplitEqual("Key\t", "key", "")
	assertSplitEqual("Key \t", "key", "")
	assertSplitEqual("Key \t ", "key", "")

	assertSplitEqual("Key=", "key", "")
	assertSplitEqual("Key =", "key", "")
	assertSplitEqual("Key = ", "key", "")
	assertSplitEqual("Key  =", "key", "")

	assertSplitEqual("Key Value=", "key", "Value=")
	assertSplitEqual("Key Value =", "key", "Value =")
	assertSplitEqual("Key Value = ", "key", "Value =")
	assertSplitEqual("Key \t Value =", "key", "Value =")
	assertSplitEqual("Key \t Value = C", "key", "Value = C")
}

func TestEvalMatchLine(t *testing.T) {
	assert := assert.New(t)

	// empty
	assert.False(evalMatchLine("", "", nil))
	assert.False(evalMatchLine("", "john", nil))

	// user only
	assert.True(evalMatchLine("User=john", "john", nil))
	assert.True(evalMatchLine("User =john", "john", nil))
	assert.True(evalMatchLine("User= john", "john", nil))
	assert.True(evalMatchLine("user = john", "john", nil))
	assert.True(evalMatchLine("User john", "john", nil))
	assert.True(evalMatchLine("User\tjohn", "john", nil))
	assert.True(evalMatchLine("User \t john", "john", nil))

	assert.False(evalMatchLine("user=john", "mary", nil))
	assert.False(evalMatchLine("User john", "mary", nil))

	// multi users
	assert.True(evalMatchLine("User=john,mary", "mary", nil))
	assert.True(evalMatchLine("User =john,mary", "mary", nil))
	assert.True(evalMatchLine("User= john,mary,bob", "mary", nil))
	assert.True(evalMatchLine("User = john,mary,bob", "mary", nil))
	assert.True(evalMatchLine("User john,mary,bob", "mary", nil))
	assert.True(evalMatchLine("User\tjohn,mary,bob", "mary", nil))
	assert.True(evalMatchLine("user \t john,mary,bob", "mary", nil))

	assert.False(evalMatchLine("user=john,mary", "bob", nil))
	assert.False(evalMatchLine("User john,mary", "bob", nil))

	// negate user
	assert.True(evalMatchLine("User=!root", "bob", nil))
	assert.True(evalMatchLine("User =!root", "bob", nil))
	assert.True(evalMatchLine("User= !root", "bob", nil))
	assert.True(evalMatchLine("User = !root", "bob", nil))
	assert.True(evalMatchLine("User !root", "bob", nil))
	assert.True(evalMatchLine("User\t!root", "bob", nil))
	assert.True(evalMatchLine("user \t !root", "bob", nil))

	assert.True(evalMatchLine("User=!john,!admin", "bob", nil))
	assert.True(evalMatchLine("User !mary,!bob", "john", nil))

	assert.False(evalMatchLine("User=!root", "root", nil))
	assert.False(evalMatchLine("user !root", "root", nil))

	assert.False(evalMatchLine("User !john,!admin", "john", nil))
	assert.False(evalMatchLine("User=!mary,!bob", "bob", nil))

	// user wildcard
	assert.True(evalMatchLine("User=jo*", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("User=j?h*", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("User=*hn", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("User=ma*", "john", []string{"admin", "docker"}))

	// mixed positive + negative group
	assert.True(evalMatchLine("User=john,!mary", "john", nil))
	assert.True(evalMatchLine("User =john,!mary", "john", nil))
	assert.True(evalMatchLine("User= john,!mary", "john", nil))
	assert.True(evalMatchLine("User = john,!mary", "john", nil))
	assert.True(evalMatchLine("User john,!mary", "john", nil))
	assert.True(evalMatchLine("User\tjohn,!mary", "john", nil))
	assert.True(evalMatchLine("user \t john,!mary", "john", nil))

	assert.True(evalMatchLine("User=joh*,!johx", "john", nil))
	assert.True(evalMatchLine("User=!ma*", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("User=joh*,!johx", "johx", nil))
	assert.False(evalMatchLine("User=!jo*", "john", []string{"admin", "docker"}))

	assert.False(evalMatchLine("User = john,!mary", "mary", nil))
	assert.False(evalMatchLine("User = john,!mary", "bob", nil))
	assert.False(evalMatchLine("User john,!mary", "mary", nil))
	assert.False(evalMatchLine("user john,!mary", "bob", nil))

	// group only
	assert.True(evalMatchLine("Group=admin", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group =admin", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group= admin", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group = admin", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group admin", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group\tadmin", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group \t admin", "john", []string{"admin"}))

	assert.True(evalMatchLine("Group=admin", "john", []string{"users", "docker", "admin"}))
	assert.True(evalMatchLine("Group  admin", "john", []string{"users", "docker", "admin"}))

	assert.False(evalMatchLine("Group=admin", "john", []string{"root"}))
	assert.False(evalMatchLine("Group admin", "john", []string{"root"}))
	assert.False(evalMatchLine("Group=admin", "john", []string{"users", "docker"}))
	assert.False(evalMatchLine("Group admin", "john", []string{"users", "docker"}))

	// multi groups
	assert.True(evalMatchLine("Group=admin,docker", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group admin,docker", "john", []string{"docker"}))
	assert.True(evalMatchLine("Group = admin,docker", "john", []string{"root", "docker"}))
	assert.True(evalMatchLine("Group   admin,docker", "john", []string{"admin", "root"}))

	assert.False(evalMatchLine("Group=admin,docker", "john", nil))
	assert.False(evalMatchLine("Group=admin,docker", "john", []string{"root"}))
	assert.False(evalMatchLine("Group admin,docker", "john", []string{"root", "users"}))

	// negate group
	assert.True(evalMatchLine("Group=!admin", "john", []string{"root"}))
	assert.True(evalMatchLine("Group !wheel", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group=!admin,!docker", "john", []string{"users"}))
	assert.True(evalMatchLine("group  \t !wheel,!root", "john", []string{"admin"}))

	assert.False(evalMatchLine("Group=!admin", "john", []string{"admin"}))
	assert.False(evalMatchLine("group  !wheel", "john", []string{"wheel"}))
	assert.False(evalMatchLine("Group=!admin,!docker", "john", []string{"docker"}))
	assert.False(evalMatchLine("group  \t !wheel,!root", "john", []string{"root"}))

	// group wildcard
	assert.True(evalMatchLine("Group=adm*", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("Group=docke?", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("Group=wh*", "john", []string{"admin", "docker"}))

	// mixed positive + negative group
	assert.True(evalMatchLine("Group=admin,!wheel", "bob", []string{"admin"}))
	assert.True(evalMatchLine("Group=wheel,!admin", "bob", []string{"wheel"}))

	assert.False(evalMatchLine("group admin,!wheel", "bob", []string{"wheel"}))
	assert.False(evalMatchLine("group wheel,!admin", "bob", []string{"admin"}))

	assert.True(evalMatchLine("group whee*,!wheel", "bob", []string{"wheex"}))
	assert.False(evalMatchLine("group whee*,!wheel", "bob", []string{"wheel"}))
	assert.False(evalMatchLine("Group=!adm*", "john", []string{"admin"}))
	assert.True(evalMatchLine("Group=!adm*", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("Group=!wh*", "john", []string{"admin", "docker"}))

	// user + group
	assert.True(evalMatchLine("User=john Group=admin", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("User john Group admin", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("User=jo* Group=adm*", "john", []string{"admin", "docker"}))

	assert.False(evalMatchLine("User=john Group=wheel", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("User=bob Group=admin", "john", []string{"admin", "docker"}))

	// multi values
	assert.True(evalMatchLine("User=john,mary Group=admin,docker", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("User=john,mary Group=wheel,root", "john", []string{"admin", "docker"}))

	// with negation
	assert.True(evalMatchLine("User=john Group=!wheel", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("User=john Group=!wheel", "john", []string{"admin", "wheel"}))
	assert.False(evalMatchLine("User=!john Group=admin", "john", []string{"admin", "docker"}))

	// mixed positive + negative
	assert.True(evalMatchLine("User=john,!mary Group=admin,!wheel", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("User=john,!mary Group=admin,!wheel", "mary", []string{"admin", "docker"}))
	assert.False(evalMatchLine("User=john,!mary Group=!admin,!docker", "john", []string{"admin", "docker"}))

	// wildcards inside and
	assert.True(evalMatchLine("User=jo* Group=adm*", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("User=jo* Group=wh*", "john", []string{"admin", "wheel"}))
	assert.False(evalMatchLine("User=ma* Group=adm*", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("User=jo* Group=wh*", "john", []string{"admin", "docker"}))

	// spacing + tab
	assert.True(evalMatchLine("User \t john \t Group = admin", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("User= john   Group= admin , docker", "john", []string{"admin", "docker"}))

	// reverse order (group then User)
	assert.True(evalMatchLine("Group=admin User=john", "john", []string{"admin", "docker"}))
	assert.True(evalMatchLine("Group admin User \t john", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("Group=wheel User=john", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("Group=admin User=bob", "john", []string{"admin", "docker"}))
	assert.False(evalMatchLine("Group \t admin User  bob", "john", []string{"admin", "docker"}))
}
