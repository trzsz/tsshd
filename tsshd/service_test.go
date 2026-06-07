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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePortRanges(t *testing.T) {
	enableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = enableWarning }()

	assert := assert.New(t)
	assert.Equal([][2]uint16{{22, 22}}, parsePortRanges("22"))
	assert.Equal([][2]uint16{{100, 102}}, parsePortRanges("100-102"))
	assert.Equal([][2]uint16{{200, 202}}, parsePortRanges("200 - 202"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}, {30, 30}}, parsePortRanges("10 20 30"))
	assert.Equal([][2]uint16{{1, 3}, {5, 5}, {7, 9}, {11, 11}}, parsePortRanges("1-3 5,7 - 9 11"))
	assert.Equal([][2]uint16{{1, 2}, {3, 4}, {5, 5}}, parsePortRanges("1-2,3-4 5"))
	assert.Equal([][2]uint16{{10, 12}, {15, 15}}, parsePortRanges("  10\t-\t12  , 15 "))
	assert.Equal([][2]uint16{{50, 50}}, parsePortRanges("50-50"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}}, parsePortRanges("10,,20"))
	assert.Equal([][2]uint16(nil), parsePortRanges("0,70000,abc"))
	assert.Equal([][2]uint16(nil), parsePortRanges("100-50"))
	assert.Equal([][2]uint16(nil), parsePortRanges("-"))
	assert.Equal([][2]uint16(nil), parsePortRanges("- 10"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 -"))
	assert.Equal([][2]uint16{{1, 3}, {7, 7}}, parsePortRanges("1-3,abc,5 - 4,7"))
	assert.Equal([][2]uint16(nil), parsePortRanges(""))
	assert.Equal([][2]uint16(nil), parsePortRanges("8000-9000-10000"))
	assert.Equal([][2]uint16(nil), parsePortRanges("8000-"))
	assert.Equal([][2]uint16(nil), parsePortRanges("-9000"))
	assert.Equal([][2]uint16{{10, 12}}, parsePortRanges("10 - 12 - 15"))
	assert.Equal([][2]uint16{{1, 65535}}, parsePortRanges("1-65535"))
	assert.Equal([][2]uint16{{10, 10}, {10, 10}, {10, 10}}, parsePortRanges("10 10 10"))
	assert.Equal([][2]uint16{{20, 25}, {22, 23}}, parsePortRanges("20-25 22-23"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 - 0"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 - - 11"))
	assert.Equal([][2]uint16{{10, 11}}, parsePortRanges("10 - 11 -"))
}
