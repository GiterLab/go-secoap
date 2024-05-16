// Copyright 2024 tobyzxj
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secoapcore

import (
	"hash/crc32"

	"github.com/GiterLab/crc16"
)

// crc16BytesModbus 对数据流进行CRC16校验（CRC16-MODBUS）
func crc16BytesModbus(data []byte) uint16 {
	table := crc16.MakeTable(crc16.CRC16_MODBUS)
	h := crc16.New(table)
	h.Write(data)
	return h.Sum16()
}

// CRC16Bytes 对数据流进行CRC16校验
func CRC16Bytes(data []byte) uint16 {
	return crc16BytesModbus(data)
}

// CRC32Bytes 计算一个数据流的CRC32值
func CRC32Bytes(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// CRC32String 计算一个字符串的CRC32值
func CRC32String(str string) uint32 {
	return crc32.ChecksumIEEE([]byte(str))
}
