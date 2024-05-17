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

package coderv0

import (
	"encoding/binary"
	"fmt"

	"github.com/GiterLab/go-secoap/secoapcore"
)

var DefaultCoder = new(Coder)

type Coder struct{}

func (c *Coder) Size(m secoapcore.Message) (int, error) {
	size := 4
	payloadLen := len(m.Payload)
	size += payloadLen
	return size, nil
}

func (c *Coder) Encode(m secoapcore.Message, buf []byte) (int, error) {
	/*
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|0 0|R|R|R|R| T |  EID  |  ETP  |    CRC16-L    |    CRC16-H    |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		| Payload (if any) ...
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	if !secoapcore.ValidateType(m.Type) {
		return -1, fmt.Errorf("invalid Type(%v)", m.Type)
	}
	if !secoapcore.ValidateEID(m.EncoderID) {
		return -1, fmt.Errorf("invalid EncoderID(%v)", m.EncoderID)
	}
	if !secoapcore.ValidateETP(m.EncoderType) {
		return -1, fmt.Errorf("invalid EncoderType(%v)", m.EncoderType)
	}
	size, err := c.Size(m)
	if err != nil {
		return -1, err
	}
	if len(buf) < size {
		return size, secoapcore.ErrTooSmall
	}

	m.Crc16 = secoapcore.CRC16Bytes(m.Payload)
	tmpbufCRC16 := []byte{0, 0}
	binary.LittleEndian.PutUint16(tmpbufCRC16, m.Crc16)

	pbuf := buf
	pbuf[0] = byte(m.Type)
	pbuf[1] = byte(m.EncoderID<<4) | byte(m.EncoderType)
	pbuf[2] = tmpbufCRC16[0]
	pbuf[3] = tmpbufCRC16[1]
	pbuf = pbuf[4:]

	copy(pbuf, m.Payload)

	return size, nil
}

func (c *Coder) Decode(data []byte, m *secoapcore.Message) (int, error) {
	size := len(data)
	if size < 4 {
		return -1, secoapcore.ErrMessageTruncated
	}

	if data[0]>>6 != 0 { // version 0
		return -1, secoapcore.ErrMessageInvalidVersion
	}

	typ := secoapcore.Type(data[0] & 0x3)
	eid := int32(data[1] >> 4)
	etp := int32(data[1] & 0xf)
	crc16 := binary.LittleEndian.Uint16(data[2:4])
	data = data[4:]

	m.Ver = secoapcore.Version0
	m.Payload = data

	m.Type = typ
	m.EncoderID = eid
	m.EncoderType = etp

	m.Crc16 = crc16
	if m.Crc16 != secoapcore.CRC16Bytes(m.Payload) {
		return -1, secoapcore.ErrInvalidRCRC16
	}

	return size, nil
}
