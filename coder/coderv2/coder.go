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

package coderv2

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/GiterLab/go-secoap/secoapcore"
)

var DefaultCoder = new(Coder)

type Coder struct{}

func (c *Coder) Size(m secoapcore.Message) (int, error) {
	if len(m.Token) > secoapcore.MaxTokenSize {
		return -1, secoapcore.ErrInvalidTokenLen
	}
	size := 8 + len(m.Token)
	payloadLen := len(m.Payload)
	optionsLen, err := m.Opts.Marshal(nil)
	if !errors.Is(err, secoapcore.ErrTooSmall) {
		return -1, err
	}
	if payloadLen > 0 {
		// for separator 0xff
		payloadLen++
	}
	size += payloadLen + optionsLen
	return size, nil
}

func (c *Coder) Encode(m secoapcore.Message, buf []byte) (int, error) {
	/*
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|1 0|  TKL  | T |  EID  |  ETP  |   CRC16                       |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|   Message ID                  |   Code        |   RSUM8       |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|   Token (if any, TKL bytes) ...
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|   Options (if any) ...
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|1 1 1 1 1 1 1 1|    Payload (if any) ...
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	if !secoapcore.ValidateMID(m.MessageID) {
		return -1, fmt.Errorf("invalid MessageID(%v)", m.MessageID)
	}
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
	binary.BigEndian.PutUint16(tmpbufCRC16, m.Crc16)

	tmpbufMessageID := []byte{0, 0}
	binary.BigEndian.PutUint16(tmpbufMessageID, uint16(m.MessageID))

	pbuf := buf
	pbuf[0] = (2 << 6) | (byte(0xf&len(m.Token)) << 2) | byte(m.Type)
	pbuf[1] = byte(m.EncoderID<<4) | byte(m.EncoderType)
	pbuf[2] = tmpbufCRC16[0]
	pbuf[3] = tmpbufCRC16[1]
	pbuf[4] = tmpbufMessageID[0]
	pbuf[5] = tmpbufMessageID[1]
	pbuf[6] = byte(m.Code)
	pbuf[7] = 0x00 // 最后再计算RSUM8
	pbuf = pbuf[8:]

	if len(m.Token) > secoapcore.MaxTokenSize {
		return -1, secoapcore.ErrInvalidTokenLen
	}
	copy(pbuf, m.Token)
	pbuf = pbuf[len(m.Token):]

	optionsLen, err := m.Opts.Marshal(pbuf)
	switch {
	case err == nil:
	case errors.Is(err, secoapcore.ErrTooSmall):
		return size, err
	default:
		return -1, err
	}
	pbuf = pbuf[optionsLen:]

	if len(m.Payload) > 0 {
		pbuf[0] = 0xff // payload separator
		pbuf = pbuf[1:]
	}
	copy(pbuf, m.Payload)

	buf[7] = secoapcore.RSUM8(buf[0:size]) // 计算RSUM8后填充

	return size, nil
}

func (c *Coder) Decode(data []byte, m *secoapcore.Message) (int, error) {
	size := len(data)
	if size < 8 {
		return -1, secoapcore.ErrMessageTruncated
	}

	if secoapcore.RSUM8(data) != 0 {
		return -1, secoapcore.ErrMessageInvalidRSUM8
	}

	if data[0]>>6 != 2 { // version 2
		return -1, secoapcore.ErrMessageInvalidVersion
	}

	typ := secoapcore.Type(data[0] & 0x3)
	tokenLen := int((data[0] >> 2) & 0xf)
	if tokenLen > 8 {
		return -1, secoapcore.ErrInvalidTokenLen
	}
	eid := int32(data[1] >> 4)
	etp := int32(data[1] & 0xf)
	crc16 := binary.BigEndian.Uint16(data[2:4])
	messageID := binary.BigEndian.Uint16(data[4:6])
	code := secoapcore.Code(data[6])
	data = data[8:]
	if len(data) < tokenLen {
		return -1, secoapcore.ErrMessageTruncated
	}
	token := data[:tokenLen]
	if len(token) == 0 {
		token = nil
	}
	data = data[tokenLen:]

	optionDefs := secoapcore.CoapOptionDefs
	proc, err := m.Opts.Unmarshal(data, optionDefs)
	if err != nil {
		return -1, err
	}
	data = data[proc:]
	if len(data) == 0 {
		data = nil
	}

	m.Ver = secoapcore.Version2
	m.Token = token
	m.Code = code
	m.Payload = data

	m.MessageID = int32(messageID)
	m.Type = typ
	m.EncoderID = eid
	m.EncoderType = etp

	m.Crc16 = crc16

	if m.Crc16 != secoapcore.CRC16Bytes(m.Payload) {
		return -1, secoapcore.ErrInvalidRCRC16
	}

	return size, nil
}
