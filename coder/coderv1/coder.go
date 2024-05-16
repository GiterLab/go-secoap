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

package coderv1

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
	size := 4 + len(m.Token)
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
		|0 1| T |  TKL  |      Code     |          Message ID           |
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
	size, err := c.Size(m)
	if err != nil {
		return -1, err
	}
	if len(buf) < size {
		return size, secoapcore.ErrTooSmall
	}

	tmpbufMessageID := []byte{0, 0}
	binary.BigEndian.PutUint16(tmpbufMessageID, uint16(m.MessageID))

	buf[0] = (1 << 6) | byte(m.Type)<<4 | byte(0xf&len(m.Token))
	buf[1] = byte(m.Code)
	buf[2] = tmpbufMessageID[0]
	buf[3] = tmpbufMessageID[1]
	buf = buf[4:]

	if len(m.Token) > secoapcore.MaxTokenSize {
		return -1, secoapcore.ErrInvalidTokenLen
	}
	copy(buf, m.Token)
	buf = buf[len(m.Token):]

	optionsLen, err := m.Opts.Marshal(buf)
	switch {
	case err == nil:
	case errors.Is(err, secoapcore.ErrTooSmall):
		return size, err
	default:
		return -1, err
	}
	buf = buf[optionsLen:]

	if len(m.Payload) > 0 {
		buf[0] = 0xff // payload separator
		buf = buf[1:]
	}
	copy(buf, m.Payload)
	return size, nil
}

func (c *Coder) Decode(data []byte, m *secoapcore.Message) (int, error) {
	size := len(data)
	if size < 4 {
		return -1, secoapcore.ErrMessageTruncated
	}

	if data[0]>>6 != 1 { // version 1
		return -1, secoapcore.ErrMessageInvalidVersion
	}

	typ := secoapcore.Type((data[0] >> 4) & 0x3)
	tokenLen := int(data[0] & 0xf)
	if tokenLen > 8 {
		return -1, secoapcore.ErrInvalidTokenLen
	}

	code := secoapcore.Code(data[1])
	messageID := binary.BigEndian.Uint16(data[2:4])
	data = data[4:]
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

	m.Ver = secoapcore.Version1
	m.Token = token
	m.Code = code
	m.Payload = data

	m.MessageID = int32(messageID)
	m.Type = typ

	return size, nil
}
