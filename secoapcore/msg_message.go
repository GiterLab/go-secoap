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
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
)

// MaxTokenSize maximum of token size that can be used in message
const MaxTokenSize = 8

// Message is a Secoap message.
type Message struct {
	Ver     Ver
	Token   Token
	Opts    Options
	Code    Code
	Payload []byte

	// For DTLS and UDP messages
	MessageID int32 // uint16 is valid, all other values are invalid, -1 is used for unset
	Type      Type  // uint8 is valid, all other values are invalid, -1 is used for unset

	// Additional fields
	EncoderID   int32 // 4 bits is valid, all other values are invalid, -1 is used for unset
	EncoderType int32 // 4 bits is valid, all other values are invalid, -1 is used for unset

	// Checksum
	Crc16 uint16
	Rsum8 uint8
}

// IsConfirmable returns true if this message is confirmable.
func (m Message) IsConfirmable() bool {
	return m.Type == Confirmable
}

// Options gets all the values for the given option.
func (m Message) Options(o OptionID) []interface{} {
	var rv []interface{}

	for _, v := range m.Opts {
		if o == v.ID {
			rv = append(rv, v.Value)
		}
	}

	return rv
}

// Option gets the first value for the given option ID.
func (m Message) Option(o OptionID) interface{} {
	for _, v := range m.Opts {
		if o == v.ID {
			return v.Value
		}
	}
	return nil
}

func (m Message) optionStrings(o OptionID) []string {
	var rv []string
	for _, o := range m.Options(o) {
		rv = append(rv, o.(string))
	}
	return rv
}

// Path gets the Path set on this message if any.
func (m Message) Path() []string {
	return m.optionStrings(URIPath)
}

// PathString gets a path as a / separated string.
func (m Message) PathString() string {
	return strings.Join(m.Path(), "/")
}

// SetPathString sets a path by a / separated string.
func (m *Message) SetPathString(s string) {
	for s[0] == '/' {
		s = s[1:]
	}
	m.SetPath(strings.Split(s, "/"))
}

// SetPath updates or adds a URIPath attribute on this message.
func (m *Message) SetPath(s []string) {
	m.SetOption(URIPath, s)
}

// RemoveOption removes all references to an option
func (m *Message) RemoveOption(opID OptionID) {
	m.Opts = m.Opts.Minus(opID)
}

// AddOption adds an option.
func (m *Message) AddOption(opID OptionID, val interface{}) {
	iv := reflect.ValueOf(val)
	if (iv.Kind() == reflect.Slice || iv.Kind() == reflect.Array) &&
		iv.Type().Elem().Kind() == reflect.String {
		for i := 0; i < iv.Len(); i++ {
			m.Opts = append(m.Opts, Option{opID, iv.Index(i).Interface()})
		}
		return
	}
	m.Opts = append(m.Opts, Option{opID, val})
}

// SetOption sets an option, discarding any previous value
func (m *Message) SetOption(opID OptionID, val interface{}) {
	m.RemoveOption(opID)
	m.AddOption(opID, val)
}

func (m *Message) String() string {
	if m == nil {
		return "nil"
	}
	buf := fmt.Sprintf("Ver: %v, Code: %v, Token: %v", m.Ver, m.Code, m.Token)
	path, err := m.Opts.Path()
	if err == nil {
		buf = fmt.Sprintf("%s, Path: %v", buf, path)
	}
	cf, err := m.Opts.ContentFormat()
	if err == nil {
		buf = fmt.Sprintf("%s, ContentFormat: %v", buf, cf)
	}
	queries, err := m.Opts.Queries()
	if err == nil {
		buf = fmt.Sprintf("%s, Queries: %+v", buf, queries)
	}
	if ValidateType(m.Type) {
		buf = fmt.Sprintf("%s, Type: %v", buf, m.Type)
	}
	if ValidateMID(m.MessageID) {
		buf = fmt.Sprintf("%s, MessageID: %v", buf, m.MessageID)
	}
	if ValidateEID(m.EncoderID) {
		buf = fmt.Sprintf("%s, EncoderID: %v", buf, m.EncoderID)
	}
	if ValidateETP(m.EncoderType) {
		buf = fmt.Sprintf("%s, EncoderType: %v", buf, m.EncoderType)
	}
	if len(m.Payload) > 0 {
		buf = fmt.Sprintf("%s, PayloadLen: %v", buf, len(m.Payload))
	}
	return buf
}

// Anlayse 协议分析
func (m *Message) Analyse() string {
	var out string

	if m == nil {
		return "nil"
	}

	bf := func(num int, bits int) string {
		layout := fmt.Sprintf("%%0%db", bits)

		binaryStr := fmt.Sprintf(layout, num)
		// 使用bit位计数来插入空格
		spacedBinaryStr := ""
		for _, char := range binaryStr {
			spacedBinaryStr += string(char) + " "
		}
		// 移除末尾的空格
		spacedBinaryStr = spacedBinaryStr[:len(spacedBinaryStr)-1]
		return spacedBinaryStr
	}

	nilf := func(v []byte) interface{} {
		if len(v) == 0 {
			return "Empty"
		}
		return fmt.Sprintf("% 02X", v)
	}

	switch m.Ver {
	case Version0:
		tmpbufCRC16 := []byte{0, 0}
		binary.BigEndian.PutUint16(tmpbufCRC16, m.Crc16)
		crc16 := binary.LittleEndian.Uint16(tmpbufCRC16)

		out = fmt.Sprintf(`
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V %d|R|R|R|R|T %d|EID: %d |ETP: %d |CRC16: 0x%04X                  |
   |%v|0 0 0 0|%v|%v|%v|%v|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Payload: HEX(%d)
   | %v`,
			m.Ver, m.Type, m.EncoderID, m.EncoderType, m.Crc16,
			bf(int(m.Ver), 2),
			bf(int(m.Type), 2),
			bf(int(m.EncoderID), 4),
			bf(int(m.EncoderType), 4),
			bf(int(crc16), 16),
			len(m.Payload),
			nilf(m.Payload))

	case Version1:
		out = fmt.Sprintf(`
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V %d|T %d|TKL: %d |Code: %3d      |Message ID: 0x%04X             |
   |%v|%v|%v|%v|%v|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Token: (if any) ... HEX(%d)
   | %v
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Options (if any) ... HEX
   | Path: %v
   |
   | %v
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |SEP: 0xFF      |Payload: HEX(%d)
   |%v| %v`,
			m.Ver, m.Type, len(m.Token), m.Code, m.MessageID,
			bf(int(m.Ver), 2),
			bf(int(m.Type), 2),
			bf(int(len(m.Token)), 4),
			bf(int(m.Code), 8),
			bf(int(m.MessageID), 16),
			len(m.Token),
			nilf(m.Token),
			m.Opts.URL(),
			m.Opts.String("\n   | "),
			len(m.Payload),
			bf(int(0xFF), 8),
			nilf(m.Payload))

	case Version2:
		out = fmt.Sprintf(`
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V %d|TKL: %d |T %d|EID: %d |ETP: %d |CRC16: 0x%04X                  |
   |%v|%v|%v|%v|%v|%v|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Message ID: 0x%04X             |Code: %3d      |RSUM8: 0x%02X    |
   |%v|%v|%v|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Token: (if any) ... HEX(%d)
   | %v
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Options (if any) ... HEX
   | Path: %v
   |
   | %v
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |SEP: 0xFF      |Payload: HEX(%d)
   |%v| %v`,
			m.Ver, len(m.Token), m.Type, m.EncoderID, m.EncoderType, m.Crc16,
			bf(int(m.Ver), 2),
			bf(int(len(m.Token)), 4),
			bf(int(m.Type), 2),
			bf(int(m.EncoderID), 4),
			bf(int(m.EncoderType), 4),
			bf(int(m.Crc16), 16),
			m.MessageID, m.Code, m.Rsum8,
			bf(int(m.MessageID), 16),
			bf(int(m.Code), 8),
			bf(int(m.Rsum8), 8),
			len(m.Token),
			nilf(m.Token),
			m.Opts.URL(),
			m.Opts.String("\n   | "),
			len(m.Payload),
			bf(int(0xFF), 8),
			nilf(m.Payload))
	}

	return out
}
