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
	"fmt"
	"reflect"
	"strings"
)

// MaxTokenSize maximum of token size that can be used in message
const MaxTokenSize = 8

// Message is a Secoap message.
type Message struct {
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
	buf := fmt.Sprintf("Code: %v, Token: %v", m.Code, m.Token)
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
	if len(m.Payload) > 0 {
		buf = fmt.Sprintf("%s, PayloadLen: %v", buf, len(m.Payload))
	}
	return buf
}
