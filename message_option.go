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

package secoap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// OptionID identifies an option in a message.
type OptionID uint32

/*
   +-----+----+---+---+---+----------------+--------+--------+---------+
   | No. | C  | U | N | R | Name           | Format | Length | Default |
   +-----+----+---+---+---+----------------+--------+--------+---------+
   |   1 | x  |   |   | x | If-Match       | opaque | 0-8    | (none)  |
   |   3 | x  | x | - |   | Uri-Host       | string | 1-255  | (see    |
   |     |    |   |   |   |                |        |        | below)  |
   |   4 |    |   |   | x | ETag           | opaque | 1-8    | (none)  |
   |   5 | x  |   |   |   | If-None-Match  | empty  | 0      | (none)  |
   |   7 | x  | x | - |   | Uri-Port       | uint   | 0-2    | (see    |
   |     |    |   |   |   |                |        |        | below)  |
   |   8 |    |   |   | x | Location-Path  | string | 0-255  | (none)  |
   |  11 | x  | x | - | x | Uri-Path       | string | 0-255  | (none)  |
   |  12 |    |   |   |   | Content-Format | uint   | 0-2    | (none)  |
   |  14 |    | x | - |   | Max-Age        | uint   | 0-4    | 60      |
   |  15 | x  | x | - | x | Uri-Query      | string | 0-255  | (none)  |
   |  17 | x  |   |   |   | Accept         | uint   | 0-2    | (none)  |
   |  20 |    |   |   | x | Location-Query | string | 0-255  | (none)  |
   |  23 | x  | x | - | - | Block2         | uint   | 0-3    | (none)  |
   |  27 | x  | x | - | - | Block1         | uint   | 0-3    | (none)  |
   |  28 |    |   | x |   | Size2          | uint   | 0-4    | (none)  |
   |  35 | x  | x | - |   | Proxy-Uri      | string | 1-1034 | (none)  |
   |  39 | x  | x | - |   | Proxy-Scheme   | string | 1-255  | (none)  |
   |  60 |    |   | x |   | Size1          | uint   | 0-4    | (none)  |
   +-----+----+---+---+---+----------------+--------+--------+---------+
   C=Critical, U=Unsafe, N=NoCacheKey, R=Repeatable
*/

// Option IDs.
const (
	IfMatch       OptionID = 1
	URIHost       OptionID = 3
	ETag          OptionID = 4
	IfNoneMatch   OptionID = 5
	Observe       OptionID = 6
	URIPort       OptionID = 7
	LocationPath  OptionID = 8
	URIPath       OptionID = 11
	ContentFormat OptionID = 12
	MaxAge        OptionID = 14
	URIQuery      OptionID = 15
	Accept        OptionID = 17
	LocationQuery OptionID = 20
	Block2        OptionID = 23
	Block1        OptionID = 27
	Size2         OptionID = 28
	ProxyURI      OptionID = 35
	ProxyScheme   OptionID = 39
	Size1         OptionID = 60
	NoResponse    OptionID = 258

	// The IANA policy for future additions to this sub-registry is split
	// into three tiers as follows.  The range of 0..255 is reserved for
	// options defined by the IETF (IETF Review or IESG Approval).  The
	// range of 256..2047 is reserved for commonly used options with public
	// specifications (Specification Required).  The range of 2048..64999 is
	// for all other options including private or vendor-specific ones,
	// which undergo a Designated Expert review to help ensure that the
	// option semantics are defined correctly.  The option numbers between
	// 65000 and 65535 inclusive are reserved for experiments.  They are not
	// meant for vendor-specific use of any kind and MUST NOT be used in
	// operational deployments.
	GiterLabID    OptionID = 65000
	GiterLabKey   OptionID = 65001
	AccessID      OptionID = 65002
	AccessKey     OptionID = 65003
	CheckCRC32    OptionID = 65004
	EncoderType   OptionID = 65005
	EncoderID     OptionID = 65006
	PackageNumber OptionID = 65100
)

var optionIDToString = map[OptionID]string{
	IfMatch:       "IfMatch",
	URIHost:       "URIHost",
	ETag:          "ETag",
	IfNoneMatch:   "IfNoneMatch",
	Observe:       "Observe",
	URIPort:       "URIPort",
	LocationPath:  "LocationPath",
	URIPath:       "URIPath",
	ContentFormat: "ContentFormat",
	MaxAge:        "MaxAge",
	URIQuery:      "URIQuery",
	Accept:        "Accept",
	LocationQuery: "LocationQuery",
	Block2:        "Block2",
	Block1:        "Block1",
	Size2:         "Size2",
	ProxyURI:      "ProxyURI",
	ProxyScheme:   "ProxyScheme",
	Size1:         "Size1",
	NoResponse:    "NoResponse",

	// GiterLab: add private options
	GiterLabID:    "GiterLabID",
	GiterLabKey:   "GiterLabKey",
	AccessID:      "AccessID",
	AccessKey:     "AccessKey",
	CheckCRC32:    "CheckCRC32",
	EncoderType:   "EncoderType",
	EncoderID:     "EncoderID",
	PackageNumber: "PackageNumber",
}

func (o OptionID) String() string {
	str, ok := optionIDToString[o]
	if !ok {
		return "Option(" + strconv.FormatInt(int64(o), 10) + ")"
	}
	return str
}

func ToOptionID(v string) (OptionID, error) {
	for key, val := range optionIDToString {
		if val == v {
			return key, nil
		}
	}
	return 0, errors.New("not found")
}

// Option value format (RFC7252 section 3.2)
type ValueFormat uint8

const (
	ValueUnknown ValueFormat = iota
	ValueEmpty
	ValueOpaque
	ValueUint
	ValueString
)

type OptionDef struct {
	MinLen      int
	MaxLen      int
	ValueFormat ValueFormat
}

var CoapOptionDefs = map[OptionID]OptionDef{
	IfMatch:       {ValueFormat: ValueOpaque, MinLen: 0, MaxLen: 8},
	URIHost:       {ValueFormat: ValueString, MinLen: 1, MaxLen: 255},
	ETag:          {ValueFormat: ValueOpaque, MinLen: 1, MaxLen: 8},
	IfNoneMatch:   {ValueFormat: ValueEmpty, MinLen: 0, MaxLen: 0},
	Observe:       {ValueFormat: ValueUint, MinLen: 0, MaxLen: 3},
	URIPort:       {ValueFormat: ValueUint, MinLen: 0, MaxLen: 2},
	LocationPath:  {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	URIPath:       {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	ContentFormat: {ValueFormat: ValueUint, MinLen: 0, MaxLen: 2},
	MaxAge:        {ValueFormat: ValueUint, MinLen: 0, MaxLen: 4},
	URIQuery:      {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	Accept:        {ValueFormat: ValueUint, MinLen: 0, MaxLen: 2},
	LocationQuery: {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	Block2:        {ValueFormat: ValueUint, MinLen: 0, MaxLen: 3},
	Block1:        {ValueFormat: ValueUint, MinLen: 0, MaxLen: 3},
	Size2:         {ValueFormat: ValueUint, MinLen: 0, MaxLen: 4},
	ProxyURI:      {ValueFormat: ValueString, MinLen: 1, MaxLen: 1034},
	ProxyScheme:   {ValueFormat: ValueString, MinLen: 1, MaxLen: 255},
	Size1:         {ValueFormat: ValueUint, MinLen: 0, MaxLen: 4},

	// GiterLab: add private options
	GiterLabID:    {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	GiterLabKey:   {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	AccessID:      {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	AccessKey:     {ValueFormat: ValueString, MinLen: 0, MaxLen: 255},
	CheckCRC32:    {ValueFormat: ValueUint, MinLen: 0, MaxLen: 4},
	EncoderType:   {ValueFormat: ValueUint, MinLen: 0, MaxLen: 4},
	EncoderID:     {ValueFormat: ValueUint, MinLen: 0, MaxLen: 4},
	PackageNumber: {ValueFormat: ValueUint, MinLen: 0, MaxLen: 2},
}

// VerifyOptLen checks whether valueLen is within (min, max) length limits for given option.
func VerifyOptLen(optionDefs map[OptionID]OptionDef, optionID OptionID, valueLen int) bool {
	def := optionDefs[optionID]
	if valueLen < int(def.MinLen) || valueLen > int(def.MaxLen) {
		return false
	}
	return true
}

type Option struct {
	ID    OptionID
	Value interface{}
}

// encodeInt 把一个整数编码为一个字节序列
func encodeInt(v uint32) []byte {
	switch {
	case v == 0:
		return nil
	case v < 256:
		return []byte{byte(v)}
	case v < 65536:
		rv := []byte{0, 0}
		binary.BigEndian.PutUint16(rv, uint16(v))
		return rv
	case v < 16777216:
		rv := []byte{0, 0, 0, 0}
		binary.BigEndian.PutUint32(rv, uint32(v))
		return rv[1:]
	default:
		rv := []byte{0, 0, 0, 0}
		binary.BigEndian.PutUint32(rv, uint32(v))
		return rv
	}
}

// decodeInt 解码一个字节序列为一个整数
func decodeInt(b []byte) uint32 {
	tmp := []byte{0, 0, 0, 0}
	copy(tmp[4-len(b):], b)
	return binary.BigEndian.Uint32(tmp)
}

const (
	max1ByteNumber = uint32(^uint8(0))
	max2ByteNumber = uint32(^uint16(0))
	max3ByteNumber = uint32(0xffffff)
)

const (
	ExtendOptionByteCode   = 13
	ExtendOptionByteAddend = 13
	ExtendOptionWordCode   = 14
	ExtendOptionWordAddend = 269
	ExtendOptionError      = 15
)

// extendOpt 计算 Option Delta  与 Option Length 的扩展
func extendOpt(opt int) (int, int) {
	ext := 0
	if opt >= ExtendOptionByteAddend {
		if opt >= ExtendOptionWordAddend {
			ext = opt - ExtendOptionWordAddend
			opt = ExtendOptionWordCode
		} else {
			ext = opt - ExtendOptionByteAddend
			opt = ExtendOptionByteCode
		}
	}
	return opt, ext
}

// parseExtOpt 解析 Option Delta 与 Option Length 的扩展
func parseExtOpt(data []byte, opt int) (int, int, error) {
	processed := 0
	switch opt {
	case ExtendOptionByteCode:
		if len(data) < 1 {
			return 0, -1, ErrOptionTruncated
		}
		opt = int(data[0]) + ExtendOptionByteAddend
		processed = 1
	case ExtendOptionWordCode:
		if len(data) < 2 {
			return 0, -1, ErrOptionTruncated
		}
		opt = int(binary.BigEndian.Uint16(data[:2])) + ExtendOptionWordAddend
		processed = 2
	}
	return processed, opt, nil
}

// marshalOptionHeaderExt 根据 extendOpt(opt) 计算后的 opt, ext的结果, 将 ext 写入 buf
func marshalOptionHeaderExt(buf []byte, opt, ext int) (int, error) {
	switch opt {
	case ExtendOptionByteCode:
		if len(buf) > 0 {
			buf[0] = byte(ext)
			return 1, nil
		}
		return 1, ErrTooSmall
	case ExtendOptionWordCode:
		if len(buf) > 1 {
			binary.BigEndian.PutUint16(buf, uint16(ext))
			return 2, nil
		}
		return 2, ErrTooSmall
	}
	return 0, nil
}

// marshalOptionHeader 将 Option Delta 与 Option Length 写入 buf, 组装成 Option Header
func marshalOptionHeader(buf []byte, delta, length int) (int, error) {
	size := 0

	d, dx := extendOpt(delta)
	l, lx := extendOpt(length)

	if len(buf) > 0 {
		buf[0] = byte(d<<4) | byte(l)
		size++
	} else {
		buf = nil
		size++
	}
	var lenBuf int
	var err error
	if buf == nil {
		lenBuf, err = marshalOptionHeaderExt(nil, d, dx)
	} else {
		lenBuf, err = marshalOptionHeaderExt(buf[size:], d, dx)
	}

	switch {
	case err == nil:
	case errors.Is(err, ErrTooSmall):
		buf = nil
	default:
		return -1, err
	}
	size += lenBuf

	if buf == nil {
		lenBuf, err = marshalOptionHeaderExt(nil, l, lx)
	} else {
		lenBuf, err = marshalOptionHeaderExt(buf[size:], l, lx)
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrTooSmall):
		buf = nil
	default:
		return -1, err
	}
	size += lenBuf
	if buf == nil {
		return size, ErrTooSmall
	}
	return size, nil
}

func (o Option) ToBytes() []byte {
	var v uint32

	switch i := o.Value.(type) {
	case string:
		return []byte(i)
	case []byte:
		return i
	case MediaType:
		v = uint32(i)
	case int:
		v = uint32(i)
	case int32:
		v = uint32(i)
	case uint:
		v = uint32(i)
	case uint32:
		v = i
	default:
		panic(fmt.Errorf("invalid type for option %x: %T (%v)",
			o.ID, o.Value, o.Value))
	}

	return encodeInt(v)
}

func (o Option) MarshalValue(buf []byte) (int, error) {
	value := o.ToBytes()
	if len(buf) < len(value) {
		return len(value), ErrTooSmall
	}
	copy(buf, value)
	return len(value), nil
}

func (o *Option) UnmarshalValue(optionDefs map[OptionID]OptionDef, buf []byte) (int, error) {
	if def, ok := optionDefs[o.ID]; ok {
		valueLen := len(buf)
		if !VerifyOptLen(optionDefs, o.ID, valueLen) {
			return -1, fmt.Errorf("invalid option length %d for %s", len(buf), o.ID)
		}
		switch def.ValueFormat {
		case ValueUint:
			intValue := decodeInt(buf)
			if o.ID == ContentFormat || o.ID == Accept {
				o.Value = MediaType(intValue)
			}
			o.Value = intValue
		case ValueString:
			o.Value = string(buf)
		case ValueOpaque, ValueEmpty:
			o.Value = buf
		}
		return len(buf), nil
	}
	// Skip unrecognized options (should never be reached)
	return -1, fmt.Errorf("unrecognized option %d", o.ID)
}

// Marshal 将 Option 按照 Option Format 序列化到 buf 中, previousID 为前一个 Option 的 ID, 用于计算 Option Delta
func (o Option) Marshal(buf []byte, previousID OptionID) (int, error) {
	/*
		Option Format:

		     0   1   2   3   4   5   6   7
		   +---------------+---------------+
		   |               |               |
		   |  Option Delta | Option Length |   1 byte
		   |               |               |
		   +---------------+---------------+
		   \                               \
		   /         Option Delta          /   0-2 bytes
		   \          (extended)           \
		   +-------------------------------+
		   \                               \
		   /         Option Length         /   0-2 bytes
		   \          (extended)           \
		   +-------------------------------+
		   \                               \
		   /                               /
		   \                               \
		   /         Option Value          /   0 or more bytes
		   \                               \
		   /                               /
		   \                               \
		   +-------------------------------+
	*/
	delta := int(o.ID) - int(previousID)

	lenBuf, err := o.MarshalValue(nil)
	switch {
	case err == nil, errors.Is(err, ErrTooSmall):
	default:
		return -1, err
	}

	// header marshal
	lenBuf, err = marshalOptionHeader(buf, delta, lenBuf)
	switch {
	case err == nil:
	case errors.Is(err, ErrTooSmall):
		buf = nil
	default:
		return -1, err
	}
	length := lenBuf

	if buf == nil {
		lenBuf, err = o.MarshalValue(nil)
	} else {
		lenBuf, err = o.MarshalValue(buf[length:])
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrTooSmall):
		buf = nil
	default:
		return -1, err
	}
	length += lenBuf

	if buf == nil {
		return length, ErrTooSmall
	}
	return length, nil
}

// Unmarshal 从 data 中反序列化成 Option
func (o *Option) Unmarshal(optionDefs map[OptionID]OptionDef, optionID OptionID, data []byte) (int, error) {
	if def, ok := optionDefs[optionID]; ok {
		if def.ValueFormat == ValueUnknown {
			// Skip unrecognized options (RFC7252 section 5.4.1)
			return len(data), nil
		}
		valueLen := len(data)
		if !VerifyOptLen(optionDefs, optionID, valueLen) {
			// Skip options with illegal value length (RFC7252 section 5.4.3)
			return valueLen, nil
		}
	} else {
		return -1, fmt.Errorf("unrecognized option %d", optionID)
	}
	o.ID = optionID
	proc, err := o.UnmarshalValue(optionDefs, data)
	if err != nil {
		return -1, err
	}
	return proc, nil
}

// String 返回 Option 的字符串表示
func (o Option) String() string {
	return fmt.Sprintf("ID:%s(%d) Value:%v(% 02X)", o.ID, o.ID, o.Value, o.ToBytes())
}

func parseOptionValue(optionID OptionID, valueBuf []byte) interface{} {
	def := CoapOptionDefs[optionID]
	if def.ValueFormat == ValueUnknown {
		// Skip unrecognized options (RFC7252 section 5.4.1)
		return nil
	}
	if len(valueBuf) < def.MinLen || len(valueBuf) > def.MaxLen {
		// Skip options with illegal value length (RFC7252 section 5.4.3)
		return nil
	}
	switch def.ValueFormat {
	case ValueUint:
		intValue := decodeInt(valueBuf)
		if optionID == ContentFormat || optionID == Accept {
			return MediaType(intValue)
		}
		return intValue
	case ValueString:
		return string(valueBuf)
	case ValueOpaque, ValueEmpty:
		return valueBuf
	}
	// Skip unrecognized options (should never be reached)
	return nil
}
