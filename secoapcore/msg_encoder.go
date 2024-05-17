// Copyright 2024 tobyzxj
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secoapcore

const (
	// EncoderTypeNoneUserDefine none/userdefine
	EncoderTypeNoneUserDefine = "none/userdefine"
	// EncoderTypeTextBase64 text/base64
	EncoderTypeTextBase64 = "text/base64"
	// EncoderTypeTextPlain text/plain
	EncoderTypeTextPlain = "text/plain"
	// EncoderTypeTextHex text/hex
	EncoderTypeTextHex = "text/hex"
	// EncoderTypeApplicationOctetStream application/octet-stream
	EncoderTypeApplicationOctetStream = "application/octet-stream"
	// EncoderTypeApplicationProtobuf application/protobuf
	EncoderTypeApplicationProtobuf = "application/protobuf"
	// EncoderTypeApplicationJson application/json
	EncoderTypeApplicationJson = "application/json"
)

// GetEncoderType 获取协议 Payload 编码类型, coap协议默认是 application/protobuf
func GetEncoderType(encoderType int32, encoderID int32) string {
	switch encoderType {
	case 0:
		switch encoderID {
		case 0:
			return EncoderTypeNoneUserDefine
		}
	case 1:
		switch encoderID {
		case 0:
			return EncoderTypeTextBase64
		}
	case 2:
		switch encoderID {
		case 0:
			return EncoderTypeTextPlain
		}
	case 3:
		switch encoderID {
		case 0:
			return EncoderTypeTextHex
		}
	case 4:
		switch encoderID {
		case 0:
			return EncoderTypeApplicationOctetStream
		}
	case 5:
		switch encoderID {
		case 0:
			return EncoderTypeApplicationProtobuf
		}
	case 6:
		switch encoderID {
		case 0:
			return EncoderTypeApplicationJson
		}
	}
	return EncoderTypeNoneUserDefine // 默认是 protobuf 编码 / 或者用户自定义协议
}

// GetEncoder 根据编码器，获取对应的编码类型
func GetEncoder(encoderTypeX string) (encoderType int32, encoderID int32) {
	switch encoderTypeX {
	case EncoderTypeNoneUserDefine: // none/userdefine
		encoderType = 0
		encoderID = 0
	case EncoderTypeTextBase64: // text/base64
		encoderType = 1
		encoderID = 0
	case EncoderTypeTextPlain: // text/plain
		encoderType = 2
		encoderID = 0
	case EncoderTypeTextHex: // text/hex
		encoderType = 3
		encoderID = 0
	case EncoderTypeApplicationOctetStream: // application/octet-stream
		encoderType = 4
		encoderID = 0
	case EncoderTypeApplicationProtobuf: // application/protobuf
		encoderType = 5
		encoderID = 0
	case EncoderTypeApplicationJson: // application/json
		encoderType = 6
		encoderID = 0
	default:
		encoderType = 0
		encoderID = 0
	}
	return encoderType, encoderID
}

// ValidateEID validates a message eid for Payload. (0 <= eid <= 15)
func ValidateEID(eid int32) bool {
	return eid >= 0 && eid <= (1<<4-1)
}

// ValidateETP validates a message etp for Payload. (0 <= etp <= 15)
func ValidateETP(etp int32) bool {
	return etp >= 0 && etp <= (1<<4-1)
}
