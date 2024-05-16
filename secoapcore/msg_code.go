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
	"errors"
	"strconv"
)

// Code is the type used for both request and response codes.
type Code uint8

const (
	// All Code values are assigned by sub-registries according to the
	// following ranges:
	//   0.00      Indicates an Empty message (see Section 4.1).
	//   0.01-0.31 Indicates a request.  Values in this range are assigned by
	//             the "CoAP Method Codes" sub-registry (see Section 12.1.1).
	//   1.00-1.31 Reserved
	//   2.00-5.31 Indicates a response.  Values in this range are assigned by
	//             the "CoAP Response Codes" sub-registry (see
	//             Section 12.1.2).
	//   6.00-7.31 Reserved

	// Indicates an Empty message
	Empty Code = 0

	// Request Codes
	GET    Code = 1
	POST   Code = 2
	PUT    Code = 3
	DELETE Code = 4

	// Response Codes
	Created                 Code = 65
	Deleted                 Code = 66
	Valid                   Code = 67
	Changed                 Code = 68
	Content                 Code = 69
	Continue                Code = 95
	BadRequest              Code = 128
	Unauthorized            Code = 129
	BadOption               Code = 130
	Forbidden               Code = 131
	NotFound                Code = 132
	MethodNotAllowed        Code = 133
	NotAcceptable           Code = 134
	RequestEntityIncomplete Code = 136
	PreconditionFailed      Code = 140
	RequestEntityTooLarge   Code = 141
	UnsupportedMediaType    Code = 143
	TooManyRequests         Code = 157
	InternalServerError     Code = 160
	NotImplemented          Code = 161
	BadGateway              Code = 162
	ServiceUnavailable      Code = 163
	GatewayTimeout          Code = 164
	ProxyingNotSupported    Code = 165

	// 6.00-6.31 Reserved
	GiterlabErrnoOk              = 192 // 正常响应  [PV1/PV2]
	GiterlabErrnoParamConfigure  = 193 // 有新的配置参数 [PV2]
	GiterlabErrnoFirmwareUpdate  = 194 // 有新的固件可以更新 [PV2]
	GiterlabErrnoUserCommand     = 195 // 有用户命令需要执行 [PV2]
	GiterlabErrnoEnterFlightMode = 220 // 进入飞行模式[PV2]

	// 7.00-7.31 Reserved
	GiterlabErrnoIllegalKey                  = 224 //    KEY错误，设备激活码错误 [PV1/PV2]
	GiterlabErrnoDataError                   = 225 //    数据错误 [PV1/PV2]
	GiterlabErrnoDeviceNotExist              = 226 //    设备不存在或设备传感器类型匹配错误 [PV1/PV2]
	GiterlabErrnoTimeExpired                 = 227 //    时间过期 [PV1/PV2]
	GiterlabErrnoNotSupportProtocolVersion   = 228 //    不支持的协议版本 [PV1/PV2]
	GiterlabErrnoProtocolParsingErrors       = 229 //    议解析错误 [PV1/PV2]
	GiterlabErrnoRequestTimeout              = 230 // [*]请求超时 [PV1/PV2]
	GiterlabErrnoOptProtocolParsingErrors    = 231 //    可选附加头解析错误 [PV1/PV2]
	GiterlabErrnoNotSupportAnalyticalMethods = 232 //    不支持的可选附加头解析方法 [PV1/PV2]
	GiterlabErrnoNotSupportPacketType        = 233 //    不支持的包类型 [PV1/PV2]
	GiterlabErrnoDataDecodingError           = 234 //    数据解码错误 [PV1/PV2]
	GiterlabErrnoPackageLengthError          = 235 //    数据包长度字段错误 [PV1/PV2]
	GiterlabErrnoDuoxieyunServerRequestBusy  = 236 // [*]多协云服务器请求失败 [PV1过时了]
	GiterlabErrnoSluanServerRequestBusy      = 237 // [*]石峦服务器请求失败 [PV2过时了]
	GiterlabErrnoCacheServiceErrors          = 238 // [*]缓存服务出错 [PV1/PV2]
	GiterlabErrnoTableStoreServiceErrors     = 239 // [*]表格存储服务出错 [PV1/PV2]
	GiterlabErrnoDatabaseServiceErrors       = 240 // [*]数据库存储出错 [PV1/PV2]
	GiterlabErrnoNotSupportEncodingType      = 241 //    不支持的编码类型 [PV1/PV2]
	GiterlabErrnoDeviceRepeatRegistered      = 242 //    设备重复注册 [PV2]
	GiterlabErrnoDeviceSimCardUsed           = 243 //    设备手机卡重复使用 [PV2]
	GiterlabErrnoDeviceSimCardIllegal        = 244 //    设备手机卡未登记，非法的SIM卡 [PV2]
	GiterlabErrnoDeviceUpdateForcedFailed    = 245 //    强制更新设备信息失败 [PV2]
)

var codeToString = map[Code]string{
	Empty: "Empty",

	GET:    "GET",
	POST:   "POST",
	PUT:    "PUT",
	DELETE: "DELETE",

	Created:                 "Created",
	Deleted:                 "Deleted",
	Valid:                   "Valid",
	Changed:                 "Changed",
	Content:                 "Content",
	Continue:                "Continue",
	BadRequest:              "BadRequest",
	Unauthorized:            "Unauthorized",
	BadOption:               "BadOption",
	Forbidden:               "Forbidden",
	NotFound:                "NotFound",
	MethodNotAllowed:        "MethodNotAllowed",
	NotAcceptable:           "NotAcceptable",
	RequestEntityIncomplete: "RequestEntityIncomplete",
	PreconditionFailed:      "PreconditionFailed",
	RequestEntityTooLarge:   "RequestEntityTooLarge",
	UnsupportedMediaType:    "UnsupportedMediaType",
	TooManyRequests:         "TooManyRequests",
	InternalServerError:     "InternalServerError",
	NotImplemented:          "NotImplemented",
	BadGateway:              "BadGateway",
	ServiceUnavailable:      "ServiceUnavailable",
	GatewayTimeout:          "GatewayTimeout",
	ProxyingNotSupported:    "ProxyingNotSupported",

	GiterlabErrnoOk:             "giterlabErrnoOk:",
	GiterlabErrnoParamConfigure: "giterlabErrnoParamConfigure",
	GiterlabErrnoFirmwareUpdate: "giterlabErrnoFirmwareUpdate",

	GiterlabErrnoIllegalKey:                  "GiterlabErrnoIllegalKey",
	GiterlabErrnoDataError:                   "GiterlabErrnoDataError",
	GiterlabErrnoDeviceNotExist:              "GiterlabErrnoDeviceNotExist",
	GiterlabErrnoTimeExpired:                 "GiterlabErrnoTimeExpired",
	GiterlabErrnoNotSupportProtocolVersion:   "GiterlabErrnoNotSupportProtocolVersion",
	GiterlabErrnoProtocolParsingErrors:       "GiterlabErrnoProtocolParsingErrors",
	GiterlabErrnoRequestTimeout:              "GiterlabErrnoRequestTimeout",
	GiterlabErrnoOptProtocolParsingErrors:    "GiterlabErrnoOptProtocolParsingErrors",
	GiterlabErrnoNotSupportAnalyticalMethods: "GiterlabErrnoNotSupportAnalyticalMethods",
	GiterlabErrnoNotSupportPacketType:        "GiterlabErrnoNotSupportPacketType",
	GiterlabErrnoDataDecodingError:           "GiterlabErrnoDataDecodingError",
	GiterlabErrnoPackageLengthError:          "GiterlabErrnoPackageLengthError",
	GiterlabErrnoDuoxieyunServerRequestBusy:  "GiterlabErrnoDuoxieyunServerRequestBusy",
	GiterlabErrnoSluanServerRequestBusy:      "GiterlabErrnoSluanServerRequestBusy",
	GiterlabErrnoCacheServiceErrors:          "GiterlabErrnoCacheServiceErrors",
	GiterlabErrnoTableStoreServiceErrors:     "GiterlabErrnoTableStoreServiceErrors",
	GiterlabErrnoDatabaseServiceErrors:       "GiterlabErrnoDatabaseServiceErrors",
	GiterlabErrnoNotSupportEncodingType:      "GiterlabErrnoNotSupportEncodingType",
	GiterlabErrnoDeviceRepeatRegistered:      "GiterlabErrnoDeviceRepeatRegistered",
	GiterlabErrnoDeviceSimCardUsed:           "GiterlabErrnoDeviceSimCardUsed",
	GiterlabErrnoDeviceSimCardIllegal:        "GiterlabErrnoDeviceSimCardIllegal",
	GiterlabErrnoDeviceUpdateForcedFailed:    "GiterlabErrnoDeviceUpdateForcedFailed",
}

func (c Code) String() string {
	str, ok := codeToString[c]
	if !ok {
		return "Code(" + strconv.FormatInt(int64(c), 10) + ")"
	}
	return str
}

func ToCode(v string) (Code, error) {
	for key, val := range codeToString {
		if val == v {
			return key, nil
		}
	}
	return 0, errors.New("not found")
}
