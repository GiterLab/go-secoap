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
	"errors"
	"strconv"
)

// MediaType specifies the content type of a message.
type MediaType uint16

// Content types.
const (
	TextPlain         MediaType = 0     // text/plain; charset=utf-8
	AppCoseEncrypt0   MediaType = 16    // application/cose; cose-type="cose-encrypt0" (RFC 8152)
	AppCoseMac0       MediaType = 17    // application/cose; cose-type="cose-mac0" (RFC 8152)
	AppCoseSign1      MediaType = 18    // application/cose; cose-type="cose-sign1" (RFC 8152)
	AppLinkFormat     MediaType = 40    // application/link-format
	AppXML            MediaType = 41    // application/xml
	AppOctets         MediaType = 42    // application/octet-stream
	AppExi            MediaType = 47    // application/exi
	AppJSON           MediaType = 50    // application/json
	AppJSONPatch      MediaType = 51    // application/json-patch+json (RFC6902)
	AppJSONMergePatch MediaType = 52    // application/merge-patch+json (RFC7396)
	AppCBOR           MediaType = 60    // application/cbor (RFC 7049)
	AppCWT            MediaType = 61    // application/cwt
	AppCoseEncrypt    MediaType = 96    // application/cose; cose-type="cose-encrypt" (RFC 8152)
	AppCoseMac        MediaType = 97    // application/cose; cose-type="cose-mac" (RFC 8152)
	AppCoseSign       MediaType = 98    // application/cose; cose-type="cose-sign" (RFC 8152)
	AppCoseKey        MediaType = 101   // application/cose-key (RFC 8152)
	AppCoseKeySet     MediaType = 102   // application/cose-key-set (RFC 8152)
	AppSenmlJSON      MediaType = 110   // application/senml+json
	AppSenmlCbor      MediaType = 112   // application/senml+cbor
	AppCoapGroup      MediaType = 256   // coap-group+json (RFC 7390)
	AppSenmlEtchJSON  MediaType = 320   // application/senml-etch+json
	AppSenmlEtchCbor  MediaType = 322   // application/senml-etch+cbor
	AppOcfCbor        MediaType = 10000 // application/vnd.ocf+cbor
	AppLwm2mTLV       MediaType = 11542 // application/vnd.oma.lwm2m+tlv
	AppLwm2mJSON      MediaType = 11543 // application/vnd.oma.lwm2m+json
	AppLwm2mCbor      MediaType = 11544 // application/vnd.oma.lwm2m+cbor
)

var mediaTypeToString = map[MediaType]string{
	TextPlain:         "text/plain; charset=utf-8",
	AppCoseEncrypt0:   "application/cose; cose-type=\"cose-encrypt0\"",
	AppCoseMac0:       "application/cose; cose-type=\"cose-mac0\"",
	AppCoseSign1:      "application/cose; cose-type=\"cose-sign1\"",
	AppLinkFormat:     "application/link-format",
	AppXML:            "application/xml",
	AppOctets:         "application/octet-stream",
	AppExi:            "application/exi",
	AppJSON:           "application/json",
	AppJSONPatch:      "application/json-patch+json",
	AppJSONMergePatch: "application/merge-patch+json",
	AppCBOR:           "application/cbor",
	AppCWT:            "application/cwt",
	AppCoseEncrypt:    "application/cose; cose-type=\"cose-encrypt\"",
	AppCoseMac:        "application/cose; cose-type=\"cose-mac\"",
	AppCoseSign:       "application/cose; cose-type=\"cose-sign\"",
	AppCoseKey:        "application/cose-key",
	AppCoseKeySet:     "application/cose-key-set",
	AppSenmlJSON:      "application/senml+json",
	AppSenmlCbor:      "application/senml+cbor",
	AppCoapGroup:      "coap-group+json",
	AppSenmlEtchJSON:  "application/senml-etch+json",
	AppSenmlEtchCbor:  "application/senml-etch+cbor",
	AppOcfCbor:        "application/vnd.ocf+cbor",
	AppLwm2mTLV:       "application/vnd.oma.lwm2m+tlv",
	AppLwm2mJSON:      "application/vnd.oma.lwm2m+json",
	AppLwm2mCbor:      "application/vnd.oma.lwm2m+cbor",
}

func (c MediaType) String() string {
	str, ok := mediaTypeToString[c]
	if !ok {
		return "MediaType(" + strconv.FormatInt(int64(c), 10) + ")"
	}
	return str
}

func ToMediaType(v string) (MediaType, error) {
	for key, val := range mediaTypeToString {
		if val == v {
			return key, nil
		}
	}
	return 0, errors.New("not found")
}
