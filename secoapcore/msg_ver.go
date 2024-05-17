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

// Ver represents the message ver.
// It's only part of Secoap UDP messages.
type Ver int8

const (
	// Version0
	Version0 Ver = 0
	// Version1
	Version1 Ver = 1
	// Version2
	Version2 Ver = 2
)

var verToString = map[Ver]string{
	Version0: "Ver0",
	Version1: "Ver1",
	Version2: "Ver2",
}

func (c Ver) String() string {
	str, ok := verToString[c]
	if !ok {
		return "Ver(" + strconv.FormatInt(int64(c), 10) + ")"
	}
	return str
}

func ToVer(v string) (Ver, error) {
	for key, val := range verToString {
		if val == v {
			return key, nil
		}
	}
	return 0, errors.New("not found")
}

// ValidateVer validates the ver for UDP. (0 <= typ <= 3)
func ValidateVer(typ Ver) bool {
	return typ >= 0 && typ <= (1<<2-1)
}

// GetVersion gets the version from the payload.
func GetVersion(payload []byte) (ver Ver, err error) {
	if len(payload) == 0 {
		return 0, errors.New("empty payload")
	}
	ver = Ver(payload[0] >> 6)
	return ver, nil
}
