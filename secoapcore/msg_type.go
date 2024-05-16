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
	"math"
	"strconv"
)

// Type represents the message type.
// It's only part of Secoap UDP messages.
// Reliable transports like TCP do not have a type.
type Type int16

const (
	// Used for unset
	Unset Type = -1
	// Confirmable messages require acknowledgements.
	Confirmable Type = 0
	// NonConfirmable messages do not require acknowledgements.
	NonConfirmable Type = 1
	// Acknowledgement is a message indicating a response to confirmable message.
	Acknowledgement Type = 2
	// Reset indicates a permanent negative acknowledgement.
	Reset Type = 3
)

var typeToString = map[Type]string{
	Unset:           "Unset",
	Confirmable:     "Confirmable",
	NonConfirmable:  "NonConfirmable",
	Acknowledgement: "Acknowledgement",
	Reset:           "Reset",
}

func (c Type) String() string {
	str, ok := typeToString[c]
	if !ok {
		return "Type(" + strconv.FormatInt(int64(c), 10) + ")"
	}
	return str
}

func ToType(v string) (Type, error) {
	for key, val := range typeToString {
		if val == v {
			return key, nil
		}
	}
	return 0, errors.New("not found")
}

// ValidateType validates the type for UDP. (0 <= typ <= 255)
func ValidateType(typ Type) bool {
	return typ >= 0 && typ <= math.MaxUint8
}
