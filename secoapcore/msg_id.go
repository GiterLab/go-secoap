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
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync/atomic"
	"time"
)

var weakRng = NewRand(time.Now().UnixNano())

var msgID = uint32(RandMID())

// GetMID generates a message id for UDP. (0 <= mid <= 65535)
func GetMID() int32 {
	return int32(uint16(atomic.AddUint32(&msgID, 1)))
}

func RandMID() int32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		// fallback to cryptographically insecure pseudo-random generator
		return int32(uint16(weakRng.Uint32() >> 16))
	}
	return int32(uint16(binary.BigEndian.Uint32(b)))
}

// ValidateMID validates a message id for UDP. (0 <= mid <= 65535)
func ValidateMID(mid int32) bool {
	return mid >= 0 && mid <= math.MaxUint16
}
