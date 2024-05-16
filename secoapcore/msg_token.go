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
	"encoding/hex"
	"hash/crc64"
)

type Token []byte

func (t Token) String() string {
	return hex.EncodeToString(t)
}

func (t Token) Hash() uint64 {
	return crc64.Checksum(t, crc64.MakeTable(crc64.ISO))
}

// GetToken generates a random token by a given length
func GetToken() (Token, error) {
	b := make(Token, 8)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
