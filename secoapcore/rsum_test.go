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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRSUM8(t *testing.T) {
	type args struct {
		value []byte
	}
	tests := []struct {
		name string
		args args
		want byte
	}{
		{
			name: "0",
			args: args{[]byte{0x00, 0x01, 0x02}},
			want: 0xFA,
		},
		{
			name: "256",
			args: args{[]byte{0x00, 0x01, 0x02, 0x03}},
			want: 0xF6,
		},
		{
			name: "16384",
			args: args{[]byte{0x00, 0x01, 0x02, 0x03, 0x04}},
			want: 0xF1,
		},
		{
			name: "5000000",
			args: args{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}},
			want: 0xEB,
		},
		{
			name: "20000000",
			args: args{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}},
			want: 0xE4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RSUM8(tt.args.value)
			require.Equal(t, tt.want, got)
		})
	}
}
