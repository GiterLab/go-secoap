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
	"context"

	"github.com/GiterLab/go-secoap/coder/coderv0"
	"github.com/GiterLab/go-secoap/coder/coderv1"
	"github.com/GiterLab/go-secoap/coder/coderv2"
	"github.com/GiterLab/go-secoap/message"
	"github.com/GiterLab/go-secoap/secoapcore"
)

const (
	Version0 secoapcore.Ver = 0 // Version0 版本0，私有SECOAP协议
	Version1 secoapcore.Ver = 1 // Version1 版本1，标准COAP协议
	Version2 secoapcore.Ver = 2 // Version2 版本2，私有SECOAP协议, 默认使用此协议
)

// Secoap Secoap协议实例
type Secoap struct {
	Version secoapcore.Ver
	Message *message.Message

	ctx *context.Context
}

// NewSecoap 创建一个Secoap协议实例
func NewSecoap(ver secoapcore.Ver) *Secoap {
	if ver > 2 {
		ver = Version2
	}
	ctx := context.Background()
	return &Secoap{
		Version: ver,
		Message: message.NewMessage(ctx),
		ctx:     &ctx,
	}
}

func (s *Secoap) SetContext(ctx context.Context) {
	s.ctx = &ctx
}

func (s *Secoap) GetContext() context.Context {
	return *s.ctx
}

func (s *Secoap) SetVersion(ver secoapcore.Ver) {
	s.Version = ver
}

func (s *Secoap) GetVersion() secoapcore.Ver {
	return s.Version
}

func (s *Secoap) SetMessage(msg *message.Message) {
	s.Message = msg
}

func (s *Secoap) GetMessage() *message.Message {
	return s.Message
}

func (s *Secoap) Marshal() ([]byte, error) {
	var encoder message.Encoder

	if s.Message == nil {
		return nil, secoapcore.ErrMessageNil
	}
	switch s.Version {
	case Version0:
		encoder = coderv0.DefaultCoder
	case Version1:
		encoder = coderv1.DefaultCoder
	case Version2:
		encoder = coderv2.DefaultCoder
	default:
		return nil, secoapcore.ErrMessageInvalidVersion
	}

	return s.Message.MarshalWithEncoder(encoder)
}

func (s *Secoap) Unmarshal(data []byte) (int, error) {
	var decoder message.Decoder

	if s.Message == nil {
		return 0, secoapcore.ErrMessageNil
	}
	switch s.Version {
	case Version0:
		decoder = coderv0.DefaultCoder
	case Version1:
		decoder = coderv1.DefaultCoder
	case Version2:
		decoder = coderv2.DefaultCoder
	default:
		return 0, secoapcore.ErrMessageInvalidVersion
	}

	return s.Message.UnmarshalWithDecoder(decoder, data)
}
