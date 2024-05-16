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
)

var (
	ErrTooSmall               = errors.New("too small bytes buffer")
	ErrShortRead              = errors.New("invalid short read")
	ErrInvalidOptionHeaderExt = errors.New("invalid option header ext")
	ErrInvalidTokenLen        = errors.New("invalid token length")
	ErrInvalidValueLength     = errors.New("invalid value length")
	ErrInvalidEncoding        = errors.New("invalid encoding")

	ErrOptionTruncated              = errors.New("option truncated")
	ErrOptionUnexpectedExtendMarker = errors.New("option unexpected extend marker")
	ErrOptionsTooSmall              = errors.New("too small options buffer")
	ErrOptionTooLong                = errors.New("option is too long")
	ErrOptionGapTooLarge            = errors.New("option gap too large")
	ErrOptionNotFound               = errors.New("option not found")
	ErrOptionDuplicate              = errors.New("duplicated option")

	ErrMessageNil            = errors.New("message is nil")
	ErrMessageTruncated      = errors.New("message is truncated")
	ErrMessageInvalidVersion = errors.New("message has invalid version")
	ErrMessageInvalidRSUM8   = errors.New("message has invalid rsum8")
	ErrInvalidRCRC16         = errors.New("message has invalid crc16")
)
