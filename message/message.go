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

package message

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/GiterLab/go-secoap/secoapcore"
	"github.com/hashicorp/go-multierror"
)

type Encoder interface {
	Size(m secoapcore.Message) (int, error)
	Encode(m secoapcore.Message, buf []byte) (int, error)
}

type Decoder interface {
	Decode(buf []byte, m *secoapcore.Message) (int, error)
}

type Message struct {
	// Context context of request.
	ctx             context.Context
	msg             secoapcore.Message
	hijacked        atomic.Bool
	isModified      bool
	valueBuffer     []byte
	origValueBuffer []byte
	body            io.ReadSeeker
	sequence        uint64

	// local vars
	bufferUnmarshal []byte
	bufferMarshal   []byte
}

const valueBufferSize = 256

func NewMessage(ctx context.Context) *Message {
	valueBuffer := make([]byte, valueBufferSize)
	return &Message{
		ctx: ctx,
		msg: secoapcore.Message{
			Opts:      make(secoapcore.Options, 0, 16),
			MessageID: -1,
			Type:      secoapcore.Unset,
		},
		valueBuffer:     valueBuffer,
		origValueBuffer: valueBuffer,
		bufferUnmarshal: make([]byte, 256),
		bufferMarshal:   make([]byte, 256),
	}
}

func (r *Message) Context() context.Context {
	return r.ctx
}

func (r *Message) SetContext(ctx context.Context) {
	r.ctx = ctx
}

func (r *Message) SetMessage(message secoapcore.Message) {
	r.Reset()
	r.msg = message
	if len(message.Payload) > 0 {
		r.body = bytes.NewReader(message.Payload)
	}
	r.isModified = true
}

func (r *Message) Version() secoapcore.Ver {
	return r.msg.Ver
}

func (r *Message) UpsertVersion(ver secoapcore.Ver) {
	if secoapcore.ValidateVer(ver) {
		return
	}
	r.SetVersion(ver)
}

// SetVersion only 0 to 2^2-1 are valid.
func (r *Message) SetVersion(ver secoapcore.Ver) {
	r.msg.Ver = ver
	r.isModified = true
}

// SetMessageID only 0 to 2^16-1 are valid.
func (r *Message) SetMessageID(mid int32) {
	r.msg.MessageID = mid
	r.isModified = true
}

// UpsertMessageID set value only when origin value is invalid. Only 0 to 2^16-1 values are valid.
func (r *Message) UpsertMessageID(mid int32) {
	if secoapcore.ValidateMID(r.msg.MessageID) {
		return
	}
	r.SetMessageID(mid)
}

// MessageID returns 0 to 2^16-1 otherwise it contains invalid value.
func (r *Message) MessageID() int32 {
	return r.msg.MessageID
}

func (r *Message) SetType(typ secoapcore.Type) {
	r.msg.Type = typ
	r.isModified = true
}

// UpsertType set value only when origin value is invalid. Only 0 to 2^8-1 values are valid.
func (r *Message) UpsertType(typ secoapcore.Type) {
	if secoapcore.ValidateType(r.msg.Type) {
		return
	}
	r.SetType(typ)
}

func (r *Message) Type() secoapcore.Type {
	return r.msg.Type
}

func (r *Message) SetEncoderID(eid int32) {
	r.msg.EncoderID = eid
	r.isModified = true
}

func (r *Message) UpsertEncoderID(eid int32) {
	if secoapcore.ValidateEID(r.msg.EncoderID) {
		return
	}
	r.SetEncoderID(eid)
}

func (r *Message) EncoderID() int32 {
	return r.msg.EncoderID
}

func (r *Message) SetEncoderType(etp int32) {
	r.msg.EncoderType = etp
	r.isModified = true
}

func (r *Message) UpsertEncoderType(etp int32) {
	if secoapcore.ValidateETP(r.msg.EncoderType) {
		return
	}
	r.SetEncoderType(etp)
}

func (r *Message) EncoderType() int32 {
	return r.msg.EncoderType
}

// Reset clear message for next reuse
func (r *Message) Reset() {
	r.msg.Token = nil
	r.msg.Code = secoapcore.Empty
	r.msg.Opts = r.msg.Opts[:0]
	r.msg.MessageID = -1
	r.msg.Type = secoapcore.Unset
	r.msg.Payload = nil
	r.valueBuffer = r.origValueBuffer
	r.body = nil
	r.isModified = false
	if cap(r.bufferMarshal) > 1024 {
		r.bufferMarshal = make([]byte, 256)
	}
	if cap(r.bufferUnmarshal) > 1024 {
		r.bufferUnmarshal = make([]byte, 256)
	}
	r.isModified = false
}

func (r *Message) Path() (string, error) {
	return r.msg.Opts.Path()
}

func (r *Message) Queries() ([]string, error) {
	return r.msg.Opts.Queries()
}

func (r *Message) Remove(opt secoapcore.OptionID) {
	r.msg.Opts = r.msg.Opts.Remove(opt)
	r.isModified = true
}

func (r *Message) Token() secoapcore.Token {
	if r.msg.Token == nil {
		return nil
	}
	token := make(secoapcore.Token, 0, 8)
	token = append(token, r.msg.Token...)
	return token
}

func (r *Message) SetToken(token secoapcore.Token) {
	if token == nil {
		r.msg.Token = nil
		return
	}
	r.msg.Token = append(r.msg.Token[:0], token...)
}

func (r *Message) ResetOptsTo(in secoapcore.Options) {
	opts, used, err := r.msg.Opts.ResetOptionsTo(r.valueBuffer, in)
	if errors.Is(err, secoapcore.ErrTooSmall) {
		r.valueBuffer = append(r.valueBuffer, make([]byte, used)...)
		opts, used, err = r.msg.Opts.ResetOptionsTo(r.valueBuffer, in)
	}
	if err != nil {
		panic(fmt.Errorf("cannot reset opts to: %w", err))
	}
	r.msg.Opts = opts
	r.valueBuffer = r.valueBuffer[used:]
	if len(in) > 0 {
		r.isModified = true
	}
}

func (r *Message) Opts() secoapcore.Options {
	return r.msg.Opts
}

// SetPath stores the given path within URI-Path opts.
//
// The value is stored by the algorithm described in RFC7252 and
// using the internal buffer. If the path is too long, but valid
// (URI-Path segments must have maximal length of 255) the internal
// buffer is expanded.
// If the path is too long, but not valid then the function returns
// ErrInvalidValueLength error.
func (r *Message) SetPath(p string) error {
	opts, used, err := r.msg.Opts.SetPath(r.valueBuffer, p)
	if errors.Is(err, secoapcore.ErrTooSmall) {
		expandBy, errSize := secoapcore.GetPathBufferSize(p)
		if errSize != nil {
			return fmt.Errorf("cannot calculate buffer size for path: %w", errSize)
		}
		r.valueBuffer = append(r.valueBuffer, make([]byte, expandBy)...)
		opts, used, err = r.msg.Opts.SetPath(r.valueBuffer, p)
	}
	if err != nil {
		return fmt.Errorf("cannot set path: %w", err)
	}
	r.msg.Opts = opts
	r.valueBuffer = r.valueBuffer[used:]
	r.isModified = true
	return nil
}

// MustSetPath calls SetPath and panics if it returns an error.
func (r *Message) MustSetPath(p string) {
	if err := r.SetPath(p); err != nil {
		panic(err)
	}
}

func (r *Message) Code() secoapcore.Code {
	return r.msg.Code
}

func (r *Message) SetCode(code secoapcore.Code) {
	r.msg.Code = code
	r.isModified = true
}

// AddETag appends value to existing ETags.
//
// Option definition:
// - format: opaque, length: 1-8, repeatable
func (r *Message) AddETag(value []byte) error {
	optionDefs := secoapcore.CoapOptionDefs
	if !secoapcore.VerifyOptLen(optionDefs, secoapcore.ETag, len(value)) {
		return secoapcore.ErrInvalidValueLength
	}
	r.AddOptionBytes(secoapcore.ETag, value)
	return nil
}

// SetETag inserts/replaces ETag option(s).
//
// After a successful call only a single ETag value will remain.
func (r *Message) SetETag(value []byte) error {
	optionDefs := secoapcore.CoapOptionDefs
	if !secoapcore.VerifyOptLen(optionDefs, secoapcore.ETag, len(value)) {
		return secoapcore.ErrInvalidValueLength
	}
	r.SetOptionBytes(secoapcore.ETag, value)
	return nil
}

// ETag returns first ETag value
func (r *Message) ETag() ([]byte, error) {
	return r.GetOptionBytes(secoapcore.ETag)
}

// ETags returns all ETag values
//
// Writes ETag values to output array, returns number of written values or error.
func (r *Message) ETags(b [][]byte) (int, error) {
	return r.GetOptionAllBytes(secoapcore.ETag, b)
}

func (r *Message) AddQuery(query string) {
	r.AddOptstring(secoapcore.URIQuery, query)
}

func (r *Message) GetOptionUint32(id secoapcore.OptionID) (uint32, error) {
	return r.msg.Opts.GetUint32(id)
}

func (r *Message) SetOptstring(opt secoapcore.OptionID, value string) {
	opts, used, err := r.msg.Opts.SetString(r.valueBuffer, opt, value)
	if errors.Is(err, secoapcore.ErrTooSmall) {
		r.valueBuffer = append(r.valueBuffer, make([]byte, used)...)
		opts, used, err = r.msg.Opts.SetString(r.valueBuffer, opt, value)
	}
	if err != nil {
		panic(fmt.Errorf("cannot set string option: %w", err))
	}
	r.msg.Opts = opts
	r.valueBuffer = r.valueBuffer[used:]
	r.isModified = true
}

func (r *Message) AddOptstring(opt secoapcore.OptionID, value string) {
	opts, used, err := r.msg.Opts.AddString(r.valueBuffer, opt, value)
	if errors.Is(err, secoapcore.ErrTooSmall) {
		r.valueBuffer = append(r.valueBuffer, make([]byte, used)...)
		opts, used, err = r.msg.Opts.AddString(r.valueBuffer, opt, value)
	}
	if err != nil {
		panic(fmt.Errorf("cannot add string option: %w", err))
	}
	r.msg.Opts = opts
	r.valueBuffer = r.valueBuffer[used:]
	r.isModified = true
}

func (r *Message) AddOptionBytes(opt secoapcore.OptionID, value []byte) {
	if len(r.valueBuffer) < len(value) {
		r.valueBuffer = append(r.valueBuffer, make([]byte, len(value)-len(r.valueBuffer))...)
	}
	n := copy(r.valueBuffer, value)
	v := r.valueBuffer[:n]
	r.msg.Opts = r.msg.Opts.Add(secoapcore.Option{ID: opt, Value: v})
	r.valueBuffer = r.valueBuffer[n:]
	r.isModified = true
}

func (r *Message) SetOptionBytes(opt secoapcore.OptionID, value []byte) {
	if len(r.valueBuffer) < len(value) {
		r.valueBuffer = append(r.valueBuffer, make([]byte, len(value)-len(r.valueBuffer))...)
	}
	n := copy(r.valueBuffer, value)
	v := r.valueBuffer[:n]
	r.msg.Opts = r.msg.Opts.Set(secoapcore.Option{ID: opt, Value: v})
	r.valueBuffer = r.valueBuffer[n:]
	r.isModified = true
}

// GetOptionBytes gets bytes of the first option with given ID.
func (r *Message) GetOptionBytes(id secoapcore.OptionID) ([]byte, error) {
	return r.msg.Opts.GetBytes(id)
}

// GetOptionAllBytes gets array of bytes of all opts with given ID.
func (r *Message) GetOptionAllBytes(id secoapcore.OptionID, b [][]byte) (int, error) {
	return r.msg.Opts.GetBytess(id, b)
}

func (r *Message) SetOptionUint32(opt secoapcore.OptionID, value uint32) {
	opts, used, err := r.msg.Opts.SetUint32(r.valueBuffer, opt, value)
	if errors.Is(err, secoapcore.ErrTooSmall) {
		r.valueBuffer = append(r.valueBuffer, make([]byte, used)...)
		opts, used, err = r.msg.Opts.SetUint32(r.valueBuffer, opt, value)
	}
	if err != nil {
		panic(fmt.Errorf("cannot set uint32 option: %w", err))
	}
	r.msg.Opts = opts
	r.valueBuffer = r.valueBuffer[used:]
	r.isModified = true
}

func (r *Message) AddOptionUint32(opt secoapcore.OptionID, value uint32) {
	opts, used, err := r.msg.Opts.AddUint32(r.valueBuffer, opt, value)
	if errors.Is(err, secoapcore.ErrTooSmall) {
		r.valueBuffer = append(r.valueBuffer, make([]byte, used)...)
		opts, used, err = r.msg.Opts.AddUint32(r.valueBuffer, opt, value)
	}
	if err != nil {
		panic(fmt.Errorf("cannot add uint32 option: %w", err))
	}
	r.msg.Opts = opts
	r.valueBuffer = r.valueBuffer[used:]
	r.isModified = true
}

func (r *Message) ContentFormat() (secoapcore.MediaType, error) {
	v, err := r.GetOptionUint32(secoapcore.ContentFormat)
	return secoapcore.MediaType(v), err
}

func (r *Message) HasOption(id secoapcore.OptionID) bool {
	return r.msg.Opts.HasOption(id)
}

func (r *Message) SetContentFormat(contentFormat secoapcore.MediaType) {
	r.SetOptionUint32(secoapcore.ContentFormat, uint32(contentFormat))
}

func (r *Message) SetObserve(observe uint32) {
	r.SetOptionUint32(secoapcore.Observe, observe)
}

func (r *Message) Observe() (uint32, error) {
	return r.GetOptionUint32(secoapcore.Observe)
}

// SetAccept set's accept option.
func (r *Message) SetAccept(contentFormat secoapcore.MediaType) {
	r.SetOptionUint32(secoapcore.Accept, uint32(contentFormat))
}

// Accept get's accept option.
func (r *Message) Accept() (secoapcore.MediaType, error) {
	v, err := r.GetOptionUint32(secoapcore.Accept)
	return secoapcore.MediaType(v), err
}

func (r *Message) BodySize() (int64, error) {
	if r.body == nil {
		return 0, nil
	}
	orig, err := r.body.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	_, err = r.body.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}
	size, err := r.body.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	_, err = r.body.Seek(orig, io.SeekStart)
	if err != nil {
		return 0, err
	}
	return size, nil
}

func (r *Message) SetBody(s io.ReadSeeker) {
	r.body = s
	r.isModified = true
}

func (r *Message) Body() io.ReadSeeker {
	return r.body
}

func (r *Message) SetSequence(seq uint64) {
	r.sequence = seq
}

func (r *Message) Sequence() uint64 {
	return r.sequence
}

func (r *Message) Hijack() {
	r.hijacked.Store(true)
}

func (r *Message) IsHijacked() bool {
	return r.hijacked.Load()
}

func (r *Message) IsModified() bool {
	return r.isModified
}

func (r *Message) SetModified(b bool) {
	r.isModified = b
}

func (r *Message) String() string {
	return r.msg.String()
}

func (r *Message) Analyse() string {
	return r.msg.Analyse()
}

func (r *Message) ReadBody() ([]byte, error) {
	if r.Body() == nil {
		return nil, nil
	}
	size, err := r.BodySize()
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	_, err = r.Body().Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 1024)
	if int64(len(payload)) < size {
		payload = make([]byte, size)
	}
	n, err := io.ReadFull(r.Body(), payload)
	if (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) && int64(n) == size {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return payload[:n], nil
}

func (r *Message) toMessage() (secoapcore.Message, error) {
	payload, err := r.ReadBody()
	if err != nil {
		return secoapcore.Message{}, err
	}
	m := r.msg
	m.Payload = payload
	return m, nil
}

func (r *Message) ToSecoapCoreMessage() (secoapcore.Message, error) {
	payload, err := r.ReadBody()
	if err != nil {
		return secoapcore.Message{}, err
	}
	m := r.msg
	m.Payload = payload
	return m, nil
}

func (r *Message) MarshalWithEncoder(encoder Encoder) ([]byte, error) {
	msg, err := r.toMessage()
	if err != nil {
		return nil, err
	}
	size, err := encoder.Size(msg)
	if err != nil {
		return nil, err
	}
	if len(r.bufferMarshal) < size {
		r.bufferMarshal = append(r.bufferMarshal, make([]byte, size-len(r.bufferMarshal))...)
	}
	n, err := encoder.Encode(msg, r.bufferMarshal)
	if err != nil {
		return nil, err
	}
	r.bufferMarshal = r.bufferMarshal[:n]
	return r.bufferMarshal, nil
}

func (r *Message) decode(decoder Decoder) (int, error) {
	var n int
	var err error
	for {
		n, err = decoder.Decode(r.bufferUnmarshal, &r.msg)
		if errors.Is(err, secoapcore.ErrOptionsTooSmall) {
			// increase buffer size and try again
			r.msg.Opts = make(secoapcore.Options, 0, len(r.msg.Opts)*2)
			continue
		}
		return n, err
	}
}

func (r *Message) UnmarshalWithDecoder(decoder Decoder, data []byte) (int, error) {
	if len(r.bufferUnmarshal) < len(data) {
		r.bufferUnmarshal = append(r.bufferUnmarshal, make([]byte, len(data)-len(r.bufferUnmarshal))...)
	}
	copy(r.bufferUnmarshal, data)
	r.body = nil
	r.bufferUnmarshal = r.bufferUnmarshal[:len(data)]
	n, err := r.decode(decoder)
	if err != nil {
		return n, err
	}
	if len(r.msg.Payload) > 0 {
		r.body = bytes.NewReader(r.msg.Payload)
	}
	return n, err
}

func (r *Message) IsSeparateMessage() bool {
	return r.Code() == secoapcore.Empty && r.Token() == nil && r.Type() == secoapcore.Acknowledgement && len(r.Opts()) == 0 && r.Body() == nil
}

func (r *Message) setupCommon(code secoapcore.Code, path string, token secoapcore.Token, opts ...secoapcore.Option) error {
	r.SetCode(code)
	r.SetToken(token)
	r.ResetOptsTo(opts)
	return r.SetPath(path)
}

func (r *Message) SetupGet(path string, token secoapcore.Token, opts ...secoapcore.Option) error {
	return r.setupCommon(secoapcore.GET, path, token, opts...)
}

func (r *Message) SetupPost(path string, token secoapcore.Token, contentFormat secoapcore.MediaType, payload io.ReadSeeker, opts ...secoapcore.Option) error {
	if err := r.setupCommon(secoapcore.POST, path, token, opts...); err != nil {
		return err
	}
	if payload != nil {
		r.SetContentFormat(contentFormat)
		r.SetBody(payload)
	}
	return nil
}

func (r *Message) SetupPut(path string, token secoapcore.Token, contentFormat secoapcore.MediaType, payload io.ReadSeeker, opts ...secoapcore.Option) error {
	if err := r.setupCommon(secoapcore.PUT, path, token, opts...); err != nil {
		return err
	}
	if payload != nil {
		r.SetContentFormat(contentFormat)
		r.SetBody(payload)
	}
	return nil
}

func (r *Message) SetupDelete(path string, token secoapcore.Token, opts ...secoapcore.Option) error {
	return r.setupCommon(secoapcore.DELETE, path, token, opts...)
}

func (r *Message) Clone(msg *Message) error {
	msg.SetCode(r.Code())
	msg.SetToken(r.Token())
	msg.ResetOptsTo(r.Opts())
	msg.SetType(r.Type())
	msg.SetMessageID(r.MessageID())

	if r.Body() == nil {
		return nil
	}
	buf := bytes.NewBuffer(nil)
	n, err := r.Body().Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	_, err = r.body.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	_, err = io.Copy(buf, r.Body())
	if err != nil {
		var errs *multierror.Error
		errs = multierror.Append(errs, err)
		_, errS := r.Body().Seek(n, io.SeekStart)
		if errS != nil {
			errs = multierror.Append(errs, errS)
		}
		return errs.ErrorOrNil()
	}
	_, err = r.Body().Seek(n, io.SeekStart)
	if err != nil {
		return err
	}
	body := bytes.NewReader(buf.Bytes())
	msg.SetBody(body)
	return nil
}
