// Copyright 2024 Andrew E. Bruno. All rights reserved.
//
// This file is part of gomunge.
//
// gomunge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// gomunge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with gomunge. If not, see <https://www.gnu.org/licenses/>.

// Package munge is a cgo wrapper for MUNGE
package munge

/*
#cgo CFLAGS: -std=gnu99
#cgo LDFLAGS: -lmunge
#include "gmunge.h"
*/
import "C"

import (
	"errors"
	"fmt"
)

var (
	// ErrCredInvalid is returned when a credential is invalid
	ErrCredInvalid = errors.New("Invalid credential")

	// ErrCredExpired is returned when a credential is expired
	ErrCredExpired = errors.New("Expired credential")

	// ErrCredRewound is returned when a credential is rewound
	ErrCredRewound = errors.New("Rewound credential")

	// ErrCredReplayed is returned when a credential is replayed
	ErrCredReplayed = errors.New("Replayed credential")

	// ErrCredUnauthorized is returned when an unauthorized credential decode is performed
	ErrCredUnauthorized = errors.New("Unauthorized credential decode")
)

// Option for configuring munge credential
type Option func(*Credential)

// Credential is the munge credential
type Credential struct {
	uid     uint32
	gid     uint32
	payload []byte
	ttl     int
}

// NewCredential creates a new munge credential with default options.
func NewCredential(options ...Option) *Credential {
	credential := &Credential{}

	for _, opt := range options {
		opt(credential)
	}

	return credential
}

// WithPayload sets the payload for the munge credential.
func WithPayload(payload []byte) Option {
	return func(m *Credential) {
		m.payload = payload
	}
}

// WithTTL sets the time-to-live for the munge credential.
func WithTTL(ttl int) Option {
	return func(m *Credential) {
		m.ttl = ttl
	}
}

// Encode returns base64 encoded munge Credential
func (m *Credential) Encode() (string, error) {
	var conf C.conf_t
	conf = C.create_conf()

	if m.payload != nil && len(m.payload) > 0 {
		conf.data = C.CBytes(m.payload)
		conf.dlen = C.int(len(m.payload))
	}

	if m.ttl != 0 {
		if m.ttl < -1 {
			return "", fmt.Errorf("Invalid time-to-live: %d", m.ttl)
		}

		var ret C.int
		if m.ttl == -1 {
			ret = C.set_opt_int(conf.ctx, C.MUNGE_OPT_TTL, C.MUNGE_TTL_MAXIMUM)
		} else {
			ret = C.set_opt_int(conf.ctx, C.MUNGE_OPT_TTL, C.int(m.ttl))
		}

		if ret != C.EMUNGE_SUCCESS {
			return "", fmt.Errorf("Failed to set ttl: %d", ret)
		}
	}

	ret := C.encode_cred(conf)
	if ret != C.EMUNGE_SUCCESS {
		return "", fmt.Errorf("Failed to encode: %d", ret)
	}

	cred := C.GoString(conf.cred)

	C.destroy_conf(conf)

	return cred, nil
}

// TTL returns the time-to-live of the credential
func (m *Credential) TTL() int {
	return m.ttl
}

// Uid returns the uid of the client that requested the credential
func (m *Credential) Uid() uint32 {
	return m.uid
}

// Uid returns the uid as a string of the client that requested the credential
func (m *Credential) UidString() string {
	return fmt.Sprintf("%d", m.uid)
}

// Gid returns the gid of the client that requested the credential
func (m *Credential) Gid() uint32 {
	return m.gid
}

// Gid returns the gid as a string of the client that requested the credential
func (m *Credential) GidString() string {
	return fmt.Sprintf("%d", m.gid)
}

// Payload returns the payload data munged into the credential
func (m *Credential) Payload() []byte {
	return m.payload
}

// Encode returns base64 encoded munge Credential with default options
func Encode() (string, error) {
	cred := NewCredential()
	return cred.Encode()
}

// Decode base64 cred into a munge Credential
func Decode(cred string) (*Credential, error) {
	var conf C.conf_t
	conf = C.create_conf()
	conf.cred = C.CString(cred)

	ret := C.decode_cred(conf)
	if ret != C.EMUNGE_SUCCESS {
		switch ret {
		case C.EMUNGE_CRED_INVALID:
			return nil, ErrCredInvalid
		case C.EMUNGE_CRED_EXPIRED:
			return nil, ErrCredExpired
		case C.EMUNGE_CRED_REWOUND:
			return nil, ErrCredRewound
		case C.EMUNGE_CRED_REPLAYED:
			return nil, ErrCredReplayed
		case C.EMUNGE_CRED_UNAUTHORIZED:
			return nil, ErrCredUnauthorized
		default:
			msg := C.GoString(C.munge_strerror(conf.status))
			return nil, fmt.Errorf("Failed to decode: %s", msg)
		}
	}

	credential := &Credential{}
	credential.uid = uint32(conf.cuid)
	credential.gid = uint32(conf.cgid)
	credential.payload = C.GoBytes(conf.data, conf.dlen)

	var ttl C.int
	ret = C.get_opt_int(conf.ctx, C.MUNGE_OPT_TTL, &ttl)
	if ret != C.EMUNGE_SUCCESS {
		return nil, fmt.Errorf("Failed to get ttl from context: %d", ret)
	}
	credential.ttl = int(ttl)

	C.destroy_conf(conf)

	return credential, nil
}
