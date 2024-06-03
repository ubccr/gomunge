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

package munge

import (
	"os/user"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	assert := assert.New(t)

	payload := []byte("Hello World")

	credA := NewCredential(WithPayload(payload), WithTTL(800))
	b64, err := credA.Encode()
	assert.NoError(err)

	assert.Contains(b64, "MUNGE:")

	credB, err := Decode(b64)
	assert.NoError(err)

	user, err := user.Current()
	assert.NoError(err)

	assert.Equal(user.Uid, credB.UidString())
	assert.Equal(user.Gid, credB.GidString())
	assert.Equal(payload, credB.Payload())
	assert.Equal(800, credB.TTL())
}

func TestDecodeError(t *testing.T) {
	assert := assert.New(t)

	credA := NewCredential(WithTTL(1))
	b64, err := credA.Encode()
	assert.NoError(err)
	assert.Contains(b64, "MUNGE:")

	time.Sleep(3 * time.Second)

	_, err = Decode(b64)
	assert.ErrorIs(ErrCredExpired, err)
}
