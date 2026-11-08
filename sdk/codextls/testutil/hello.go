// Package testutil validates captured Codex TLS records against native rustls fixtures.
package testutil

import (
	"bytes"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
)

//go:embed testdata/rustls-0.23.46/*.bin
var referenceFiles embed.FS

type NormalizedHello struct {
	RecordVersion, Version      uint16
	RandomLength, SessionLength int
	Ciphers                     []byte
	Compression                 []byte
	Extensions                  map[uint16][]byte
}

func NormalizeClientHello(raw []byte) (NormalizedHello, error) {
	var h NormalizedHello
	for len(raw) >= 5 && raw[0] != 22 {
		size := 5 + int(binary.BigEndian.Uint16(raw[3:5]))
		if size > len(raw) {
			return h, errors.New("truncated record")
		}
		raw = raw[size:]
	}
	if len(raw) < 44 || raw[0] != 22 || raw[5] != 1 {
		return h, errors.New("invalid ClientHello record")
	}
	raw = raw[:5+int(binary.BigEndian.Uint16(raw[3:5]))]
	h.RecordVersion = binary.BigEndian.Uint16(raw[1:3])
	b := raw[9:]
	h.Version = binary.BigEndian.Uint16(b[:2])
	h.RandomLength = 32
	p := 34
	h.SessionLength = int(b[p])
	p += 1 + h.SessionLength
	n := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	h.Ciphers = bytes.Clone(b[p : p+n])
	p += n
	n = int(b[p])
	p++
	h.Compression = bytes.Clone(b[p : p+n])
	p += n + 2
	h.Extensions = map[uint16][]byte{}
	var order []uint16
	for p < len(b) {
		id := binary.BigEndian.Uint16(b[p : p+2])
		n = int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		p += 4
		if p+n > len(b) {
			return h, errors.New("truncated extension")
		}
		value := bytes.Clone(b[p : p+n])
		p += n
		if _, exists := h.Extensions[id]; exists {
			return h, errors.New("duplicate extension")
		}
		if id == 0 {
			if len(value) < 6 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 || value[2] != 0 || int(binary.BigEndian.Uint16(value[3:5])) != len(value)-5 {
				return h, fmt.Errorf("invalid SNI structure %x", value)
			}
			// The controlled target's certificate verification checks its name.
			// Canonicalize the request-specific DNS name while retaining the
			// single DNS-entry structure used by the pinned rustls config.
			value = []byte{0, 14, 0, 0, 11, 'c', 'h', 'a', 't', 'g', 'p', 't', '.', 'c', 'o', 'm'}
		}
		if id == 51 {
			if len(value) == 1258 && !bytes.Equal(value[6+1184:6+1216], value[1226:1258]) {
				return h, errors.New("hybrid and classical keyshares use different X25519 keys")
			}
			for k := 2; k < len(value); {
				if k+4 > len(value) {
					return h, errors.New("truncated keyshare")
				}
				size := int(binary.BigEndian.Uint16(value[k+2 : k+4]))
				k += 4
				if k+size > len(value) {
					return h, errors.New("truncated key material")
				}
				clear(value[k : k+size])
				k += size
			}
		}
		if id == 41 {
			identities := int(binary.BigEndian.Uint16(value[:2]))
			k := 2
			for k < 2+identities {
				size := int(binary.BigEndian.Uint16(value[k : k+2]))
				k += 2
				clear(value[k : k+size+4])
				k += size + 4
			}
			k += 2
			for k < len(value) {
				size := int(value[k])
				k++
				clear(value[k : k+size])
				k += size
			}
		}
		h.Extensions[id] = value
		if id != 41 {
			order = append(order, id)
		} else if p != len(b) {
			return h, errors.New("PSK extension must be last")
		}
	}
	valid := false
	for seed := uint32(0); seed < 65536; seed++ {
		ok := true
		var last uint32
		for i, id := range order {
			key := extensionOrderHash(seed<<16 | uint32(id))
			if i > 0 && key < last {
				ok = false
				break
			}
			last = key
		}
		if ok {
			valid = true
			break
		}
	}
	if !valid {
		return h, fmt.Errorf("extension order is outside rustls seeded ordering: %v", order)
	}
	return h, nil
}

func extensionOrderHash(x uint32) uint32 {
	x = x + 0x7ed55d16 + (x << 12)
	x = (x ^ 0xc761c23c) ^ (x >> 19)
	x = x + 0x165667b1 + (x << 5)
	x = (x + 0xd3a2646c) ^ (x << 9)
	x = x + 0xfd7046c5 + (x << 3)
	return (x ^ 0xb55a4f09) ^ (x >> 16)
}

// VerifyClientHello compares the entire normalized ClientHello, accepting only
// the pinned rustls extension ordering and per-connection random material.
// Protocol must be "http" or "websocket". The capture is one TLS record;
// compatibility CCS records before a second ClientHello may also be included.
func VerifyClientHello(raw []byte, protocol string) error {
	if protocol != "http" && protocol != "websocket" {
		return fmt.Errorf("unknown reference protocol %q", protocol)
	}
	got, err := NormalizeClientHello(raw)
	if err != nil {
		return err
	}
	name := protocol + "-0.bin"
	if _, resumed := got.Extensions[41]; resumed {
		name = protocol + "-resumption-1.bin"
	} else if keyshare := got.Extensions[51]; len(keyshare) > 40 {
		name = protocol + "-hrr.bin"
	}
	reference, err := referenceFiles.ReadFile("testdata/rustls-0.23.46/" + name)
	if err != nil {
		return err
	}
	want, err := NormalizeClientHello(reference)
	if err != nil {
		return fmt.Errorf("invalid native fixture: %w", err)
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("captured ClientHello differs from native %s: got %#v; want %#v", name, got, want)
	}
	return nil
}
