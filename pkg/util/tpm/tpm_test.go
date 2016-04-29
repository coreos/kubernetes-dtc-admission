package tpm

import (
	"testing"

	"github.com/coreos/go-tspi/tspiconst"
)

func TestTPM(t *testing.T) {
	asciipolicy := []map[string]PCRConfig{
		{"0": PCRConfig{
			Policyref: "Ref",
			Source:    "Source",
			ASCIIValues: []PCRDescription{
				{
					Prefix: "Test",
					Values: []PCRValue{
						{
							Value:       "1",
							Description: "test 1",
						},
					},
				},
				{
					Prefix: "",
					Values: []PCRValue{
						{
							Value:       "2",
							Description: "test 2",
						},
					},
				},
			},
		},
		},
	}
	binarypolicy := []map[string]PCRConfig{
		{"0": PCRConfig{
			Policyref: "Ref",
			Source:    "Source",
			BinaryValues: []PCRDescription{
				{
					Prefix: "Test",
					Values: []PCRValue{
						{
							Value:       "5ccaaa9ca9f351d0c36b45c59728f1a23d16601d",
							Description: "test 1",
						},
					},
				},
				{
					Prefix: "",
					Values: []PCRValue{
						{
							Value:       "7295b69b0df06d518d481c54d71973f9f911520a",
							Description: "test 2",
						},
					},
				},
			},
		},
		},
	}
	rawpolicy := []map[string]PCRConfig{
		{"0": PCRConfig{
			Policyref: "Ref",
			Source:    "Source",
			RawValues: []PCRValue{
				{
					Value:       "6861c4035aaf7404e4114a84567e5536e91b315b",
					Description: "test raw",
				},
			},
		},
		},
	}
	log := []tspiconst.Log{
		{
			Pcr:       0,
			Eventtype: 13,
			PcrValue:  [20]byte{0x5c, 0xca, 0xaa, 0x9c, 0xa9, 0xf3, 0x51, 0xd0, 0xc3, 0x6b, 0x45, 0xc5, 0x97, 0x28, 0xf1, 0xa2, 0x3d, 0x16, 0x60, 0x1d},
			Event:     []byte("Test 1"),
		},
		{
			Pcr:       0,
			Eventtype: 13,
			PcrValue:  [20]byte{0x72, 0x95, 0xb6, 0x9b, 0x0d, 0xf0, 0x6d, 0x51, 0x8d, 0x48, 0x1c, 0x54, 0xd7, 0x19, 0x73, 0xf9, 0xf9, 0x11, 0x52, 0x0a},
			Event:     []byte("Test 2"),
		},
	}
	inconsistentlog := []tspiconst.Log{
		{
			Pcr:       0,
			Eventtype: 13,
			PcrValue:  [20]byte{0x5c, 0xca, 0xaa, 0x9c, 0xa9, 0xf3, 0x51, 0xd0, 0xc3, 0x6b, 0x45, 0xc5, 0x97, 0x28, 0xf1, 0xa2, 0x3d, 0x16, 0x60, 0x1e},
			Event:     []byte("Test 1"),
		},
	}
	invalidlog := []tspiconst.Log{
		{
			Pcr:       0,
			Eventtype: 13,
			PcrValue:  [20]byte{0x5c, 0xca, 0xaa, 0x9c, 0xa9, 0xf3, 0x51, 0xd0, 0xc3, 0x6b, 0x45, 0xc5, 0x97, 0x28, 0xf1, 0xa2, 0x3d, 0x16, 0x60, 0x1d},
			Event:     []byte("Test 1"),
		},
	}
	tamperedlog := []tspiconst.Log{
		{
			Pcr:       0,
			Eventtype: 13,
			PcrValue:  [20]byte{0x5c, 0xca, 0xaa, 0x9c, 0xa9, 0xf3, 0x51, 0xd0, 0xc3, 0x6b, 0x45, 0xc5, 0x97, 0x28, 0xf1, 0xa2, 0x3d, 0x16, 0x60, 0x1e},
			Event:     []byte("Bad 1"),
		},
		{
			Pcr:       0,
			Eventtype: 13,
			PcrValue:  [20]byte{0x72, 0x95, 0xb6, 0x9b, 0x0d, 0xf0, 0x6d, 0x51, 0x8d, 0x48, 0x1c, 0x54, 0xd7, 0x19, 0x73, 0xf9, 0xf9, 0x11, 0x52, 0x0a},
			Event:     []byte("Test 2"),
		},
	}
	quote := [][]byte{
		{0x68, 0x61, 0xc4, 0x03, 0x5a, 0xaf, 0x74, 0x04, 0xe4, 0x11, 0x4a, 0x84, 0x56, 0x7e, 0x55, 0x36, 0xe9, 0x1b, 0x31, 0x5b},
	}
	tamperedquote := [][]byte{
		{0x68, 0x61, 0xc4, 0x03, 0x5a, 0xaf, 0x74, 0x04, 0xe4, 0x11, 0x4a, 0x84, 0x56, 0x7e, 0x55, 0x36, 0xe9, 0x1b, 0x31, 0x5c},
	}

	err := ValidateLogConsistency(log)
	if err != nil {
		t.Errorf("%v", err)
	}

	err = ValidateLogConsistency(inconsistentlog)
	if err == nil {
		t.Errorf("Inconsistent log passed validation")
	}

	err = ValidateLog(log, quote)
	if err != nil {
		t.Errorf("%v", err)
	}

	err = ValidateLog(invalidlog, quote)
	if err == nil {
		t.Errorf("Invalid log passed validation")
	}

	validlog, err := ValidatePCRs(log, quote, asciipolicy)
	if err != nil {
		t.Errorf("%v %v", err, validlog)
	}

	validlog, err = ValidatePCRs(tamperedlog, quote, asciipolicy)
	if err == nil {
		t.Errorf("Invalid log passed ASCII validation")
	}

	validlog, err = ValidatePCRs(tamperedlog, quote, binarypolicy)
	if err == nil {
		t.Errorf("Invalid log passed binary validation")
	}
	validlog, err = ValidatePCRs(log, tamperedquote, rawpolicy)
	if err == nil {
		t.Errorf("Invalid log passed raw validation")
	}
}
