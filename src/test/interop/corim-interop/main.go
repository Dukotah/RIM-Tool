// Command corim-interop is a test helper for checking RIM Tool CoRIMs against
// the Veraison reference implementation (github.com/veraison/corim).
//
// Subcommands:
//
//	rewrap  -to spec|legacy IN OUT  re-encode the tags array of an unsigned CoRIM
//	add-cotl IN OUT                 append a Veraison-built CoTL (tag 508) to an
//	                                unsigned, spec-encoded CoRIM
//	cose-verify -cert PEM IN        verify a COSE_Sign1 with go-cose only
//	                                (no CoRIM payload decoding)
//	jwk KEY.pem                     print an EC private key as a JWK, for cocli
//
// "spec" is the draft-ietf-rats-corim encoding of a concise-tag-type-choice:
// #6.506(bytes .cbor concise-mid-tag), and likewise for 505 and 508.
// "legacy" is the encoding RIM Tool (HIRS_Utils CoRimConfig) emits and
// CoRimParser expects: bytes .cbor #6.506(concise-mid-tag).
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/corim/cotl"
)

const unsignedCorimTag = 501

var tagNames = map[uint64]string{505: "CoSWID", 506: "CoMID", 507: "CoTS", 508: "CoTL"}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "rewrap":
		err = rewrapCmd(os.Args[2:])
	case "add-cotl":
		err = addCotlCmd(os.Args[2:])
	case "cose-verify":
		err = coseVerifyCmd(os.Args[2:])
	case "jwk":
		err = jwkCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "corim-interop:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: corim-interop rewrap|add-cotl|cose-verify|jwk ...")
	os.Exit(2)
}

// unsignedMap decodes #6.501({...}) (or a bare map) keeping values raw.
func unsignedMap(data []byte) (map[int64]cbor.RawMessage, error) {
	var tag cbor.RawTag
	body := data
	if err := cbor.Unmarshal(data, &tag); err == nil {
		if tag.Number != unsignedCorimTag {
			return nil, fmt.Errorf("expected CBOR tag %d, got %d", unsignedCorimTag, tag.Number)
		}
		body = tag.Content
	}
	m := map[int64]cbor.RawMessage{}
	if err := cbor.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("decoding corim-map: %w", err)
	}
	return m, nil
}

func encodeUnsigned(m map[int64]cbor.RawMessage) ([]byte, error) {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(cbor.Tag{Number: unsignedCorimTag, Content: m})
}

func rewrapCmd(args []string) error {
	fs := flag.NewFlagSet("rewrap", flag.ExitOnError)
	to := fs.String("to", "spec", "target encoding: spec or legacy")
	_ = fs.Parse(args)
	if fs.NArg() != 2 || (*to != "spec" && *to != "legacy") {
		return errors.New("usage: rewrap -to spec|legacy IN OUT")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := unsignedMap(data)
	if err != nil {
		return err
	}
	var tags []cbor.RawMessage
	if err := cbor.Unmarshal(m[1], &tags); err != nil {
		return fmt.Errorf("decoding tags array: %w", err)
	}
	out := make([]cbor.RawMessage, 0, len(tags))
	for i, t := range tags {
		num, content, form, err := splitTag(t)
		if err != nil {
			return fmt.Errorf("tag %d: %w", i, err)
		}
		var enc []byte
		if *to == "spec" {
			enc, err = cbor.Marshal(cbor.Tag{Number: num, Content: content})
		} else {
			inner, ierr := cbor.Marshal(cbor.RawTag{Number: num, Content: cbor.RawMessage(content)})
			if ierr != nil {
				return ierr
			}
			enc, err = cbor.Marshal(inner)
		}
		if err != nil {
			return err
		}
		fmt.Printf("tag %d: %s (%d) %s -> %s\n", i, tagNames[num], num, form, *to)
		out = append(out, enc)
	}
	if m[1], err = cbor.Marshal(out); err != nil {
		return err
	}
	buf, err := encodeUnsigned(m)
	if err != nil {
		return err
	}
	return os.WriteFile(fs.Arg(1), buf, 0o644)
}

// splitTag accepts either encoding and returns the tag number and the
// encoded concise-*-tag map.
func splitTag(raw cbor.RawMessage) (uint64, []byte, string, error) {
	var rt cbor.RawTag
	if err := cbor.Unmarshal(raw, &rt); err == nil {
		var b []byte
		if err := cbor.Unmarshal(rt.Content, &b); err != nil {
			return 0, nil, "", fmt.Errorf("tag %d content is not a byte string", rt.Number)
		}
		return rt.Number, b, "spec", nil
	}
	var b []byte
	if err := cbor.Unmarshal(raw, &b); err != nil {
		return 0, nil, "", errors.New("neither a tag nor a byte string")
	}
	if err := cbor.Unmarshal(b, &rt); err != nil {
		return 0, nil, "", errors.New("byte string does not hold a CBOR tag")
	}
	return rt.Number, rt.Content, "legacy", nil
}

func addCotlCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: add-cotl IN OUT")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var uc corim.UnsignedCorim
	if err := uc.FromCBOR(data); err != nil {
		return fmt.Errorf("decoding %s: %w", args[0], err)
	}
	var ids []cotl.TagIdentityMap
	for _, t := range uc.Tags {
		if t.Number != corim.ComidTag {
			continue
		}
		var c comid.Comid
		if err := c.FromCBOR(t.Content); err != nil {
			return fmt.Errorf("decoding CoMID: %w", err)
		}
		ids = append(ids, cotl.TagIdentityMap{TagID: c.TagIdentity.TagID})
	}
	if len(ids) == 0 {
		return fmt.Errorf("%s contains no CoMID tags", args[0])
	}
	id, err := cotl.NewTagIdentityMap("rim-tool-interop-cotl")
	if err != nil {
		return err
	}
	tl := cotl.ConciseTlTag{
		TagIdentity: *id,
		TagsList:    ids,
		TlValidity:  corim.Validity{NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	tagged, err := tl.ToCBOR()
	if err != nil {
		return fmt.Errorf("encoding CoTL: %w", err)
	}
	var tag corim.Tag
	if err := tag.UnmarshalCBOR(tagged); err != nil {
		return fmt.Errorf("re-reading CoTL: %w", err)
	}
	uc.Tags = append(uc.Tags, tag)
	buf, err := uc.ToCBOR()
	if err != nil {
		return fmt.Errorf("encoding CoRIM: %w", err)
	}
	fmt.Printf("added CoTL listing %d CoMID(s)\n", len(ids))
	return os.WriteFile(args[1], buf, 0o644)
}

func coseVerifyCmd(args []string) error {
	fs := flag.NewFlagSet("cose-verify", flag.ExitOnError)
	certPath := fs.String("cert", "", "PEM certificate holding the verification key")
	_ = fs.Parse(args)
	if fs.NArg() != 1 || *certPath == "" {
		return errors.New("usage: cose-verify -cert PEM IN")
	}
	pemData, err := os.ReadFile(*certPath)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(pemData)
	if blk == nil {
		return errors.New("no PEM block in certificate file")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("decoding COSE_Sign1: %w", err)
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return err
	}
	v, err := cose.NewVerifier(alg, cert.PublicKey)
	if err != nil {
		return err
	}
	if err := msg.Verify(nil, v); err != nil {
		return err
	}
	if k, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		fmt.Printf("verified: alg %v, key curve %s\n", alg, k.Curve.Params().Name)
	} else {
		fmt.Printf("verified: alg %v\n", alg)
	}
	return nil
}

func jwkCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: jwk KEY.pem")
	}
	pemData, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	// openssl ecparam -genkey writes an "EC PARAMETERS" block first
	blk, rest := pem.Decode(pemData)
	for blk != nil && blk.Type == "EC PARAMETERS" {
		blk, rest = pem.Decode(rest)
	}
	if blk == nil {
		return errors.New("no private key PEM block in key file")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		var ok bool
		if key, ok = k.(*ecdsa.PrivateKey); !ok {
			return errors.New("not an EC private key")
		}
	} else if key, err = x509.ParseECPrivateKey(blk.Bytes); err != nil {
		return err
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	b64 := func(b []byte) string {
		p := make([]byte, size-len(b), size)
		return base64.RawURLEncoding.EncodeToString(append(p, b...))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"kty": "EC",
		"crv": key.Curve.Params().Name,
		"x":   b64(key.X.Bytes()),
		"y":   b64(key.Y.Bytes()),
		"d":   b64(key.D.Bytes()),
	})
}
