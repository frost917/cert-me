// Package cryptoformats contains the concrete cryptographic format adapters.
package cryptoformats

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"

	"cert-me/internal/app/port"
	"cert-me/internal/cryptowork"
	"cert-me/internal/domain"
	"cert-me/internal/secret"
	"golang.org/x/crypto/pbkdf2"
)

const (
	pkiImportFileLimit   = 4 << 20
	maxPBKDF2Iterations  = 2_000_000
	maxRequestIterations = 4_000_000
)

var (
	oidPBES2Parser                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2Parser                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256Parser            = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES128CBCParser             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBCParser             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBCParser             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSubjectAltNameParser        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCRLNumberParser             = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidDeltaCRLIndicatorParser     = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionParser   = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidAuthorityKeyIdentifierParse = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidCRLReasonParser             = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidCertificateIssuerParser     = asn1.ObjectIdentifier{2, 5, 29, 29}
	oidCommonNameParser            = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrganizationParser          = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnitParser    = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCountryParser               = asn1.ObjectIdentifier{2, 5, 4, 6}
)

// PKIParser parses only the import encodings listed in docs/pki-import.md.
// It does not assign storage identities or issuer relationships.
type PKIParser struct{}

var _ port.PKIParser = (*PKIParser)(nil)

// NewPKIParser returns the stateless PKI parser.
func NewPKIParser() *PKIParser { return &PKIParser{} }

func (p *PKIParser) ParseCertificateBundle(ctx context.Context, input port.CertificateBundleInput) (port.CertificateBundleFacts, error) {
	if err := checkPKIContext(ctx); err != nil {
		return port.CertificateBundleFacts{}, err
	}
	if len(input.Data) == 0 || len(input.Data) > pkiImportFileLimit {
		return port.CertificateBundleFacts{}, pkiFormatError("certificate bundle is empty or exceeds the 4 MiB file limit")
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return port.CertificateBundleFacts{}, err
	}
	defer release()

	var ders [][]byte
	if looksLikePEM(input.Data) {
		blocks, err := decodePEMSequence(input.Data, "CERTIFICATE")
		if err != nil {
			return port.CertificateBundleFacts{}, pkiFormatError("certificate bundle PEM is invalid")
		}
		ders = blocks
	} else {
		certificates, err := x509.ParseCertificates(input.Data)
		if err != nil {
			return port.CertificateBundleFacts{}, pkiFormatError("certificate bundle DER is invalid")
		}
		ders = make([][]byte, 0, len(certificates))
		for _, certificate := range certificates {
			ders = append(ders, certificate.Raw)
		}
	}
	if len(ders) == 0 {
		return port.CertificateBundleFacts{}, pkiFormatError("certificate bundle contains no certificates")
	}

	facts := port.CertificateBundleFacts{Certificates: make([]port.ParsedCertificateFacts, 0, len(ders))}
	for _, der := range ders {
		if err := checkPKIContext(ctx); err != nil {
			return port.CertificateBundleFacts{}, err
		}
		parsed, err := parseImportedCertificate(der)
		if err != nil {
			return port.CertificateBundleFacts{}, err
		}
		facts.Certificates = append(facts.Certificates, parsed)
	}
	if err := checkPKIContext(ctx); err != nil {
		return port.CertificateBundleFacts{}, err
	}
	return facts, nil
}

func (p *PKIParser) ParseCRL(ctx context.Context, input port.CRLInput) (port.ParsedCRLFacts, error) {
	if err := checkPKIContext(ctx); err != nil {
		return port.ParsedCRLFacts{}, err
	}
	if len(input.Data) == 0 || len(input.Data) > pkiImportFileLimit {
		return port.ParsedCRLFacts{}, pkiFormatError("CRL is empty or exceeds the 4 MiB file limit")
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return port.ParsedCRLFacts{}, err
	}
	defer release()

	der := input.Data
	if looksLikePEM(input.Data) {
		der, err = decodeOnePEM(input.Data, "X509 CRL", "CRL")
		if err != nil {
			return port.ParsedCRLFacts{}, pkiFormatError("CRL PEM must contain exactly one supported CRL block")
		}
	}
	parsed, err := parseCRLDER(der)
	if err != nil {
		return port.ParsedCRLFacts{}, pkiFormatError("CRL DER is invalid or contains trailing data")
	}
	if parsed.v2 != nil {
		if err := validateCRLASN1Consumption(parsed.v2); err != nil {
			return port.ParsedCRLFacts{}, err
		}
		if err := validateCRLExtensions(parsed.v2); err != nil {
			return port.ParsedCRLFacts{}, err
		}
	}
	issuer, err := subjectFromPKIX(parsed.issuer)
	if err != nil {
		return port.ParsedCRLFacts{}, pkiFormatError("CRL issuer name cannot be represented by the import contract")
	}
	if parsed.thisUpdate.IsZero() {
		return port.ParsedCRLFacts{}, pkiFormatError("CRL has no thisUpdate time")
	}
	if !parsed.nextUpdate.IsZero() && !parsed.nextUpdate.After(parsed.thisUpdate) {
		return port.ParsedCRLFacts{}, pkiFormatError("CRL nextUpdate must follow thisUpdate")
	}
	thisUpdate := domain.NewInstant(parsed.thisUpdate)
	if thisUpdate.IsZero() {
		return port.ParsedCRLFacts{}, pkiFormatError("CRL thisUpdate cannot be represented by the storage timestamp")
	}

	var number domain.CRLNumber
	if parsed.number != nil {
		number, err = domain.NewCRLNumberFromBig(parsed.number)
		if err != nil {
			return port.ParsedCRLFacts{}, pkiFormatError("CRL number is invalid")
		}
	}
	facts := port.ParsedCRLFacts{
		DER:            append([]byte(nil), der...),
		IssuerSubject:  issuer,
		AuthorityKeyID: append([]byte(nil), parsed.authorityKeyID...),
		Number:         number,
		ThisUpdate:     thisUpdate,
		NextUpdate:     domain.NewInstant(parsed.nextUpdate),
		Revoked:        make([]port.RevokedEntryFacts, 0, len(parsed.entries)),
	}
	for _, entry := range parsed.entries {
		if err := checkPKIContext(ctx); err != nil {
			return port.ParsedCRLFacts{}, err
		}
		if err := validateCRLEntryExtensions(entry.Extensions); err != nil {
			return port.ParsedCRLFacts{}, err
		}
		serial, err := domain.NewSerialNumberFromBig(entry.SerialNumber)
		if err != nil {
			return port.ParsedCRLFacts{}, pkiFormatError("CRL contains an invalid revoked certificate serial")
		}
		if entry.RevocationTime.IsZero() {
			return port.ParsedCRLFacts{}, pkiFormatError("CRL contains a revoked entry without a revocation time")
		}
		reason, ok := importedCRLReason(entry.ReasonCode)
		if !ok {
			return port.ParsedCRLFacts{}, pkiFormatError("CRL contains an unsupported revocation reason")
		}
		facts.Revoked = append(facts.Revoked, port.RevokedEntryFacts{
			Serial:    serial,
			RevokedAt: domain.NewInstant(entry.RevocationTime),
			Reason:    reason,
		})
	}
	if err := checkPKIContext(ctx); err != nil {
		return port.ParsedCRLFacts{}, err
	}
	return facts, nil
}

// PreflightCAKeys validates the complete set of CA-key encodings and sums
// PBKDF2 work before any encrypted key is decrypted. It keeps no parsed key
// beyond the validation of its own unencrypted input.
func (p *PKIParser) PreflightCAKeys(ctx context.Context, inputs []port.CAKeyInput) error {
	if err := checkPKIContext(ctx); err != nil {
		return err
	}
	if len(inputs) == 0 {
		return nil
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	return preflightCAKeys(ctx, inputs)
}

func (p *PKIParser) ParseCAKey(ctx context.Context, input port.CAKeyInput) (port.ValidatedCAKeyInput, error) {
	if err := p.PreflightCAKeys(ctx, []port.CAKeyInput{input}); err != nil {
		return port.ValidatedCAKeyInput{}, err
	}
	key, algorithm, public, err := p.parsePrivateKey(ctx, input.Data, input.Passphrase, input.ExpectedPublicKey)
	if err != nil {
		return port.ValidatedCAKeyInput{}, err
	}
	return port.ValidatedCAKeyInput{PrivateKey: key, Algorithm: algorithm, PublicKey: public}, nil
}

func (p *PKIParser) ParseInternalTLSKey(ctx context.Context, input port.TLSKeyInput) (port.ValidatedTLSKeyInput, error) {
	if err := p.PreflightCAKeys(ctx, []port.CAKeyInput{{
		Data: input.Data, Passphrase: input.Passphrase, ExpectedPublicKey: input.ExpectedPublicKey,
	}}); err != nil {
		return port.ValidatedTLSKeyInput{}, err
	}
	key, algorithm, public, err := p.parsePrivateKey(ctx, input.Data, input.Passphrase, input.ExpectedPublicKey)
	if err != nil {
		return port.ValidatedTLSKeyInput{}, err
	}
	return port.ValidatedTLSKeyInput{PrivateKey: key, Algorithm: algorithm, PublicKey: public}, nil
}

func (p *PKIParser) parsePrivateKey(ctx context.Context, data []byte, passphrase *secret.Input, expected domain.PublicKey) (*secret.Input, domain.KeyAlgorithm, domain.PublicKey, error) {
	if err := checkPKIContext(ctx); err != nil {
		return nil, "", domain.PublicKey{}, err
	}
	if len(data) == 0 || len(data) > pkiImportFileLimit {
		return nil, "", domain.PublicKey{}, pkiFormatError("private key is empty or exceeds the 4 MiB file limit")
	}
	if expected.IsZero() || expected.Algorithm().Validate() != nil {
		return nil, "", domain.PublicKey{}, pkiFormatError("expected public key is invalid")
	}
	release, err := cryptowork.Acquire(ctx)
	if err != nil {
		return nil, "", domain.PublicKey{}, err
	}
	defer release()

	encoded, err := decodePrivateKeyEnvelope(data)
	if err != nil {
		return nil, "", domain.PublicKey{}, err
	}
	if encoded.owned {
		defer zeroPKIBytes(encoded.der)
	}
	var private any
	if encoded.label == "ENCRYPTED PRIVATE KEY" || (encoded.label == "" && looksLikeEncryptedPKCS8(encoded.der)) {
		params, encrypted, err := inspectEncryptedPKCS8(encoded.der)
		if err != nil {
			return nil, "", domain.PublicKey{}, err
		}
		defer params.clear()
		if passphrase == nil {
			return nil, "", domain.PublicKey{}, pkiFormatError("encrypted PKCS#8 key requires a passphrase")
		}
		err = passphrase.Use(func(password []byte) error {
			if err := checkPKIContext(ctx); err != nil {
				return err
			}
			plain, err := decryptPBES2(params, encrypted, password)
			if err != nil {
				return pkiFormatError("encrypted PKCS#8 key could not be decrypted")
			}
			defer zeroPKIBytes(plain)
			private, err = parsePlainPrivateKey(plain, "PRIVATE KEY")
			if err != nil {
				return err
			}
			return checkPKIContext(ctx)
		})
		if err != nil {
			if private != nil {
				clearImportedPrivateKey(private)
			}
			return nil, "", domain.PublicKey{}, err
		}
	} else {
		if passphrase != nil {
			return nil, "", domain.PublicKey{}, pkiFormatError("a passphrase was supplied for an unencrypted private key")
		}
		private, err = parsePlainPrivateKey(encoded.der, encoded.label)
		if err != nil {
			return nil, "", domain.PublicKey{}, err
		}
	}
	defer clearImportedPrivateKey(private)

	algorithm, public, err := importedPrivatePublicKey(private)
	if err != nil {
		return nil, "", domain.PublicKey{}, err
	}
	if !public.Equal(expected) {
		return nil, "", domain.PublicKey{}, pkiFormatError("private key does not match the expected certificate public key")
	}
	if err := checkPKIContext(ctx); err != nil {
		return nil, "", domain.PublicKey{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, "", domain.PublicKey{}, pkiFormatError("private key could not be normalized to PKCS#8")
	}
	owned := secret.New(privateDER)
	return owned, algorithm, public, nil
}

func preflightCAKeys(ctx context.Context, inputs []port.CAKeyInput) error {
	var iterationTotal int64
	for _, input := range inputs {
		if err := checkPKIContext(ctx); err != nil {
			return err
		}
		iterations, err := preflightOneCAKey(input)
		if err != nil {
			return err
		}
		iterationTotal += int64(iterations)
		if iterationTotal > maxRequestIterations {
			return pkiFormatError("request PBKDF2 iteration total exceeds 4,000,000")
		}
	}
	return checkPKIContext(ctx)
}

func preflightOneCAKey(input port.CAKeyInput) (int, error) {
	if len(input.Data) == 0 || len(input.Data) > pkiImportFileLimit {
		return 0, pkiFormatError("private key is empty or exceeds the 4 MiB file limit")
	}
	encoded, err := decodePrivateKeyEnvelope(input.Data)
	if err != nil {
		return 0, err
	}
	if encoded.owned {
		defer zeroPKIBytes(encoded.der)
	}
	if encoded.label == "ENCRYPTED PRIVATE KEY" || (encoded.label == "" && looksLikeEncryptedPKCS8(encoded.der)) {
		params, _, err := inspectEncryptedPKCS8(encoded.der)
		if err != nil {
			return 0, err
		}
		defer params.clear()
		if input.Passphrase == nil {
			return 0, pkiFormatError("encrypted PKCS#8 key requires a passphrase")
		}
		if err := input.Passphrase.Use(func([]byte) error { return nil }); err != nil {
			return 0, pkiFormatError("encrypted PKCS#8 passphrase is unavailable")
		}
		return params.iterations, nil
	}
	if input.Passphrase != nil {
		return 0, pkiFormatError("a passphrase was supplied for an unencrypted private key")
	}
	private, err := parsePlainPrivateKey(encoded.der, encoded.label)
	if err != nil {
		return 0, err
	}
	defer clearImportedPrivateKey(private)
	if _, _, err := importedPrivatePublicKey(private); err != nil {
		return 0, err
	}
	return 0, nil
}

type privateKeyEnvelope struct {
	der   []byte
	label string
	owned bool
}

func decodePrivateKeyEnvelope(data []byte) (privateKeyEnvelope, error) {
	if looksLikePEM(data) {
		block, err := decodePEMBlock(data)
		if err != nil {
			return privateKeyEnvelope{}, pkiFormatError("private key PEM block is invalid or unsupported")
		}
		switch block.Type {
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		default:
			zeroPKIBytes(block.Bytes)
			return privateKeyEnvelope{}, pkiFormatError("private key PEM label is unsupported")
		}
		if len(block.Headers) != 0 {
			zeroPKIBytes(block.Bytes)
			return privateKeyEnvelope{}, pkiFormatError("private key PEM headers are unsupported")
		}
		return privateKeyEnvelope{der: block.Bytes, label: block.Type, owned: true}, nil
	}
	return privateKeyEnvelope{der: data}, nil
}

type pbes2Parameters struct {
	iterations int
	salt       []byte
	keySize    int
	iv         []byte
	ciphertext []byte
}

func (params *pbes2Parameters) clear() {
	if params == nil {
		return
	}
	zeroPKIBytes(params.salt)
	zeroPKIBytes(params.iv)
	zeroPKIBytes(params.ciphertext)
}

func looksLikeEncryptedPKCS8(der []byte) bool {
	outer, err := parseASN1Full(der)
	if err != nil || !isASN1Sequence(outer) {
		return false
	}
	parts, err := sequenceParts(outer)
	if err != nil || len(parts) < 1 || !isASN1Sequence(parts[0]) {
		return false
	}
	algorithm, err := parseAlgorithmIdentifier(parts[0])
	return err == nil && algorithm.Algorithm.Equal(oidPBES2Parser)
}

func inspectEncryptedPKCS8(der []byte) (pbes2Parameters, []byte, error) {
	outer, err := parseASN1Full(der)
	if err != nil || !isASN1Sequence(outer) {
		return pbes2Parameters{}, nil, pkiFormatError("encrypted PKCS#8 ASN.1 is invalid")
	}
	parts, err := sequenceParts(outer)
	if err != nil || len(parts) != 2 || !isASN1Sequence(parts[0]) || !isASN1Primitive(parts[1], asn1.TagOctetString) {
		return pbes2Parameters{}, nil, pkiFormatError("encrypted PKCS#8 structure is invalid")
	}
	algorithm, err := parseAlgorithmIdentifier(parts[0])
	if err != nil || !algorithm.Algorithm.Equal(oidPBES2Parser) || len(algorithm.Parameters.FullBytes) == 0 || !isASN1Sequence(algorithm.Parameters) {
		return pbes2Parameters{}, nil, pkiFormatError("only PBES2 encrypted PKCS#8 is supported")
	}
	pbesParts, err := sequenceParts(algorithm.Parameters)
	if err != nil || len(pbesParts) != 2 {
		return pbes2Parameters{}, nil, pkiFormatError("PBES2 parameters are invalid")
	}
	kdf, err := parseAlgorithmIdentifier(pbesParts[0])
	if err != nil || !kdf.Algorithm.Equal(oidPBKDF2Parser) || len(kdf.Parameters.FullBytes) == 0 || !isASN1Sequence(kdf.Parameters) {
		return pbes2Parameters{}, nil, pkiFormatError("only PBKDF2 encrypted PKCS#8 is supported")
	}
	params, err := parsePBKDF2Parameters(kdf.Parameters)
	if err != nil {
		return pbes2Parameters{}, nil, err
	}
	defer zeroPKIBytes(params.salt)
	cipherAlg, err := parseAlgorithmIdentifier(pbesParts[1])
	if err != nil || len(cipherAlg.Parameters.FullBytes) == 0 {
		return pbes2Parameters{}, nil, pkiFormatError("PBES2 encryption scheme is invalid")
	}
	keySize, ok := aesCBCKeySize(cipherAlg.Algorithm)
	if !ok || !isASN1Primitive(cipherAlg.Parameters, asn1.TagOctetString) {
		return pbes2Parameters{}, nil, pkiFormatError("only AES-CBC with a 128, 192, or 256 bit key is supported")
	}
	iv := cipherAlg.Parameters.Bytes
	if len(iv) != aes.BlockSize {
		return pbes2Parameters{}, nil, pkiFormatError("AES-CBC IV must be 16 bytes")
	}
	if params.hasKeyLength && params.keyLength != keySize {
		return pbes2Parameters{}, nil, pkiFormatError("PBKDF2 keyLength does not match the AES key size")
	}
	if len(parts[1].Bytes) == 0 || len(parts[1].Bytes)%aes.BlockSize != 0 || len(parts[1].Bytes) > pkiImportFileLimit {
		return pbes2Parameters{}, nil, pkiFormatError("encrypted PKCS#8 ciphertext must be a positive AES block multiple within 4 MiB")
	}
	result := pbes2Parameters{
		iterations: params.iterations,
		salt:       append([]byte(nil), params.salt...),
		keySize:    keySize,
		iv:         append([]byte(nil), iv...),
		ciphertext: append([]byte(nil), parts[1].Bytes...),
	}
	return result, result.ciphertext, nil
}

type parsedPBKDF2Parameters struct {
	iterations   int
	salt         []byte
	keyLength    int
	hasKeyLength bool
}

func parsePBKDF2Parameters(raw asn1.RawValue) (parsedPBKDF2Parameters, error) {
	parts, err := sequenceParts(raw)
	if err != nil || len(parts) < 3 || len(parts) > 4 || !isASN1Primitive(parts[0], asn1.TagOctetString) {
		return parsedPBKDF2Parameters{}, pkiFormatError("PBKDF2 parameters are malformed")
	}
	salt := parts[0].Bytes
	if len(salt) < 8 || len(salt) > 64 {
		return parsedPBKDF2Parameters{}, pkiFormatError("PBKDF2 salt must be between 8 and 64 bytes")
	}
	iterations, err := parseASN1Int(parts[1])
	if err != nil || iterations < 1 || iterations > maxPBKDF2Iterations {
		return parsedPBKDF2Parameters{}, pkiFormatError("PBKDF2 iterations must be between 1 and 2,000,000")
	}
	parsed := parsedPBKDF2Parameters{iterations: iterations, salt: append([]byte(nil), salt...)}
	index := 2
	if isASN1Primitive(parts[index], asn1.TagInteger) {
		keyLength, err := parseASN1Int(parts[index])
		if err != nil || keyLength <= 0 {
			return parsedPBKDF2Parameters{}, pkiFormatError("PBKDF2 keyLength is invalid")
		}
		parsed.keyLength = keyLength
		parsed.hasKeyLength = true
		index++
	}
	if index >= len(parts) || index != len(parts)-1 || !isASN1Sequence(parts[index]) {
		return parsedPBKDF2Parameters{}, pkiFormatError("PBKDF2 must explicitly select HMAC-SHA256")
	}
	prf, err := parseAlgorithmIdentifier(parts[index])
	if err != nil || !prf.Algorithm.Equal(oidHMACSHA256Parser) {
		return parsedPBKDF2Parameters{}, pkiFormatError("PBKDF2 PRF must explicitly select HMAC-SHA256")
	}
	if len(prf.Parameters.FullBytes) != 0 && !isASN1Primitive(prf.Parameters, asn1.TagNull) {
		return parsedPBKDF2Parameters{}, pkiFormatError("HMAC-SHA256 parameters must be absent or NULL")
	}
	if len(prf.Parameters.FullBytes) != 0 && len(prf.Parameters.Bytes) != 0 {
		return parsedPBKDF2Parameters{}, pkiFormatError("HMAC-SHA256 NULL parameters are malformed")
	}
	return parsed, nil
}

func decryptPBES2(params pbes2Parameters, ciphertext, password []byte) ([]byte, error) {
	key := pbkdf2.Key(password, params.salt, params.iterations, params.keySize, sha256.New)
	defer zeroPKIBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, params.iv).CryptBlocks(plain, ciphertext)
	padding, err := removePKCS7Padding(plain, aes.BlockSize)
	if err != nil {
		zeroPKIBytes(plain)
		return nil, err
	}
	for i := len(plain) - padding; i < len(plain); i++ {
		plain[i] = 0
	}
	return plain[:len(plain)-padding], nil
}

func removePKCS7Padding(data []byte, blockSize int) (int, error) {
	if len(data) == 0 || blockSize <= 0 || len(data)%blockSize != 0 {
		return 0, errors.New("invalid CBC padding")
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > blockSize {
		return 0, errors.New("invalid CBC padding")
	}
	var mismatch int
	for i := 0; i < blockSize; i++ {
		mask := subtle.ConstantTimeLessOrEq(i+1, padding)
		mismatch |= mask * (int(data[len(data)-1-i]) ^ padding)
	}
	if mismatch != 0 {
		return 0, errors.New("invalid CBC padding")
	}
	return padding, nil
}

func parsePlainPrivateKey(der []byte, label string) (any, error) {
	if _, err := parseASN1Full(der); err != nil {
		return nil, pkiFormatError("private key DER has trailing or malformed ASN.1 data")
	}
	switch label {
	case "PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		if label == "ENCRYPTED PRIVATE KEY" {
			return nil, pkiFormatError("encrypted PKCS#8 inner value is invalid")
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, pkiFormatError("PKCS#8 private key is invalid")
		}
		if !supportedPrivateKeyType(key) {
			clearImportedPrivateKey(key)
			return nil, pkiFormatError("private key algorithm is outside the supported set")
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, pkiFormatError("PKCS#1 RSA private key is invalid")
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, pkiFormatError("SEC1 EC private key is invalid")
		}
		return key, nil
	case "":
		if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			if !supportedPrivateKeyType(key) {
				clearImportedPrivateKey(key)
				return nil, pkiFormatError("private key algorithm is outside the supported set")
			}
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(der); err == nil {
			return key, nil
		}
		return nil, pkiFormatError("DER is not a supported unencrypted private key")
	default:
		return nil, pkiFormatError("private key PEM label is unsupported")
	}
}

func supportedPrivateKeyType(key any) bool {
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return true
	default:
		return false
	}
}

func importedPrivatePublicKey(private any) (domain.KeyAlgorithm, domain.PublicKey, error) {
	var public any
	switch key := private.(type) {
	case *rsa.PrivateKey:
		if key == nil || key.N == nil {
			return "", domain.PublicKey{}, pkiFormatError("RSA private key is invalid")
		}
		switch key.N.BitLen() {
		case 2048:
			public = &key.PublicKey
			algorithm := domain.KeyAlgorithmRSA2048
			return makeImportedPublicKey(public, algorithm)
		case 3072:
			public = &key.PublicKey
			algorithm := domain.KeyAlgorithmRSA3072
			return makeImportedPublicKey(public, algorithm)
		case 4096:
			public = &key.PublicKey
			algorithm := domain.KeyAlgorithmRSA4096
			return makeImportedPublicKey(public, algorithm)
		default:
			return "", domain.PublicKey{}, pkiFormatError("RSA private key must be 2048, 3072, or 4096 bits")
		}
	case *ecdsa.PrivateKey:
		if key == nil || key.Curve == nil || key.D == nil {
			return "", domain.PublicKey{}, pkiFormatError("ECDSA private key is invalid")
		}
		var algorithm domain.KeyAlgorithm
		switch key.Curve.Params().Name {
		case elliptic.P256().Params().Name:
			algorithm = domain.KeyAlgorithmECDSAP256
		case elliptic.P384().Params().Name:
			algorithm = domain.KeyAlgorithmECDSAP384
		default:
			return "", domain.PublicKey{}, pkiFormatError("ECDSA private key must use P-256 or P-384")
		}
		return makeImportedPublicKey(&key.PublicKey, algorithm)
	default:
		return "", domain.PublicKey{}, pkiFormatError("private key algorithm is unsupported")
	}
}

func makeImportedPublicKey(key any, algorithm domain.KeyAlgorithm) (domain.KeyAlgorithm, domain.PublicKey, error) {
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", domain.PublicKey{}, pkiFormatError("private key public half is invalid")
	}
	defer zeroPKIBytes(spki)
	public, err := domain.NewPublicKey(algorithm, spki)
	if err != nil {
		return "", domain.PublicKey{}, pkiFormatError("private key public half is invalid")
	}
	return algorithm, public, nil
}

func clearImportedPrivateKey(private any) {
	switch key := private.(type) {
	case *rsa.PrivateKey:
		if key == nil {
			return
		}
		wipeBigInt(key.D)
		for _, prime := range key.Primes {
			wipeBigInt(prime)
		}
		wipeBigInt(key.Precomputed.Dp)
		wipeBigInt(key.Precomputed.Dq)
		wipeBigInt(key.Precomputed.Qinv)
		for i := range key.Precomputed.CRTValues {
			wipeBigInt(key.Precomputed.CRTValues[i].Exp)
			wipeBigInt(key.Precomputed.CRTValues[i].Coeff)
			wipeBigInt(key.Precomputed.CRTValues[i].R)
		}
	case *ecdsa.PrivateKey:
		if key != nil {
			wipeBigInt(key.D)
		}
	}
}

func wipeBigInt(value *big.Int) {
	if value == nil {
		return
	}
	words := value.Bits()
	for i := range words {
		words[i] = 0
	}
	value.SetInt64(0)
}

func parseImportedCertificate(der []byte) (port.ParsedCertificateFacts, error) {
	parsed, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(parsed.Raw, der) {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate DER is invalid or contains trailing data")
	}
	if err := uniqueExtensionOIDs(parsed.Extensions); err != nil {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate contains duplicate extensions")
	}
	if len(parsed.UnhandledCriticalExtensions) != 0 {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate contains an unsupported critical extension")
	}
	if !supportedCertificateSignature(parsed.SignatureAlgorithm) {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate uses an unsupported or weak signature algorithm")
	}
	algorithm, ok := importedPublicAlgorithm(parsed.PublicKey)
	if !ok {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate public key algorithm is unsupported")
	}
	public, err := domain.NewPublicKey(algorithm, parsed.RawSubjectPublicKeyInfo)
	if err != nil {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate SubjectPublicKeyInfo is invalid")
	}
	subject, err := subjectFromPKIX(parsed.Subject)
	if err != nil {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate subject name cannot be represented by the import contract")
	}
	if subject.CommonName() != parsed.Subject.CommonName {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate subject common name requires normalization")
	}
	issuer, err := subjectFromPKIX(parsed.Issuer)
	if err != nil {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate issuer name cannot be represented by the import contract")
	}
	if issuer.CommonName() != parsed.Issuer.CommonName {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate issuer common name requires normalization")
	}
	serial, err := domain.NewSerialNumberFromBig(parsed.SerialNumber)
	if err != nil {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate serial number is invalid")
	}
	validity, err := domain.NewValidityWindow(domain.NewInstant(parsed.NotBefore), domain.NewInstant(parsed.NotAfter))
	if err != nil {
		return port.ParsedCertificateFacts{}, pkiFormatError("certificate validity period is invalid")
	}
	sans, err := importedSANs(parsed.Extensions)
	if err != nil {
		return port.ParsedCertificateFacts{}, err
	}
	kind := domain.CertificateKindLeaf
	profile := domain.CertificateProfile("")
	if parsed.IsCA {
		if !parsed.BasicConstraintsValid {
			return port.ParsedCertificateFacts{}, pkiFormatError("CA certificate has invalid basic constraints")
		}
		kind = domain.CertificateKindCA
	} else {
		profile, err = importedLeafProfile(parsed)
		if err != nil {
			return port.ParsedCertificateFacts{}, err
		}
	}
	return port.ParsedCertificateFacts{
		DER:             append([]byte(nil), parsed.Raw...),
		PublicKey:       public,
		SPKIFingerprint: public.Fingerprint(),
		KeyAlgorithm:    algorithm,
		Serial:          serial,
		Validity:        validity,
		Subject:         subject,
		SANs:            sans,
		Kind:            kind,
		Profile:         profile,
		IssuerSubject:   issuer,
		AuthorityKeyID:  append([]byte(nil), parsed.AuthorityKeyId...),
		SubjectKeyID:    append([]byte(nil), parsed.SubjectKeyId...),
	}, nil
}

func importedPublicAlgorithm(public any) (domain.KeyAlgorithm, bool) {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return "", false
		}
		switch key.N.BitLen() {
		case 2048:
			return domain.KeyAlgorithmRSA2048, true
		case 3072:
			return domain.KeyAlgorithmRSA3072, true
		case 4096:
			return domain.KeyAlgorithmRSA4096, true
		}
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.Curve.Params() == nil {
			return "", false
		}
		switch key.Curve.Params().Name {
		case elliptic.P256().Params().Name:
			return domain.KeyAlgorithmECDSAP256, true
		case elliptic.P384().Params().Name:
			return domain.KeyAlgorithmECDSAP384, true
		}
	}
	return "", false
}

func supportedCertificateSignature(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

func subjectFromPKIX(name pkix.Name) (domain.Subject, error) {
	var facts domain.SubjectFacts
	seen := make(map[string]bool, 4)
	for _, attribute := range name.Names {
		var field *string
		switch {
		case attribute.Type.Equal(oidCommonNameParser):
			field = &facts.CommonName
		case attribute.Type.Equal(oidOrganizationParser):
			field = &facts.Organization
		case attribute.Type.Equal(oidOrganizationalUnitParser):
			field = &facts.OrganizationalUnit
		case attribute.Type.Equal(oidCountryParser):
			field = &facts.Country
		default:
			continue
		}
		key := attribute.Type.String()
		value, ok := attribute.Value.(string)
		if !ok || seen[key] {
			return domain.Subject{}, errors.New("ambiguous or non-string subject attribute")
		}
		*field = value
		seen[key] = true
	}
	return domain.NewSubject(facts)
}

func importedSANs(extensions []pkix.Extension) ([]domain.SAN, error) {
	var raw []byte
	for _, extension := range extensions {
		if extension.Id.Equal(oidSubjectAltNameParser) {
			raw = extension.Value
			break
		}
	}
	if raw == nil {
		return nil, nil
	}
	sequence, err := parseASN1Full(raw)
	if err != nil || !isASN1Sequence(sequence) {
		return nil, pkiFormatError("certificate SubjectAltName extension is malformed")
	}
	entries, err := sequenceParts(sequence)
	if err != nil {
		return nil, pkiFormatError("certificate SubjectAltName extension is malformed")
	}
	sans := make([]domain.SAN, 0, len(entries))
	for _, entry := range entries {
		if entry.Class != asn1.ClassContextSpecific || entry.IsCompound {
			return nil, pkiFormatError("certificate contains an unsupported SubjectAltName form")
		}
		var kind domain.SANType
		var value string
		switch entry.Tag {
		case 2: // dNSName [2] IA5String
			kind = domain.SANTypeDNS
			if !isASCII(entry.Bytes) {
				return nil, pkiFormatError("certificate DNS SubjectAltName is not IA5")
			}
			value = string(entry.Bytes)
		case 6: // uniformResourceIdentifier [6] IA5String
			kind = domain.SANTypeURI
			if !isASCII(entry.Bytes) {
				return nil, pkiFormatError("certificate URI SubjectAltName is not IA5")
			}
			value = string(entry.Bytes)
		case 7: // iPAddress [7] OCTET STRING
			kind = domain.SANTypeIP
			address, ok := netip.AddrFromSlice(entry.Bytes)
			if !ok || (len(entry.Bytes) != 4 && len(entry.Bytes) != 16) {
				return nil, pkiFormatError("certificate IP SubjectAltName is invalid")
			}
			value = address.String()
		default:
			return nil, pkiFormatError("certificate contains an unsupported SubjectAltName type")
		}
		san, err := domain.NewSAN(kind, value)
		if err != nil {
			return nil, pkiFormatError("certificate SubjectAltName is outside the supported set")
		}
		if san.Value() != value {
			return nil, pkiFormatError("certificate SubjectAltName requires normalization")
		}
		sans = append(sans, san)
	}
	return sans, nil
}

func importedLeafProfile(cert *x509.Certificate) (domain.CertificateProfile, error) {
	if len(cert.UnknownExtKeyUsage) != 0 {
		return "", pkiFormatError("leaf certificate uses an unsupported extended key usage")
	}
	hasServer, hasClient := false, false
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			hasServer = true
		case x509.ExtKeyUsageClientAuth:
			hasClient = true
		default:
			return "", pkiFormatError("leaf certificate uses an unsupported extended key usage")
		}
	}
	switch {
	case hasServer && hasClient && len(cert.ExtKeyUsage) == 2:
		return domain.CertificateProfileDual, nil
	case hasServer && !hasClient && len(cert.ExtKeyUsage) == 1:
		return domain.CertificateProfileServerTLS, nil
	case hasClient && !hasServer && len(cert.ExtKeyUsage) == 1:
		return domain.CertificateProfileClientMTLS, nil
	default:
		return "", pkiFormatError("leaf certificate must declare a supported server, client, or dual profile")
	}
}

func validateCRLExtensions(crl *x509.RevocationList) error {
	if err := uniqueExtensionOIDs(crl.Extensions); err != nil {
		return pkiFormatError("CRL contains duplicate extensions")
	}
	for _, extension := range crl.Extensions {
		switch {
		case extension.Id.Equal(oidCRLNumberParser), extension.Id.Equal(oidAuthorityKeyIdentifierParse):
			if extension.Critical {
				return pkiFormatError("CRL number and authority key identifier must not be critical")
			}
		case extension.Id.Equal(oidDeltaCRLIndicatorParser):
			return pkiFormatError("delta CRLs are not supported")
		case extension.Id.Equal(oidIssuingDistributionParser):
			if !extension.Critical || !isFullScopeIssuingDistributionPoint(extension.Value) {
				return pkiFormatError("partitioned or malformed CRLs are not supported")
			}
		default:
			return pkiFormatError("CRL contains an unsupported extension")
		}
	}
	return nil
}

func validateCRLASN1Consumption(crl *x509.RevocationList) error {
	outer, err := parseASN1Full(crl.Raw)
	if err != nil || !isASN1Sequence(outer) {
		return pkiFormatError("CRL outer ASN.1 structure is malformed")
	}
	outerParts, err := sequenceParts(outer)
	if err != nil || len(outerParts) != 3 || !isASN1Sequence(outerParts[0]) ||
		!isASN1Sequence(outerParts[1]) || !isASN1Primitive(outerParts[2], asn1.TagBitString) ||
		!bytes.Equal(outerParts[0].FullBytes, crl.RawTBSRevocationList) {
		return pkiFormatError("CRL outer ASN.1 structure contains unsupported data")
	}
	tbsParts, err := sequenceParts(outerParts[0])
	if err != nil || len(tbsParts) < 4 || !isASN1Primitive(tbsParts[0], asn1.TagInteger) ||
		!isASN1Sequence(tbsParts[1]) || !isASN1Sequence(tbsParts[2]) || !isASN1Time(tbsParts[3]) {
		return pkiFormatError("CRL TBSCertList structure is malformed")
	}
	version, err := parseASN1Int(tbsParts[0])
	if err != nil || version != 1 {
		return pkiFormatError("only X.509 v2 CRLs are supported")
	}
	if !bytes.Equal(tbsParts[1].FullBytes, outerParts[1].FullBytes) {
		return pkiFormatError("CRL inner and outer signature algorithms differ")
	}
	index := 4
	if index < len(tbsParts) && isASN1Time(tbsParts[index]) {
		index++
	}
	if index < len(tbsParts) && isASN1Sequence(tbsParts[index]) {
		entries, err := sequenceParts(tbsParts[index])
		if err != nil {
			return pkiFormatError("CRL revokedCertificates sequence is malformed")
		}
		for _, entry := range entries {
			if err := validateRawCRLEntry(entry); err != nil {
				return err
			}
		}
		index++
	}
	if index < len(tbsParts) {
		value := tbsParts[index]
		if value.Class != asn1.ClassContextSpecific || value.Tag != 0 || !value.IsCompound {
			return pkiFormatError("CRL TBSCertList has an unsupported trailing field")
		}
		wrapped, err := parseASN1Full(value.Bytes)
		if err != nil || !isASN1Sequence(wrapped) {
			return pkiFormatError("CRL extensions wrapper is malformed")
		}
		if err := validateRawExtensionSequence(wrapped); err != nil {
			return err
		}
		index++
	}
	if index != len(tbsParts) {
		return pkiFormatError("CRL TBSCertList contains trailing ASN.1 fields")
	}
	return nil
}

func validateRawCRLEntry(entry asn1.RawValue) error {
	if !isASN1Sequence(entry) {
		return pkiFormatError("CRL entry is not a sequence")
	}
	parts, err := sequenceParts(entry)
	if err != nil || len(parts) < 2 || len(parts) > 3 || !isASN1Primitive(parts[0], asn1.TagInteger) || !isASN1Time(parts[1]) {
		return pkiFormatError("CRL entry ASN.1 structure is malformed")
	}
	if len(parts) == 3 {
		if !isASN1Sequence(parts[2]) {
			return pkiFormatError("CRL entry extensions are malformed")
		}
		return validateRawExtensionSequence(parts[2])
	}
	return nil
}

func validateRawExtensionSequence(sequence asn1.RawValue) error {
	extensions, err := sequenceParts(sequence)
	if err != nil {
		return pkiFormatError("extension sequence is malformed")
	}
	for _, extension := range extensions {
		if !isASN1Sequence(extension) {
			return pkiFormatError("extension is not a sequence")
		}
		fields, err := sequenceParts(extension)
		if err != nil || (len(fields) != 2 && len(fields) != 3) || !isASN1Primitive(fields[0], asn1.TagOID) {
			return pkiFormatError("extension ASN.1 structure is malformed")
		}
		valueIndex := 1
		if len(fields) == 3 {
			if !isASN1Primitive(fields[1], asn1.TagBoolean) {
				return pkiFormatError("extension critical flag is malformed")
			}
			var critical bool
			rest, err := asn1.Unmarshal(fields[1].FullBytes, &critical)
			if err != nil || len(rest) != 0 || !critical {
				return pkiFormatError("extension explicit default critical flag is malformed")
			}
			valueIndex = 2
		}
		if !isASN1Primitive(fields[valueIndex], asn1.TagOctetString) {
			return pkiFormatError("extension value is malformed")
		}
	}
	return nil
}

func isASN1Time(value asn1.RawValue) bool {
	return isASN1Primitive(value, asn1.TagUTCTime) || isASN1Primitive(value, asn1.TagGeneralizedTime)
}

func isFullScopeIssuingDistributionPoint(der []byte) bool {
	sequence, err := parseASN1Full(der)
	if err != nil || !isASN1Sequence(sequence) {
		return false
	}
	parts, err := sequenceParts(sequence)
	return err == nil && len(parts) == 0
}

func validateCRLEntryExtensions(extensions []pkix.Extension) error {
	if err := uniqueExtensionOIDs(extensions); err != nil {
		return pkiFormatError("CRL entry contains duplicate extensions")
	}
	for _, extension := range extensions {
		if extension.Id.Equal(oidCertificateIssuerParser) {
			return pkiFormatError("indirect CRLs are not supported")
		}
		if !extension.Id.Equal(oidCRLReasonParser) || extension.Critical {
			return pkiFormatError("CRL entry contains an unsupported extension")
		}
	}
	return nil
}

func importedCRLReason(reason int) (domain.RevocationReason, bool) {
	switch reason {
	case 0:
		return domain.RevocationReasonUnspecified, true
	case 1:
		return domain.RevocationReasonKeyCompromise, true
	case 2:
		return domain.RevocationReasonCACompromise, true
	case 3:
		return domain.RevocationReasonAffiliationChanged, true
	case 4:
		return domain.RevocationReasonSuperseded, true
	case 5:
		return domain.RevocationReasonCessationOfOperation, true
	case 9:
		return domain.RevocationReasonPrivilegeWithdrawn, true
	case 10:
		return domain.RevocationReasonAACompromise, true
	default:
		// certificateHold, removeFromCRL, and unknown codes are outside MVP.
		return "", false
	}
}

func uniqueExtensionOIDs(extensions []pkix.Extension) error {
	seen := make(map[string]struct{}, len(extensions))
	for _, extension := range extensions {
		key := extension.Id.String()
		if _, ok := seen[key]; ok {
			return errors.New("duplicate extension")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func parseAlgorithmIdentifier(raw asn1.RawValue) (pkix.AlgorithmIdentifier, error) {
	if !isASN1Sequence(raw) {
		return pkix.AlgorithmIdentifier{}, errors.New("algorithm identifier is not a sequence")
	}
	parts, err := sequenceParts(raw)
	if err != nil || len(parts) < 1 || len(parts) > 2 || !isASN1Primitive(parts[0], asn1.TagOID) {
		return pkix.AlgorithmIdentifier{}, errors.New("algorithm identifier is malformed")
	}
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(parts[0].FullBytes, &oid); err != nil || len(rest) != 0 {
		return pkix.AlgorithmIdentifier{}, errors.New("algorithm identifier OID is malformed")
	}
	result := pkix.AlgorithmIdentifier{Algorithm: oid}
	if len(parts) == 2 {
		parameter := parts[1]
		result.Parameters = asn1.RawValue{Class: parameter.Class, Tag: parameter.Tag, IsCompound: parameter.IsCompound, Bytes: parameter.Bytes, FullBytes: parameter.FullBytes}
	}
	return result, nil
}

func aesCBCKeySize(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidAES128CBCParser):
		return 16, true
	case oid.Equal(oidAES192CBCParser):
		return 24, true
	case oid.Equal(oidAES256CBCParser):
		return 32, true
	default:
		return 0, false
	}
}

func parseASN1Full(der []byte) (asn1.RawValue, error) {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(der, &value)
	if err != nil || len(rest) != 0 || !bytes.Equal(value.FullBytes, der) {
		return asn1.RawValue{}, errors.New("ASN.1 value must consume all input")
	}
	return value, nil
}

func sequenceParts(sequence asn1.RawValue) ([]asn1.RawValue, error) {
	if !isASN1Sequence(sequence) {
		return nil, errors.New("ASN.1 value is not a sequence")
	}
	content := sequence.Bytes
	parts := make([]asn1.RawValue, 0, 4)
	for len(content) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(content, &value)
		if err != nil || len(rest) >= len(content) {
			return nil, errors.New("ASN.1 sequence contains malformed content")
		}
		parts = append(parts, value)
		content = rest
	}
	return parts, nil
}

func parseASN1Int(value asn1.RawValue) (int, error) {
	if !isASN1Primitive(value, asn1.TagInteger) {
		return 0, errors.New("ASN.1 value is not an integer")
	}
	var result int
	rest, err := asn1.Unmarshal(value.FullBytes, &result)
	if err != nil || len(rest) != 0 {
		return 0, errors.New("ASN.1 integer is invalid")
	}
	return result, nil
}

func isASN1Sequence(value asn1.RawValue) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence && value.IsCompound
}

func isASN1Primitive(value asn1.RawValue, tag int) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == tag && !value.IsCompound
}

func decodePEMSequence(data []byte, allowedType string) ([][]byte, error) {
	var blocks [][]byte
	remaining := data
	for {
		remaining = trimASCIIWhitespace(remaining)
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return nil, errors.New("unexpected bytes around PEM blocks")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != allowedType || len(block.Headers) != 0 {
			return nil, errors.New("unsupported PEM block")
		}
		blocks = append(blocks, block.Bytes)
		remaining = rest
	}
	return blocks, nil
}

func decodeOnePEM(data []byte, allowedTypes ...string) ([]byte, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("PEM headers are unsupported")
	}
	for _, allowed := range allowedTypes {
		if block.Type == allowed {
			return block.Bytes, nil
		}
	}
	return nil, errors.New("unsupported PEM block type")
}

func decodePEMBlock(data []byte) (*pem.Block, error) {
	remaining := trimASCIIWhitespace(data)
	if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
		return nil, errors.New("input is not PEM")
	}
	block, rest := pem.Decode(remaining)
	if block == nil {
		return nil, errors.New("PEM must contain exactly one headerless block")
	}
	if len(trimASCIIWhitespace(rest)) != 0 {
		zeroPKIBytes(block.Bytes)
		return nil, errors.New("PEM must contain exactly one headerless block")
	}
	return block, nil
}

func looksLikePEM(data []byte) bool {
	return bytes.HasPrefix(trimASCIIWhitespace(data), []byte("-----BEGIN "))
}

func trimASCIIWhitespace(data []byte) []byte {
	for len(data) > 0 {
		switch data[0] {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			data = data[1:]
		default:
			return data
		}
	}
	return data
}

func isASCII(data []byte) bool {
	for _, value := range data {
		if value > 0x7f {
			return false
		}
	}
	return true
}

func checkPKIContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("cryptoformats: context is required")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cryptoformats: operation canceled: %w", err)
	}
	return nil
}

func pkiFormatError(message string) error {
	return fmt.Errorf("cryptoformats: %s: %w", message, domain.ErrInvalidValue)
}

func zeroPKIBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
