package cryptoformats

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// parsedCRL holds the common facts needed from either the MVP-supported
// X.509 v2 CRL form or a legacy v1 CRL with no extensions.
type parsedCRL struct {
	v2             *x509.RevocationList
	v1             *pkix.CertificateList
	issuer         pkix.Name
	issuerDER      []byte
	authorityKeyID []byte
	number         *big.Int
	thisUpdate     time.Time
	nextUpdate     time.Time
	entries        []x509.RevocationListEntry
	crlExtensions  []pkix.Extension
}

func parseCRLDER(der []byte) (*parsedCRL, error) {
	if len(der) == 0 {
		return nil, errors.New("empty CRL")
	}
	if list, err := x509.ParseRevocationList(der); err == nil && bytes.Equal(list.Raw, der) {
		return &parsedCRL{
			v2: list, issuer: list.Issuer, issuerDER: append([]byte(nil), list.RawIssuer...),
			authorityKeyID: append([]byte(nil), list.AuthorityKeyId...), number: cloneBigInt(list.Number),
			thisUpdate: list.ThisUpdate, nextUpdate: list.NextUpdate,
			entries:       append([]x509.RevocationListEntry(nil), list.RevokedCertificateEntries...),
			crlExtensions: append([]pkix.Extension(nil), list.Extensions...),
		}, nil
	}

	var list pkix.CertificateList
	rest, err := asn1.Unmarshal(der, &list)
	if err != nil || len(rest) != 0 || list.TBSCertList.Version != 0 ||
		list.TBSCertList.Raw == nil || len(list.TBSCertList.Extensions) != 0 {
		return nil, errors.New("CRL is neither a supported v2 CRL nor an extension-free v1 CRL")
	}
	innerAlgorithm, err := asn1.Marshal(list.TBSCertList.Signature)
	if err != nil {
		return nil, errors.New("CRL inner signature algorithm is invalid")
	}
	outerAlgorithm, err := asn1.Marshal(list.SignatureAlgorithm)
	if err != nil || !bytes.Equal(innerAlgorithm, outerAlgorithm) {
		return nil, errors.New("CRL inner and outer signature algorithms differ")
	}
	issuerDER, err := asn1.Marshal(list.TBSCertList.Issuer)
	if err != nil {
		return nil, errors.New("CRL issuer name is invalid")
	}
	issuer := pkix.Name{}
	issuer.FillFromRDNSequence(&list.TBSCertList.Issuer)
	entries := make([]x509.RevocationListEntry, 0, len(list.TBSCertList.RevokedCertificates))
	for _, old := range list.TBSCertList.RevokedCertificates {
		if old.SerialNumber == nil || old.RevocationTime.IsZero() || len(old.Extensions) != 0 {
			return nil, errors.New("v1 CRL contains invalid or unsupported entry data")
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber: old.SerialNumber, RevocationTime: old.RevocationTime, ReasonCode: 0,
		})
	}
	return &parsedCRL{
		v1: &list, issuer: issuer, issuerDER: issuerDER,
		thisUpdate: list.TBSCertList.ThisUpdate, nextUpdate: list.TBSCertList.NextUpdate,
		entries: entries,
	}, nil
}

func (p *parsedCRL) checkSignatureFrom(issuer *x509.Certificate) error {
	if p == nil || issuer == nil {
		return errors.New("CRL and issuer are required")
	}
	if p.v2 != nil {
		return p.v2.CheckSignatureFrom(issuer)
	}
	if p.v1 != nil {
		return issuer.CheckCRLSignature(p.v1)
	}
	return errors.New("CRL version is unsupported")
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}
