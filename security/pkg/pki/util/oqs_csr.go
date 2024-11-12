package util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func createOQSCertificateRequest(rand io.Reader, template *x509.CertificateRequest, publicKeyBytes []byte, signer *oqs.Signature) (csr []byte, err error) {
	publicKeyAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 772, 1, 2}, // Dilithum OID
		Parameters: asn1.RawValue{FullBytes: []byte{5, 0}},
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0,
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: []asn1.RawValue{},
	}

	tbsBytes, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(tbsBytes)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR: tbsCSR,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 772, 1, 2}, // Dilithum OID
			Parameters: asn1.RawValue{FullBytes: []byte{5, 0}},
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
