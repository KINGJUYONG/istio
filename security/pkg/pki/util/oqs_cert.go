package util

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Define OIDs for OQS algorithms
var (
	oidDilithium2    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 772, 1, 2} // Dilithium2 OID
	emptyASN1Subject = []byte{0x30, 0x00}                                 // ASN.1 Sequence, length 0
)

type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// OQSPrivateKey represents a private key for OQS signature algorithms
type OQSPrivateKey struct {
	Sig       *oqs.Signature
	PubKey    []byte
	PrivKey   []byte
	Algorithm string
}

func (k *OQSPrivateKey) Public() crypto.PublicKey {
	return k.PubKey
}

func (k *OQSPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.Sig == nil { // Now valid since Sig is a pointer
		return nil, errors.New("oqs: signature algorithm not initialized")
	}
	return k.Sig.Sign(digest)
}

func CreateCertificateWithOQS(rand io.Reader, template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
	// Verify that we're using an OQS private key
	oqsKey, isOQS := priv.(*OQSPrivateKey)
	if !isOQS {
		return nil, errors.New("x509: expected OQS private key")
	}

	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	if template.SerialNumber.Sign() == -1 {
		return nil, errors.New("x509: serial number must be positive")
	}

	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return nil, errors.New("x509: only CAs are allowed to specify MaxPathLen")
	}

	// Set up signature algorithm identifier based on OQS algorithm
	var algorithmIdentifier pkix.AlgorithmIdentifier
	switch oqsKey.Algorithm {
	case "Dilithium2":
		algorithmIdentifier.Algorithm = oidDilithium2
	default:
		return nil, errors.New("x509: unsupported OQS algorithm")
	}

	// Marshal the public key
	publicKeyBytes, publicKeyAlgorithm, err := marshalOQSPublicKey(pub, oqsKey.Algorithm)
	if err != nil {
		return nil, err
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	subjectKeyId := template.SubjectKeyId
	if len(subjectKeyId) == 0 && template.IsCA {
		h := sha1.Sum(publicKeyBytes)
		subjectKeyId = h[:]
	}

	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject),
		authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: algorithmIdentifier,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents

	// Sign using OQS algorithm directly
	signature, err := oqsKey.Sign(rand, tbsCertContents, nil)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(certificate{
		TBSCertificate:     c,
		SignatureAlgorithm: algorithmIdentifier,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// Helper functions
func subjectBytes(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return emptyASN1Subject, nil
	}
	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

func buildCertExtensions(template *x509.Certificate, subjectIsEmpty bool, authorityKeyId, subjectKeyId []byte) ([]pkix.Extension, error) {
	var extensions []pkix.Extension

	if template.KeyUsage != 0 {
		ext := pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // Key Usage OID
			Critical: true,
			Value:    []byte{3, 2, byte(template.KeyUsage)},
		}
		extensions = append(extensions, ext)
	}

	if len(subjectKeyId) > 0 {
		ext := pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14}, // Subject Key ID OID
			Value: subjectKeyId,
		}
		extensions = append(extensions, ext)
	}

	if len(authorityKeyId) > 0 {
		ext := pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35}, // Authority Key ID OID
			Value: authorityKeyId,
		}
		extensions = append(extensions, ext)
	}

	if template.BasicConstraintsValid {
		isCA := uint8(0)
		if template.IsCA {
			isCA = 255 // Using 255 (0xFF) for true
		}

		ext := pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // Basic Constraints OID
			Critical: true,
			Value:    []byte{0x30, 0x03, 0x01, 0x01, isCA},
		}
		extensions = append(extensions, ext)
	}

	return extensions, nil
}

func marshalOQSPublicKey(pub any, algorithm string) ([]byte, pkix.AlgorithmIdentifier, error) {
	oqsPub, ok := pub.([]byte)
	if !ok {
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported OQS public key type")
	}

	var oid asn1.ObjectIdentifier
	switch algorithm {
	case "Dilithium2":
		oid = oidDilithium2
	default:
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported OQS algorithm")
	}

	pkix := pkix.AlgorithmIdentifier{
		Algorithm: oid,
	}

	return oqsPub, pkix, nil
}
