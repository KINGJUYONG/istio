package util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
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

	var oqsKey *OQSPrivateKey
	var algorithm string

	switch k := priv.(type) {
	case *OQSPrivateKey:
		oqsKey = k
		// algorithm = k.Algorithm
	case oqs.Signature:
		oqsKey = &OQSPrivateKey{Sig: &k}
		return nil, fmt.Errorf("x509: oqs.Signature: %T", priv)
	case *oqs.Signature:
		return nil, fmt.Errorf("x509: *oqs.Signature: %T", priv)
	case crypto.PrivateKey:
		return nil, fmt.Errorf("x509: crypto.PrivateKey: %T", priv)
	default:
		return nil, fmt.Errorf("x509: (%s / %s)unsupported private key type: %T", k, algorithm, priv)
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

func GenOQSCertKeyFromOptions(options CertOptions) (pemCert []byte, pemKey []byte, err error) {
	// Check for OQS algorithm first
	if options.IsOQS {
		sig := &oqs.Signature{}
		if err := sig.Init(options.OQSAlgorithm, nil); err != nil {
			return nil, nil, fmt.Errorf("cert generation fails at OQS initialization (%v)", err)
		}

		pubKey, err := sig.GenerateKeyPair()
		if err != nil {
			return nil, nil, fmt.Errorf("cert generation fails at OQS key generation (%v)", err)
		}

		oqsPriv := &OQSPrivateKey{
			Sig: sig,
		}
		return genCert(options, oqsPriv, pubKey)
	}

	// Existing ECDSA logic
	if options.ECSigAlg != "" {
		var ecPriv *ecdsa.PrivateKey

		switch options.ECSigAlg {
		case EcdsaSigAlg:
			var curve elliptic.Curve
			switch options.ECCCurve {
			case P384Curve:
				curve = elliptic.P384()
			default:
				curve = elliptic.P256()
			}

			ecPriv, err = ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				return nil, nil, fmt.Errorf("cert generation fails at EC key generation (%v)", err)
			}

		default:
			return nil, nil, errors.New("cert generation fails due to unsupported EC signature algorithm")
		}
		return genCert(options, ecPriv, &ecPriv.PublicKey)
	}

	// Existing RSA logic
	if options.RSAKeySize < minimumRsaKeySize {
		return nil, nil, fmt.Errorf("requested key size does not meet the minimum required size of %d (requested: %d)",
			minimumRsaKeySize, options.RSAKeySize)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, options.RSAKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("cert generation fails at RSA key generation (%v)", err)
	}
	return genCert(options, rsaPriv, &rsaPriv.PublicKey)
}
