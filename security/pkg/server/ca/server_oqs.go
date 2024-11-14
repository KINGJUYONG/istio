package ca

import (
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/pki/ca"
	caerror "istio.io/istio/security/pkg/pki/error"
	"istio.io/istio/security/pkg/pki/util"
)

func (s *Server) CreateOQSCertificate(ctx context.Context, request *pb.IstioCertificateRequest) (
	*pb.IstioCertificateResponse, error,
) {

	s.monitoring.CSR.Increment()
	caller, err := security.Authenticate(ctx, s.Authenticators)
	if caller == nil || err != nil {
		s.monitoring.AuthnError.Increment()
		return nil, status.Error(codes.Unauthenticated, "request authenticate failure")
	}

	serverCaLog := serverCaLog.WithLabels("client", security.GetConnectionAddress(ctx))
	// By default, we will use the callers identity for the certificate
	serverCaLog.Infof("OQSCertificate")
	sans := caller.Identities
	crMetadata := request.Metadata.GetFields()
	impersonatedIdentity := crMetadata[security.ImpersonatedIdentity].GetStringValue()
	if impersonatedIdentity != "" {
		serverCaLog.Debugf("impersonated identity: %s", impersonatedIdentity)
		// If there is an impersonated identity, we will override to use that identity (only single value
		// supported), if the real caller is authorized.
		if s.nodeAuthorizer == nil {
			s.monitoring.AuthnError.Increment()
			// Return an opaque error (for security purposes) but log the full reason
			serverCaLog.Warnf("impersonation not allowed, as node authorizer is not configured")
			return nil, status.Error(codes.Unauthenticated, "request impersonation authentication failure")

		}
		if err := s.nodeAuthorizer.authenticateImpersonation(caller.KubernetesInfo, impersonatedIdentity); err != nil {
			s.monitoring.AuthnError.Increment()
			// Return an opaque error (for security purposes) but log the full reason
			serverCaLog.Warnf("impersonation failed: %v", err)
			return nil, status.Error(codes.Unauthenticated, "request impersonation authentication failure")
		}
		// Node is authorized to impersonate; overwrite the SAN to the impersonated identity.
		sans = []string{impersonatedIdentity}
	}
	serverCaLog.Debugf("generating a certificate, sans: %v, requested ttl: %s", sans, time.Duration(request.ValidityDuration*int64(time.Second)))
	certSigner := crMetadata[security.CertSigner].GetStringValue()
	_, _, certChainBytes, rootCertBytes := s.ca.GetCAKeyCertBundle().GetAll()
	certOpts := ca.CertOpts{
		SubjectIDs: sans,
		TTL:        time.Duration(request.ValidityDuration) * time.Second,
		ForCA:      false,
		CertSigner: certSigner,
	}
	var signErr error
	var cert []byte
	var respCertChain []string

	if certSigner == "" {
		cert, signErr = s.ca.OQSSign([]byte(request.Csr), certOpts)
	} else {
		serverCaLog.Debugf("signing CSR with cert chain")
		respCertChain, signErr = s.ca.SignWithCertChain([]byte(request.Csr), certOpts)
	}
	if signErr != nil {
		serverCaLog.Errorf("CSR signing error: %v", signErr.Error())
		s.monitoring.GetCertSignError(signErr.(*caerror.Error).ErrorType()).Increment()
		return nil, status.Errorf(signErr.(*caerror.Error).HTTPErrorCode(), "CSR signing error (%v)", signErr.(*caerror.Error))
	}
	if certSigner == "" {
		respCertChain = []string{string(cert)}
		if len(certChainBytes) != 0 {
			respCertChain = append(respCertChain, string(certChainBytes))
			serverCaLog.Debugf("Append cert chain to response, %s", string(certChainBytes))
		}
	}
	if len(rootCertBytes) != 0 {
		respCertChain = append(respCertChain, string(rootCertBytes))
	}
	response := &pb.IstioCertificateResponse{
		CertChain: respCertChain,
	}
	s.monitoring.Success.Increment()
	serverCaLog.Debugf("CSR successfully signed, sans %v.", caller.Identities)
	return response, nil
}

func recordCertsExpiry(keyCertBundle *util.KeyCertBundle) {
	rootCertExpiry, err := keyCertBundle.ExtractRootCertExpiryTimestamp()
	if err != nil {
		serverCaLog.Errorf("failed to extract root cert expiry timestamp (error %v)", err)
	}
	rootCertExpiryTimestamp.Record(rootCertExpiry)

	if len(keyCertBundle.GetCertChainPem()) == 0 {
		return
	}

	certChainExpiry, err := keyCertBundle.ExtractCACertExpiryTimestamp()
	if err != nil {
		serverCaLog.Errorf("failed to extract CA cert expiry timestamp (error %v)", err)
	}
	certChainExpiryTimestamp.Record(certChainExpiry)
}
