package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jkoelker/schwab-proxy/log"
	tlspkg "github.com/jkoelker/schwab-proxy/tls"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	t.Parallel()

	cert, err := tlspkg.GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Error("No certificate data generated")
	}

	if cert.PrivateKey == nil {
		t.Error("No private key generated")
	}
}

func TestManagerWithSelfSigned(t *testing.T) {
	t.Parallel()

	// Test manager with no cert files (should use self-signed)
	manager := tlspkg.NewManager("", "")

	ctx := setupTestLogging(t)

	err := manager.Initialize(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize manager: %v", err)
	}

	// Test GetCertificate
	cert, err := manager.GetCertificate(nil)
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	if cert == nil {
		t.Error("Certificate is nil")
	}
}

// generateTestCertFiles creates test certificate and key files for testing.
func generateTestCertFiles(certPath, keyPath string) error {
	// Generate key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Generate certificate with random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate file
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Write key file
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

func TestManagerWithFiles(t *testing.T) {
	t.Parallel()

	// Create temporary directory for test certificates
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate test certificate files
	if err := generateTestCertFiles(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate files: %v", err)
	}

	// Test manager with the files
	manager := tlspkg.NewManager(certPath, keyPath)
	ctx := setupTestLogging(t)

	err := manager.Initialize(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize manager with files: %v", err)
	}

	// Test GetCertificate
	loadedCert, err := manager.GetCertificate(nil)
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	if loadedCert == nil {
		t.Fatal("Certificate is nil")
	}

	// Verify certificate has expected properties
	if len(loadedCert.Certificate) == 0 {
		t.Error("No certificate data")
	}

	if loadedCert.PrivateKey == nil {
		t.Error("No private key")
	}
}

func TestTLSConfig(t *testing.T) {
	t.Parallel()

	manager := tlspkg.NewManager("", "")
	ctx := setupTestLogging(t)

	err := manager.Initialize(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize manager: %v", err)
	}

	config := manager.Config()

	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %v", config.MinVersion)
	}

	if config.GetCertificate == nil {
		t.Error("GetCertificate function is nil")
	}

	if len(config.CipherSuites) == 0 {
		t.Error("No cipher suites configured")
	}
}

func TestCertificateReload(t *testing.T) {
	t.Parallel()

	certPath, keyPath := setupCertificateFiles(t)
	manager := initializeManager(t, certPath, keyPath)
	initialCert := getCertificate(t, manager, "initial")

	regenerateCertificateFiles(t, certPath, keyPath)
	reloadCertificate(t, manager)
	newCert := getCertificate(t, manager, "new")

	verifyCertificatesAreDifferent(t, initialCert, newCert)
}

// setupCertificateFiles creates temporary certificate files for testing.
func setupCertificateFiles(t *testing.T) (string, string) {
	t.Helper()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	if err := generateTestCertFiles(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate files: %v", err)
	}

	return certPath, keyPath
}

// initializeManager creates and initializes a TLS manager.
func initializeManager(t *testing.T, certPath, keyPath string) *tlspkg.Manager {
	t.Helper()

	manager := tlspkg.NewManager(certPath, keyPath)
	ctx := setupTestLogging(t)

	if err := manager.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize manager: %v", err)
	}

	return manager
}

// getCertificate retrieves a certificate from the manager.
func getCertificate(t *testing.T, manager *tlspkg.Manager, description string) *tls.Certificate {
	t.Helper()

	cert, err := manager.GetCertificate(nil)
	if err != nil {
		t.Fatalf("Failed to get %s certificate: %v", description, err)
	}

	return cert
}

// regenerateCertificateFiles creates new certificate files.
func regenerateCertificateFiles(t *testing.T, certPath, keyPath string) {
	t.Helper()

	if err := generateTestCertFiles(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate new certificate files: %v", err)
	}
}

// reloadCertificate triggers a certificate reload.
func reloadCertificate(t *testing.T, manager *tlspkg.Manager) {
	t.Helper()

	ctx := setupTestLogging(t)
	if err := manager.ReadCertificate(ctx); err != nil {
		t.Fatalf("Failed to reload certificate: %v", err)
	}
}

// verifyCertificatesAreDifferent ensures two certificates have different serial numbers.
func verifyCertificatesAreDifferent(t *testing.T, initialCert, newCert *tls.Certificate) {
	t.Helper()

	if len(initialCert.Certificate) == 0 || len(newCert.Certificate) == 0 {
		t.Fatal("Certificate data is missing")
	}

	initialX509, err := x509.ParseCertificate(initialCert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse initial certificate: %v", err)
	}

	newX509, err := x509.ParseCertificate(newCert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse new certificate: %v", err)
	}

	if initialX509.SerialNumber.Cmp(newX509.SerialNumber) == 0 {
		t.Error("Certificate was not reloaded - serial numbers are the same")
	}
}

// setupTestLogging creates a context with a test logger that outputs to t.Log.
func setupTestLogging(t *testing.T) context.Context {
	t.Helper()

	// Create a custom slog handler that writes to t.Log
	handler := slog.NewTextHandler(&testLogWriter{t: t}, &slog.HandlerOptions{
		Level: slog.LevelDebug, // Show all log levels in tests
	})

	// Create logger and add it to context derived from t.Context()
	logger := slog.New(handler)

	return log.WithLogger(t.Context(), logger)
}

// testLogWriter implements io.Writer to redirect slog output to t.Log.
type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(value []byte) (int, error) {
	// Check if context is done (test has finished)
	select {
	case <-w.t.Context().Done():
		// Test context is cancelled, skip logging
		return len(value), nil
	default:
		// Context still active, safe to log
		w.t.Log(string(value))

		return len(value), nil
	}
}
