package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/jkoelker/schwab-proxy/log"
)

const (
	defaultSerialBits    = 128
	oneDay               = 24 * time.Hour
	defaultWatchInterval = 10 * time.Second
)

// ErrNoCertificate is returned when no certificate is available.
var ErrNoCertificate = errors.New("no TLS certificate available")

// Manager handles TLS certificate loading and automatic reloading.
type Manager struct {
	sync.RWMutex

	certPath string
	keyPath  string

	certificate       *tls.Certificate
	cachedKeyPEMBlock []byte
	watcher           *fsnotify.Watcher
	interval          time.Duration
}

// NewManager creates a new TLS certificate manager.
func NewManager(certPath, keyPath string) *Manager {
	return &Manager{
		certPath: certPath,
		keyPath:  keyPath,
		interval: defaultWatchInterval,
	}
}

// Initialize loads the certificate and starts watching for changes.
func (m *Manager) Initialize(ctx context.Context) error {
	// Try to load from files first
	if m.certPath != "" && m.keyPath != "" {
		if err := m.ReadCertificate(ctx); err == nil {
			log.Info(ctx, "Loaded TLS certificate from files",
				"cert_path", m.certPath,
				"key_path", m.keyPath)

			// Set up file watching
			if err := m.setupWatcher(ctx); err != nil {
				log.Warn(ctx, "Failed to setup file watcher, using polling only", "error", err)
			}

			// Start watching for changes
			go m.watchForChanges(ctx)

			return nil
		}

		log.Warn(ctx, "Failed to load TLS certificate from files, will use self-signed",
			"cert_path", m.certPath,
			"key_path", m.keyPath)
	}

	// Generate self-signed certificate as fallback
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}

	m.Lock()
	m.certificate = &cert
	m.Unlock()

	log.Info(ctx, "Using self-signed TLS certificate")

	return nil
}

// GetCertificate returns the current certificate for use in tls.Config.GetCertificate.
func (m *Manager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.RLock()
	defer m.RUnlock()

	if m.certificate == nil {
		return nil, ErrNoCertificate
	}

	return m.certificate, nil
}

// Config creates a tls.Config using the certificate manager.
func (m *Manager) Config() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// ReadCertificate reads the certificate and key files from disk, parses them,
// and updates the current certificate if changed.
func (m *Manager) ReadCertificate(ctx context.Context) error {
	certPEMBlock, err := os.ReadFile(m.certPath)
	if err != nil {
		return fmt.Errorf("failed to read cert file: %w", err)
	}

	keyPEMBlock, err := os.ReadFile(m.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if !m.updateCachedCertificate(&cert, keyPEMBlock) {
		return nil
	}

	log.Info(ctx, "Updated current TLS certificate")

	return nil
}

// setupWatcher initializes the fsnotify watcher.
func (m *Manager) setupWatcher(ctx context.Context) error {
	var err error

	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Add watches for both files
	if err := m.watcher.Add(m.certPath); err != nil {
		_ = m.watcher.Close()

		return fmt.Errorf("failed to watch cert file: %w", err)
	}

	if err := m.watcher.Add(m.keyPath); err != nil {
		_ = m.watcher.Close()

		return fmt.Errorf("failed to watch key file: %w", err)
	}

	// Start the event handler
	go m.handleWatchEvents(ctx)

	return nil
}

// updateCachedCertificate checks if the new certificate differs from the
// cache, updates it and returns whether it was updated.
func (m *Manager) updateCachedCertificate(cert *tls.Certificate, keyPEMBlock []byte) bool {
	m.Lock()
	defer m.Unlock()

	if m.certificate != nil &&
		len(cert.Certificate) > 0 && len(m.certificate.Certificate) > 0 &&
		bytes.Equal(m.certificate.Certificate[0], cert.Certificate[0]) &&
		bytes.Equal(m.cachedKeyPEMBlock, keyPEMBlock) {
		return false
	}

	m.certificate = cert
	m.cachedKeyPEMBlock = keyPEMBlock

	return true
}

// watchForChanges monitors certificate files for changes using both fsnotify
// events and periodic polling.
func (m *Manager) watchForChanges(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	// Close watcher when context is done
	defer func() {
		if m.watcher != nil {
			_ = m.watcher.Close()
		}
	}()

	log.Info(ctx, "Starting certificate poll+watcher", "interval", m.interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.ReadCertificate(ctx); err != nil {
				log.Error(ctx, err, "failed to read certificate during polling")
			}
		}
	}
}

// handleWatchEvents processes file system events from fsnotify.
func (m *Manager) handleWatchEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			m.handleEvent(ctx, event)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}

			log.Error(ctx, err, "certificate watch error")
		}
	}
}

// handleEvent processes a single file system event.
func (m *Manager) handleEvent(ctx context.Context, event fsnotify.Event) {
	// Only care about events which may modify the contents of the file
	switch {
	case event.Op.Has(fsnotify.Write):
	case event.Op.Has(fsnotify.Create):
	case event.Op.Has(fsnotify.Chmod), event.Op.Has(fsnotify.Remove):
		// If the file was removed or renamed, re-add the watch
		if err := m.watcher.Add(event.Name); err != nil {
			log.Error(ctx, err, "error re-watching file", "file", event.Name)
		}
	default:
		return
	}

	log.Debug(ctx, "certificate file event", "event", event.Op.String(), "file", event.Name)

	if err := m.ReadCertificate(ctx); err != nil {
		log.Error(ctx, err, "error re-reading certificate after file event")
	}
}

// GenerateSelfSignedCert generates a self-signed certificate valid for
// 24 hours.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), defaultSerialBits))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Schwab API Proxy (Self-Signed)"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(oneDay),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},

		//nolint: mnd // The localhost IPs are well known numbers
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal EC private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create key pair: %w", err)
	}

	return pair, nil
}
