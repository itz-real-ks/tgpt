// 📦 Package client
package client

import (
    "crypto/x509"
    "fmt"
    "os"
    "time"

    tls_client "github.com/bogdanfinn/tls-client"
    "github.com/bogdanfinn/tls-client/profiles"
)

// 🔒 Load Custom Cert Pool (used for Termux or custom CA environments)
func loadCustomCertPool() (*x509.CertPool, error) {
    // 📁 Define possible cert.pem paths
    paths := []string{
        os.ExpandEnv("$PREFIX/etc/tls/cert.pem"),
        "/data/data/com.termux/files/usr/etc/tls/cert.pem",
    }

    // 🔍 Search for cert.pem in defined paths
    for _, p := range paths {
        if info, err := os.Stat(p); err == nil && !info.IsDir() {
            pemData, err := os.ReadFile(p)
            if err != nil {
                return nil, fmt.Errorf("❌ cannot read %s: %w", p, err)
            }
            pool := x509.NewCertPool()
            if !pool.AppendCertsFromPEM(pemData) {
                return nil, fmt.Errorf("❌ failed to parse certs from %s", p)
            }
            return pool, nil
        }
    }

    // ⚠️ Custom cert not found, fallback to system CAs silently
    return nil, nil
}

// 🌐 Create new TLS Client
func NewClient() (tls_client.HttpClient, error) {
    // ⚙️ Define client options
    opts := []tls_client.HttpClientOption{
        tls_client.WithTimeoutSeconds(600),
        tls_client.WithClientProfile(profiles.Firefox_110),
        tls_client.WithNotFollowRedirects(),
        tls_client.WithCookieJar(tls_client.NewCookieJar()),
        // tls_client.WithInsecureSkipVerify(), // Use only for testing!
    }

    // 🧾 Try loading custom cert pool
    pool, err := loadCustomCertPool()
    if err != nil {
        return nil, err
    }

    // 🌱 If custom cert pool is present, configure transport options
    if pool != nil {
        idle := 30 * time.Second
        transports := &tls_client.TransportOptions{
            RootCAs:             pool,
            IdleConnTimeout:     &idle,
            MaxIdleConns:        10,
            MaxIdleConnsPerHost: 5,
        }
        opts = append(opts, tls_client.WithTransportOptions(transports))
    }

    // 🚀 Create the HTTP client
    client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
    if err != nil {
        return nil, fmt.Errorf("❌ failed to make TLS client: %w", err)
    }

    return client, nil
}
