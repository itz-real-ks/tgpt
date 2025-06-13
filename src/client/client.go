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

// Added custom certificates loading blocks, specially for **_Termux users only_**
// Connections needed to be routed with server certificates verification from new cert.pem at {for Termux only}

// PATH for cert.pem {for Termux} : /data/data/com.termux/files/usr/etc/tls/cert.pem 
// Can visit Termux Repo ca-certificates at : https://github.com/termux/termux-packages/commit/3fc73b7527adaf774a577d9d6ac821ed507c2350#diff-9b1a45da670f05621c90785244d7d25cc4616f1eccb0f85991e7052cab0400dcR6
// Download new cacert.pem at https://curl.se/ca/cacert.pem

// 🔒 Load Custom Cert Pool
func loadCustomCertPool() (*x509.CertPool, error) {
    // 📝 Define possible cert.pem paths
    paths := []string{
        os.ExpandEnv("$PREFIX/etc/tls/cert.pem"),
        "/data/data/com.termux/files/usr/etc/tls/cert.pem",
    }

    // 🔍 Search for cert.pem in defined paths
    for _, p := range paths {
        if info, err := os.Stat(p); err == nil && !info.IsDir() {
            pemData, err := os.ReadFile(p)
            if err != nil {
                return nil, fmt.Errorf("cannot read %s: %w", p, err)
            }
            pool := x509.NewCertPool()
            if !pool.AppendCertsFromPEM(pemData) {
                return nil, fmt.Errorf("failed to parse certs from %s", p)
            }
            fmt.Printf("📈 Loaded custom CA pool from %s\n", p)
            return pool, nil
        }
    }

    // 🤔 Custom cert not found, fallback to system CAs
    fmt.Println("🔍 Custom cert not found, using system CAs")
    return nil, nil
}

// 📈 New Client
func NewClient() (tls_client.HttpClient, error) {
    // ⚙️ Define client options
    opts := []tls_client.HttpClientOption{
        tls_client.WithTimeoutSeconds(600),
        tls_client.WithClientProfile(profiles.Firefox_110),
        tls_client.WithNotFollowRedirects(),
        tls_client.WithCookieJar(tls_client.NewCookieJar()),
        // tls_client.WithInsecureSkipVerify(),
    }

    // 🔒 Load custom cert pool
    pool, err := loadCustomCertPool()
    if err != nil {
        return nil, err
    }

    // 📈 Add custom cert pool to client options if available
    if pool != nil {
        idle := 30 * time.Second
        transports := &tls_client.TransportOptions{
            RootCAs:           pool,
            IdleConnTimeout:   &idle,
            MaxIdleConns:      10,
            MaxIdleConnsPerHost: 5,
        }
        opts = append(opts, tls_client.WithTransportOptions(transports))
    }

    // 📈 Create new TLS client
    client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
    if err != nil {
        return nil, fmt.Errorf("failed to make TLS client: %w", err)
    }
    return client, nil
}
