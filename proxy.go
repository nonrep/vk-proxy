package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	e.Any("/*", proxyHandler)
	e.Logger.Fatal(e.Start(":8080"))
}

func proxyHandler(c echo.Context) error {
	req := c.Request()

	if req.Method == http.MethodConnect {
		return handleHTTPS(c)
	}

	return handleHTTP(c)
}

func handleHTTP(c echo.Context) error {
	req := c.Request()
	resp := c.Response()

	targetURLStr := req.RequestURI
	if targetURLStr == "" || !strings.HasPrefix(targetURLStr, "http://") && !strings.HasPrefix(targetURLStr, "https://") {
		return c.String(http.StatusBadRequest, "Invalid target URL")
	}

	targetURL, err := url.ParseRequestURI(targetURLStr)
	if err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("Failed to parse target URL: %v", err))
	}

	proxyReq, err := http.NewRequest(req.Method, targetURL.String(), req.Body)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to create proxy request: %v", err))
	}

	for name, values := range req.Header {
		if name != "Proxy-Connection" {
			for _, value := range values {
				proxyReq.Header.Add(name, value)
			}
		}
	}

	proxyReq.URL.Path = targetURL.Path
	proxyReq.URL.RawQuery = targetURL.RawQuery
	proxyReq.RequestURI = ""
	proxyReq.Host = targetURL.Host

	var conn net.Conn
	if targetURL.Scheme == "https" {
		conn, err = tls.Dial("tcp", targetURL.Host+":443", &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.Dial("tcp", targetURL.Host+":80")
	}
	if err != nil {
		log.Printf("dial failed: %v", err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to connect to target server: %v", err))
	}
	defer conn.Close()

	err = proxyReq.Write(conn)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to write request to target server: %v", err))
	}

	bufReader := bufio.NewReader(conn)
	proxyResp, err := http.ReadResponse(bufReader, proxyReq)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to read response from target server: %v", err))
	}
	defer proxyResp.Body.Close()

	for name, values := range proxyResp.Header {
		for _, value := range values {
			resp.Header().Add(name, value)
		}
	}

	resp.Header().Set("Connection", "close")
	resp.WriteHeader(proxyResp.StatusCode)
	_, err = io.Copy(resp, proxyResp.Body)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to copy response body: %v", err))
	}

	return nil
}

func handleHTTPS(c echo.Context) error {
	req := c.Request()
	resp := c.Response()

	hostPort := req.Host
	if hostPort == "" {
		hostPort = req.URL.Host
	}
	if hostPort == "" {
		return c.String(http.StatusBadRequest, "No host specified in CONNECT")
	}

	hijacker, ok := resp.Writer.(http.Hijacker)
	if !ok {
		return c.String(http.StatusInternalServerError, "Hijacking not supported")
	}

	resp.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to hijack connection: %v", err))
	}
	defer clientConn.Close()

	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		hostPort = net.JoinHostPort(host, "443")
	}

	remoteConn, err := net.Dial("tcp", hostPort)
	if err != nil {
		return c.String(http.StatusServiceUnavailable, fmt.Sprintf("Failed to connect to remote: %v", err))
	}
	defer remoteConn.Close()

	cert, err := GenerateCert(host, big.NewInt(time.Now().UnixNano()))
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to generate certificate: %v", err))
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer tlsClientConn.Close()

	tlsRemoteConn := tls.Client(remoteConn, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsRemoteConn.Close()

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(tlsClientConn, tlsRemoteConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(tlsRemoteConn, tlsClientConn)
		errChan <- err
	}()

	<-errChan

	return nil
}

func GenerateCert(domain string, serial *big.Int) (tls.Certificate, error) {
	scriptPath := "internal/scripts/gen_cert.sh"

	err := os.Chmod(scriptPath, 0755)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to make script executable: %w", err)
	}

	cmd := exec.Command(scriptPath, domain, fmt.Sprintf("%d", serial))

	var certOut bytes.Buffer
	cmd.Stdout = &certOut

	if err := cmd.Run(); err != nil {
		return tls.Certificate{}, fmt.Errorf("script execution failed: %w", err)
	}

	certPEM := certOut.Bytes()

	keyPEM, err := os.ReadFile("certs/cert.key")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key file: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create X509 key pair: %w", err)
	}

	_, err = x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return tlsCert, nil
}
