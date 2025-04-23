package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"
)

var db *sqlx.DB

type RequestRecord struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	GetParams  map[string]string `json:"get_params"`
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	PostParams map[string]string `json:"post_params"`
	Body       string            `json:"body"`
}

type ResponseRecord struct {
	Code    int               `json:"code"`
	Message string            `json:"message"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type Record struct {
	ID        int            `db:"id"`
	Request   RequestRecord  `db:"request"`
	Response  ResponseRecord `db:"response"`
	Timestamp time.Time      `db:"timestamp"`
}

func main() {
	initDB()
	defer db.Close()

	e := echo.New()
	e.Any("/*", proxyHandler)
	e.Logger.Fatal(e.Start(":8080"))
}

func initDB() {
	var err error
	connStr := "host=db user=postgres password=postgres dbname=postgres port=5432 sslmode=disable"
	db, err = sqlx.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to open database connection:", err)
	}

	for i := 0; i < 10; i++ {
		err = db.Ping()
		if err == nil {
			break
		}
		log.Printf("Database not ready yet, retrying... (attempt %d/10)", i+1)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatal("Failed to connect to database after retries:", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS records (
			id SERIAL PRIMARY KEY,
			request JSONB NOT NULL,
			response JSONB NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	log.Println("Database connection established successfully")
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

	requestRecord, err := parseRequest(req, targetURL)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to parse request: %v", err))
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

	responseRecord, err := parseResponse(proxyResp)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to parse response: %v", err))
	}

	err = saveRecord(requestRecord, responseRecord)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to save record: %v", err))
	}

	scanForSQLInjection(requestRecord, responseRecord)

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

func parseRequest(req *http.Request, targetURL *url.URL) (RequestRecord, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	getParams := make(map[string]string)
	for key, values := range targetURL.Query() {
		if len(values) > 0 {
			getParams[key] = values[0]
		}
	}

	headers := make(map[string]string)
	for key, values := range req.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	cookies := make(map[string]string)
	for _, cookie := range req.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	postParams := make(map[string]string)
	if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(bodyBytes))
		if err == nil {
			for key, vals := range values {
				if len(vals) > 0 {
					postParams[key] = vals[0]
				}
			}
		}
	}

	return RequestRecord{
		Method:     req.Method,
		Path:       targetURL.Path,
		GetParams:  getParams,
		Headers:    headers,
		Cookies:    cookies,
		PostParams: postParams,
		Body:       string(bodyBytes),
	}, nil
}

func parseResponse(resp *http.Response) (ResponseRecord, error) {
	var bodyBytes []byte
	var err error

	// Handle compressed responses
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return ResponseRecord{}, err
		}
		defer reader.Close()
		bodyBytes, _ = io.ReadAll(reader)
	case "deflate":
		reader, err := zlib.NewReader(resp.Body)
		if err != nil {
			return ResponseRecord{}, err
		}
		defer reader.Close()
		bodyBytes, _ = io.ReadAll(reader)
	default:
		bodyBytes, err = io.ReadAll(resp.Body)
	}

	if err != nil {
		return ResponseRecord{}, err
	}

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return ResponseRecord{
		Code:    resp.StatusCode,
		Message: resp.Status,
		Headers: headers,
		Body:    string(bodyBytes),
	}, nil
}

func saveRecord(request RequestRecord, response ResponseRecord) error {
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return err
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO records (request, response) VALUES ($1, $2)", requestJSON, responseJSON)
	return err
}

func scanForSQLInjection(request RequestRecord, originalResponse ResponseRecord) {
	for param, value := range request.GetParams {
		testSQLInjection(param, value, "GET parameter", originalResponse)
	}

	for param, value := range request.PostParams {
		testSQLInjection(param, value, "POST parameter", originalResponse)
	}

	for param, value := range request.Cookies {
		testSQLInjection(param, value, "Cookie", originalResponse)
	}

	for param, value := range request.Headers {
		testSQLInjection(param, value, "Header", originalResponse)
	}
}

func testSQLInjection(param, value, paramType string, _ ResponseRecord) {
	payloads := []string{"'", "\"", "'; --", "\"; --", "' OR '1'='1"}

	for _, payload := range payloads {
		modifiedValue := value + payload

		if strings.Contains(modifiedValue, "'") || strings.Contains(modifiedValue, "\"") {
			log.Printf("Testing %s %s=%s for SQL injection", paramType, param, modifiedValue)
		}
	}
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
