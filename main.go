// Package main implements a simple web server with HTTPS support.
package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	webrootDir         = "./static_domains" // Directory for domains and web files (the files need to be in ./static_domains/<domain>/)
	certsDir           = "./certs"          // Directory for certificates
	httpPort           = ":80"              // HTTP port
	httpsPort          = ":443"             // HTTPS port
	serverName         = "dma-srv"          // Server name
	sniffLen           = 512                // Number of bytes to sniff for file type detection
	maxFileSizeInCache = 1 << 20            // 1 MB, maximum file size to cache
)

var (
	allowedDomains []string                      // List of allowed domain names
	fileCache      = make(map[string]CachedFile) // Cache for file content
	cacheMutex     sync.RWMutex                  // Mutex for file cache
)

// CachedFile represents a cached file with its content, content type, and modification time.
type CachedFile struct {
	Content     []byte    // File content
	ContentType string    // File content type
	ModTime     time.Time // File modification time
}

// main function sets up HTTP and HTTPS servers.
func main() {
	allowedDomains = getAllowedDomainsFromSubdirectories()

	fmt.Println("Serving", allowedDomains)

	// Create HTTPS server
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(allowedDomains...),
		Cache:      autocert.DirCache(certsDir),
	}
	tlsConfig := certManager.TLSConfig()
	tlsConfig.GetCertificate = getSelfSignedOrLetsEncryptCert(&certManager)

	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", handleFile) // Handle file requests
	httpsServer := http.Server{
		Addr:         httpsPort,
		Handler:      httpsMux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		// TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // Enable HTTP/2
	}

	// Create HTTP server
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		newURI := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, newURI, http.StatusFound)
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", handleRedirect) // Redirect HTTP to HTTPS
	httpServer := http.Server{
		Addr:         httpPort,
		Handler:      certManager.HTTPHandler(httpMux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server
	go func() {
		fmt.Println("Starting server on", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil {
			fmt.Println(err)
		}
	}()

	// Start HTTPS server
	fmt.Println("Starting server on", httpsServer.Addr)
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		fmt.Println(err)
	}
}

// getAllowedDomainsFromSubdirectories retrieves allowed domains from subdirectories in the webroot directory.
func getAllowedDomainsFromSubdirectories() []string {
	var domains []string

	files, err := os.ReadDir(webrootDir)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return domains
	}

	for _, file := range files {
		resolvedFile, err := os.Stat(filepath.FromSlash(webrootDir + "/" + file.Name()))
		if err != nil {
			fmt.Println("Error reading directory:", err)
			return domains
		}

		if resolvedFile.IsDir() {
			domains = append(domains, file.Name())
		}
	}

	return domains
}

// getFileFromCache retrieves a file from the cache based on the key.
func getFileFromCache(key string) (CachedFile, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	cachedFile, ok := fileCache[key]
	return cachedFile, ok
}

// cacheFile stores a file in the cache with its content, content type, and modification time.
func cacheFile(key string, content []byte, contentType string, modTime time.Time) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	fileCache[key] = CachedFile{Content: content, ContentType: contentType, ModTime: modTime}
}

// getFileModTime retrieves the modification time of a file.
func getFileModTime(filePath string) time.Time {
	fileStat, err := os.Stat(filePath)
	if err != nil {
		return time.Now() // Treat as modified if error occurs
	}
	return fileStat.ModTime()
}

// addHeaders adds basic HTTP headers to the response.
func addHeaders(w http.ResponseWriter, contenttype string, cache bool) {
	// Set common security headers
	w.Header().Set("Server", serverName)
	w.Header().Set("Content-Type", contenttype)
	// Add more security headers if needed

	if cache {
		w.Header().Set("Cache-Control", "max-age=300")
	} else {
		w.Header().Set("Cache-control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	}
}

// for handleFile
var matchPath = regexp.MustCompile(`^(/[a-zA-Z0-9_-]+)+(\.[a-zA-Z0-9]+)+$`).MatchString

// handleFile handles requests for files, performs necessary checks, serves files, and caches them if applicable.
func handleFile(w http.ResponseWriter, r *http.Request) {
	// Extract URL path and domain from the request
	urlPath := r.URL.Path
	domain := r.Host

	// Set default domain if none provided
	if domain == "" {
		domain = "nodomain"
	}

	// Check if the domain is allowed
	allowed := false
	for _, allowedDomain := range allowedDomains {
		if domain == allowedDomain {
			allowed = true
			break
		}
	}

	// Return forbidden status if domain not allowed
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Clean the URL path for security
	if urlPath != path.Clean(urlPath) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Set default file to index.html if URL path is root
	if urlPath == "/" {
		urlPath = "/index.html"
	}

	// Check if the URL path matches the expected file pattern
	if !matchPath(urlPath) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Prepend domain and webroot to the URL path to get the file path
	filePath := filepath.FromSlash(webrootDir + "/" + domain + urlPath)

	// Get the modification time of the file
	modTime := getFileModTime(filePath)

	// Check if the file is cached and up to date
	if cachedFile, ok := getFileFromCache(filePath); ok {
		if !modTime.After(cachedFile.ModTime) {
			// Serve the cached file if up to date
			addHeaders(w, cachedFile.ContentType, true)
			w.Write(cachedFile.Content)
			return
		}
	}

	// Open the file from the server's file system
	f, err := os.Open(filePath)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer f.Close()

	// Determine the content type of the file
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		var buf [sniffLen]byte
		n, _ := io.ReadFull(f, buf[:])
		contentType = http.DetectContentType(buf[:n])
		_, err := f.Seek(0, io.SeekStart) // Rewind to output the whole file
		if err != nil {
			contentType = ""
		}
	}
	if contentType == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Read the file content into memory
	fileContent, _ := io.ReadAll(f)
	if len(fileContent) < maxFileSizeInCache {
		// Cache the file content if it's within the size limit
		cacheFile(filePath, fileContent, contentType, modTime)
	}

	// Serve the file to the HTTP client
	addHeaders(w, contentType, true)
	io.Copy(w, bytes.NewReader(fileContent))
}

// getSelfSignedOrLetsEncryptCert returns a TLS certificate based on the server name.
func getSelfSignedOrLetsEncryptCert(certManager *autocert.Manager) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		dirCache, ok := certManager.Cache.(autocert.DirCache)
		if !ok {
			dirCache = certsDir
		}

		keyFile := filepath.Join(string(dirCache), hello.ServerName+".key")
		crtFile := filepath.Join(string(dirCache), hello.ServerName+".crt")
		certificate, err := tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			fmt.Printf("%s\nNo custom cert found, using Letsencrypt\n", err)
			return certManager.GetCertificate(hello)
		}
		fmt.Println("Loaded selfsigned certificate.")
		return &certificate, err
	}
}

// cfg := &tls.Config{
// 	MinVersion:               tls.VersionTLS12,
// 	CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
// 	PreferServerCipherSuites: true,
// 	CipherSuites: []uint16{
// 		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
// 		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
// 		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
// 		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
// 	},
// }

// srv := &http.Server{
// 	Addr:         dma.CONFIG_BindAddress(),
// 	Handler:      mux,
// 	TLSConfig:    cfg,
// 	TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
// }
