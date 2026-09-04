package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"rdev/internal/client"
	"rdev/internal/updater"
)

var version = "dev"

func main() {
	var (
		serverURL       string
		clientID        string
		password        string
		identityFile    string
		enrollStdin     bool
		enrollOnly      bool
		replaceExisting bool
		shell           string
		autoUpdate      = true
		updateInterval  = time.Minute
		reconnectMin    = time.Second
		reconnectMax    = 30 * time.Second
	)

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--server", "-s":
			if i+1 < len(os.Args) {
				serverURL = os.Args[i+1]
				i++
			}
		case "--id", "-i":
			if i+1 < len(os.Args) {
				clientID = os.Args[i+1]
				i++
			}
		case "--password", "-p":
			if i+1 < len(os.Args) {
				password = os.Args[i+1]
				i++
			}
		case "--identity-file":
			if i+1 < len(os.Args) {
				identityFile = os.Args[i+1]
				i++
			}
		case "--enroll-stdin":
			enrollStdin = true
		case "--enroll-only":
			enrollOnly = true
		case "--replace-existing":
			replaceExisting = true
		case "--shell", "-S":
			if i+1 < len(os.Args) {
				shell = os.Args[i+1]
				i++
			}
		case "--no-auto-update":
			autoUpdate = false
		case "--auto-update":
			if i+1 < len(os.Args) {
				autoUpdate = parseBoolDefault(os.Args[i+1], true)
				i++
			}
		case "--update-interval":
			if i+1 < len(os.Args) {
				if d, err := time.ParseDuration(os.Args[i+1]); err == nil && d > 0 {
					updateInterval = d
				}
				i++
			}
		case "--reconnect-min":
			if i+1 < len(os.Args) {
				if d, err := time.ParseDuration(os.Args[i+1]); err == nil && d > 0 {
					reconnectMin = d
				}
				i++
			}
		case "--reconnect-max":
			if i+1 < len(os.Args) {
				if d, err := time.ParseDuration(os.Args[i+1]); err == nil && d > 0 {
					reconnectMax = d
				}
				i++
			}
		case "--version", "-v":
			fmt.Println(version)
			os.Exit(0)
		case "--help":
			fmt.Print(`Usage: rdev-client -s <server-url> [options]

Options:
  --server, -s    Server URL(s), comma-separated fallback list (e.g. tcp://1.2.3.4:8081,kcp://1.2.3.4:8082,ws://1.2.3.4:8080)
  --id, -i        Client/Device ID (default: hostname)
  --password, -p  Password for SSH auth (optional, enables password login)
	  --identity-file Read or store the protected managed-device identity
	  --enroll-stdin  Read a one-time enrollment code from standard input
	  --enroll-only   Store the enrolled identity and exit without connecting
	  --replace-existing Replace a same-owner managed device with the requested ID
  --shell, -S     Shell to use (default: $SHELL or /bin/sh or cmd.exe)
  --no-auto-update Disable built-in GitHub release auto-update
  --auto-update    Enable/disable auto-update explicitly (true/false)
  --update-interval Auto-update polling interval (default 1m)
  --reconnect-min Minimum reconnect delay (default 1s)
  --reconnect-max Maximum reconnect delay (default 30s)
  --version, -v   Print version and exit

SSH port is auto-detected from server — no need to specify manually.

Examples:
  rdev-client -s tcp://1.2.3.4:8081,kcp://1.2.3.4:8082,ws://1.2.3.4:8080 -i mydevice -p secret123
  rdev-client -s wss://rdev.example.com -i rpi4 --shell /usr/bin/fish

Environment variables:
  RDEV_SHELL    Shell to use (overrides --shell flag)
  RDEV_SERVER   Server URL (overrides --server flag)
  RDEV_ID       Client ID (overrides --id flag)
	  RDEV_IDENTITY_FILE protected managed-device identity file
  RDEV_AUTO_UPDATE true/false (default true)
  RDEV_UPDATE_INTERVAL duration like 5m or 1h
  RDEV_RECONNECT_MIN minimum reconnect delay (default 1s)
  RDEV_RECONNECT_MAX maximum reconnect delay (default 30s)
  RDEV_UPDATE_PROXY comma-separated GitHub proxy prefixes
`)
			os.Exit(0)
		}
	}

	if serverURL == "" {
		serverURL = os.Getenv("RDEV_SERVER")
	}
	if replaceExisting && !enrollStdin {
		log.Fatal("--replace-existing requires --enroll-stdin")
	}
	if clientID == "" {
		clientID = os.Getenv("RDEV_ID")
	}
	if shell == "" {
		shell = os.Getenv("RDEV_SHELL")
	}
	if identityFile == "" {
		identityFile = os.Getenv("RDEV_IDENTITY_FILE")
	}
	var deviceSecret string
	if identityFile != "" {
		identity, found, err := loadClientIdentity(identityFile)
		if err != nil {
			log.Fatalf("read protected identity: %v", err)
		}
		if found {
			if enrollStdin {
				log.Fatal("refusing to replace an existing managed-device identity")
			}
			serverURL = identity.ServerURL
			clientID = identity.DeviceID
			deviceSecret = identity.DeviceSecret
		} else if !enrollStdin {
			log.Fatal("protected identity file does not exist; use --enroll-stdin for first enrollment")
		}
	}
	if env := os.Getenv("RDEV_AUTO_UPDATE"); env != "" {
		autoUpdate = parseBoolDefault(env, autoUpdate)
	}
	if env := os.Getenv("RDEV_UPDATE_INTERVAL"); env != "" {
		if d, err := time.ParseDuration(env); err == nil && d > 0 {
			updateInterval = d
		}
	}
	if env := os.Getenv("RDEV_RECONNECT_MIN"); env != "" {
		if d, err := time.ParseDuration(env); err == nil && d > 0 {
			reconnectMin = d
		}
	}
	if env := os.Getenv("RDEV_RECONNECT_MAX"); env != "" {
		if d, err := time.ParseDuration(env); err == nil && d > 0 {
			reconnectMax = d
		}
	}
	if serverURL == "" {
		fmt.Println("Error: --server is required")
		fmt.Println("Usage: rdev-client -s <server-url> [options]")
		fmt.Println("Example: rdev-client -s tcp://1.2.3.4:8081,kcp://1.2.3.4:8082,ws://1.2.3.4:8080 -i mydevice")
		os.Exit(1)
	}

	if clientID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			clientID = "unknown"
		} else {
			clientID = hostname
		}
	}
	if enrollStdin {
		if enrollOnly && identityFile == "" {
			log.Fatal("--enroll-only requires --identity-file")
		}
		enrollmentCode, err := readEnrollmentCode(os.Stdin)
		if err != nil {
			log.Fatalf("read device enrollment: %v", err)
		}
		result, err := redeemEnrollment(serverURL, enrollmentCode, clientID, replaceExisting)
		if err != nil {
			log.Fatalf("redeem device enrollment: %v", err)
		}
		clientID = result.DeviceID
		deviceSecret = result.DeviceSecret
		serverURL = result.ServerURL
		if identityFile != "" {
			identity := clientIdentity{
				Schema:       clientIdentitySchema,
				ServerURL:    result.ServerURL,
				ClientID:     result.DeviceID,
				DeviceID:     result.DeviceID,
				DeviceSecret: result.DeviceSecret,
			}
			if err = saveClientIdentity(identityFile, identity); err != nil {
				log.Fatalf("store protected identity: %v", err)
			}
		}
		if enrollOnly {
			fmt.Printf("managed device %s enrolled\n", clientID)
			return
		}
	} else if enrollOnly {
		log.Fatal("--enroll-only requires --enroll-stdin")
	}

	serverURL = normalizeServerListForDisplay(serverURL)

	serverHost := parseServerHost(serverURL)

	fmt.Println()
	fmt.Println("  ╔═══════════════════════════════════════════╗")
	fmt.Println("  ║         RDev Remote Debug Client          ║")
	fmt.Println("  ╠═══════════════════════════════════════════╣")
	fmt.Printf("  ║  Server:  %-31s  ║\n", serverURL)
	fmt.Printf("  ║  ID:      %-31s  ║\n", clientID)
	if shell != "" {
		fmt.Printf("  ║  Shell:   %-31s  ║\n", shell)
	}
	authMode := "open device"
	if deviceSecret != "" {
		authMode = "managed device"
	}
	if password != "" {
		authMode += " + SSH password"
	}
	fmt.Printf("  ║  Auth:    %-31s  ║\n", authMode)
	fmt.Println("  ╚═══════════════════════════════════════════╝")
	fmt.Println()

	c := client.NewClient(serverURL, clientID, password, shell)
	c.SetDeviceSecret(deviceSecret)
	c.SetVersion("go/" + version)
	c.SetReconnectDelays(reconnectMin, reconnectMax)

	// Print connection hints after successful connect
	connectPrinted := false
	c.OnConnect = func(cli *client.Client) {
		if connectPrinted {
			return
		}
		connectPrinted = true

		sshPort := cli.SSHPort()
		if sshPort == "" {
			sshPort = "2222" // fallback
		}
		assignedID := cli.ClientID()
		if assignedID == "" {
			assignedID = clientID
		}

		fmt.Println("  ── How to Connect ─────────────────────────────")
		fmt.Printf("  SSH:      ssh %s@%s -p %s\n", assignedID, serverHost, sshPort)
		if password != "" {
			fmt.Println("  SSH auth: password configured")
		} else {
			fmt.Println("  SSH auth: key or short-lived access ticket")
		}
		fmt.Printf("  SFTP:     sftp -P %s %s@%s\n", sshPort, assignedID, serverHost)
		fmt.Printf("  SCP:      scp -P %s file %s@%s:~/\n", sshPort, assignedID, serverHost)
		fmt.Printf("  Dashboard: http://%s\n", serverHost)
		fmt.Println("  ────────────────────────────────────────────────")
		fmt.Println()
	}

	updater.Start(context.Background(), updater.Config{App: "client", Version: version, Enabled: autoUpdate, Interval: updateInterval})

	if err := c.Run(); err != nil {
		log.Fatalf("client error: %v", err)
	}
}

type enrollmentResult struct {
	DeviceID     string `json:"deviceId"`
	DeviceSecret string `json:"deviceSecret"`
	ServerURL    string `json:"serverUrl"`
}

const clientIdentitySchema = "rdev-client-identity.v1"

type clientIdentity struct {
	Schema       string `json:"schema"`
	ServerURL    string `json:"serverUrl"`
	ClientID     string `json:"clientId"`
	DeviceID     string `json:"deviceId"`
	DeviceSecret string `json:"deviceSecret"`
}

func redeemEnrollment(serverURL, code, deviceID string, replaceExisting bool) (enrollmentResult, error) {
	baseURL, err := enrollmentHTTPBase(serverURL)
	if err != nil {
		return enrollmentResult{}, err
	}
	body, err := json.Marshal(struct {
		Code            string `json:"code"`
		DeviceID        string `json:"deviceId"`
		ReplaceExisting bool   `json:"replaceExisting"`
	}{Code: code, DeviceID: deviceID, ReplaceExisting: replaceExisting})
	if err != nil {
		return enrollmentResult{}, err
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/enrollments/redeem", bytes.NewReader(body))
	if err != nil {
		return enrollmentResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	if err != nil {
		return enrollmentResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return enrollmentResult{}, fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	decoder.DisallowUnknownFields()
	var result enrollmentResult
	if err = decoder.Decode(&result); err != nil {
		return enrollmentResult{}, err
	}
	if result.DeviceID == "" || result.DeviceSecret == "" || result.ServerURL == "" {
		return enrollmentResult{}, fmt.Errorf("server returned incomplete enrollment data")
	}
	return result, nil
}

func readEnrollmentCode(input io.Reader) (string, error) {
	reader := bufio.NewReader(io.LimitReader(input, 4096))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line == "" || strings.TrimSpace(line) != line || strings.ContainsAny(line, "\r\n") {
		return "", fmt.Errorf("enrollment input must contain exactly one code")
	}
	remaining, readErr := io.ReadAll(reader)
	if readErr != nil {
		return "", readErr
	}
	if strings.Trim(string(remaining), "\r\n") != "" {
		return "", fmt.Errorf("enrollment input must contain exactly one code")
	}
	return line, nil
}

func loadClientIdentity(path string) (clientIdentity, bool, error) {
	data, err := readProtectedFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return clientIdentity{}, false, nil
	}
	if err != nil {
		return clientIdentity{}, false, err
	}
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	var identity clientIdentity
	if err = decoder.Decode(&identity); err != nil {
		return clientIdentity{}, false, err
	}
	var trailing json.RawMessage
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return clientIdentity{}, false, fmt.Errorf("identity contains trailing data")
	}
	if identity.Schema != clientIdentitySchema || identity.ServerURL == "" || identity.ClientID == "" ||
		identity.DeviceID == "" || identity.DeviceSecret == "" || identity.ClientID != identity.DeviceID {
		return clientIdentity{}, false, fmt.Errorf("identity is incomplete or has an unsupported schema")
	}
	return identity, true, nil
}

func saveClientIdentity(path string, identity clientIdentity) error {
	if identity.Schema != clientIdentitySchema || identity.ServerURL == "" || identity.ClientID == "" ||
		identity.DeviceID == "" || identity.DeviceSecret == "" || identity.ClientID != identity.DeviceID {
		return fmt.Errorf("identity is incomplete or has an unsupported schema")
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	return writeProtectedFile(path, string(data))
}

func enrollmentHTTPBase(serverList string) (string, error) {
	first := strings.TrimSpace(strings.Split(serverList, ",")[0])
	parsed, err := url.Parse(first)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "https", "http":
	case "wss":
		parsed.Scheme = "https"
	case "ws":
		parsed.Scheme = "http"
	default:
		return "", fmt.Errorf("enrollment requires an HTTP(S) or WebSocket server URL")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", fmt.Errorf("enrollment server URL is invalid")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func parseBoolDefault(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on", "enable", "enabled":
		return true
	case "0", "false", "no", "n", "off", "disable", "disabled":
		return false
	default:
		return fallback
	}
}

func normalizeServerListForDisplay(value string) string {
	parts := strings.Split(value, ",")
	for i, p := range parts {
		u := strings.TrimSpace(p)
		for _, scheme := range []string{"tcp", "kcp", "udp", "ws", "wss", "http", "https"} {
			prefix := scheme + "://"
			if strings.HasPrefix(u, scheme+":///") {
				u = prefix + strings.TrimLeft(u[len(prefix):], "/")
			}
		}
		if !strings.Contains(u, "://") {
			u = "tcp://" + u
		}
		parts[i] = u
	}
	return strings.Join(parts, ",")
}

// parseServerHost extracts the host portion from the first endpoint.
func parseServerHost(serverURL string) string {
	u := strings.TrimSpace(strings.Split(serverURL, ",")[0])
	for _, scheme := range []string{"tcp://", "kcp://", "udp://", "ws://", "wss://", "http://", "https://"} {
		u = strings.TrimPrefix(u, scheme)
	}
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	host, _, err := net.SplitHostPort(u)
	if err != nil {
		return u
	}
	return host
}
