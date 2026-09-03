package client

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"rdev/internal/protocol"
)

const (
	cloudTransferSchema         = "feidu.rdev-cloud-transfer.v1"
	cloudTransferDownload       = "cloud_to_device"
	cloudTransferUpload         = "device_to_cloud"
	cloudTransferAPIBodyLimit   = 2 * 1024 * 1024
	cloudTransferBufferSize     = 1024 * 1024
	cloudTransferMaxPartRetries = 3
)

type cloudTransferEnvelope[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

type cloudTransferPlan struct {
	Schema                string `json:"schema"`
	TransferID            string `json:"transfer_id"`
	Direction             string `json:"direction"`
	SourcePath            string `json:"source_path"`
	DestinationParentPath string `json:"destination_parent_path"`
	FileName              string `json:"file_name"`
	SizeBytes             int64  `json:"size_bytes"`
	SHA1                  string `json:"sha1"`
}

type cloudUploadPart struct {
	PartNumber int    `json:"part_number"`
	Status     string `json:"status,omitempty"`
	UploadURL  string `json:"upload_url,omitempty"`
}

type cloudUploadSession struct {
	SessionID   string            `json:"session_id"`
	OperationID string            `json:"operation_id"`
	Status      string            `json:"status"`
	FileName    string            `json:"file_name"`
	SizeBytes   uint64            `json:"size_bytes"`
	ModifiedAt  uint64            `json:"modified_at_ms"`
	ProofStart  uint64            `json:"proof_start"`
	ProofEnd    uint64            `json:"proof_end"`
	PartSize    uint64            `json:"part_size"`
	PartCount   uint              `json:"part_count"`
	RapidUpload bool              `json:"rapid_upload"`
	Parts       []cloudUploadPart `json:"parts"`
}

type cloudUploadSessionResponse struct {
	Session cloudUploadSession `json:"session"`
	Parts   []cloudUploadPart  `json:"parts"`
}

type cloudTransferProgress struct {
	State     string `json:"state"`
	BytesDone int64  `json:"bytes_done"`
	SHA1      string `json:"sha1,omitempty"`
}

type cloudTransferReporter struct {
	bootstrapURL string
	token        string
	lastAt       time.Time
	lastBytes    int64
}

func (c *Client) handleCloudTransferStart(msg *protocol.Message) {
	if msg == nil || !validCloudTransferID(msg.TransferID) || !validCloudTransferBootstrapURL(msg.BootstrapURL) || !validCloudTransferCredential(msg.TransferToken) {
		return
	}
	c.mu.Lock()
	if _, exists := c.cloudTransfers[msg.TransferID]; exists {
		c.mu.Unlock()
		return
	}
	c.cloudTransfers[msg.TransferID] = struct{}{}
	c.mu.Unlock()

	transferID := msg.TransferID
	bootstrapURL := msg.BootstrapURL
	token := msg.TransferToken
	go func() {
		err := executeCloudTransfer(context.Background(), bootstrapURL, token, transferID)
		c.mu.Lock()
		delete(c.cloudTransfers, transferID)
		c.mu.Unlock()
		result := &protocol.Message{Type: protocol.MsgCloudTransferResult, TransferID: transferID, TransferState: "completed"}
		if err != nil {
			result.TransferState = "failed"
			result.Error = "cloud transfer failed"
		}
		_ = c.send(result)
	}()
}

func executeCloudTransfer(ctx context.Context, bootstrapURL, token, transferID string) error {
	if !validCloudTransferID(transferID) || !validCloudTransferBootstrapURL(bootstrapURL) || !validCloudTransferCredential(token) {
		return errors.New("invalid cloud transfer dispatch")
	}
	var plan cloudTransferPlan
	if err := cloudTransferAPI(ctx, http.MethodGet, bootstrapURL, token, nil, &plan); err != nil {
		return err
	}
	if plan.Schema != cloudTransferSchema || plan.TransferID != transferID || plan.SizeBytes < 0 {
		return errors.New("cloud transfer plan is inconsistent")
	}
	reporter := &cloudTransferReporter{bootstrapURL: bootstrapURL, token: token}
	if err := reporter.report(ctx, "running", 0, "", true); err != nil {
		return err
	}
	var err error
	switch plan.Direction {
	case cloudTransferDownload:
		err = executeCloudDownload(ctx, plan, bootstrapURL, token, reporter)
	case cloudTransferUpload:
		err = executeCloudUpload(ctx, plan, bootstrapURL, token, reporter)
	default:
		err = errors.New("cloud transfer direction is invalid")
	}
	if err != nil {
		_ = reporter.report(ctx, "failed", reporter.lastBytes, "", true)
		return err
	}
	return nil
}

func executeCloudDownload(ctx context.Context, plan cloudTransferPlan, bootstrapURL, token string, reporter *cloudTransferReporter) error {
	if plan.DestinationParentPath == "" || !validCloudTransferFileName(plan.FileName) || !validSHA1(plan.SHA1) {
		return errors.New("cloud download plan is incomplete")
	}
	destinationPath := filepath.Join(plan.DestinationParentPath, plan.FileName)
	partPath := destinationPath + ".rdev-cloud.part"
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0755); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}
	offset, err := resumableCloudPartOffset(partPath, plan.SizeBytes)
	if err != nil {
		return err
	}
	if offset == plan.SizeBytes {
		digest, publishErr := publishCloudDownload(partPath, destinationPath, plan.SHA1)
		if publishErr != nil {
			return publishErr
		}
		return reporter.report(ctx, "completed", offset, digest, true)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudTransferSubresource(bootstrapURL, "content"), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if offset > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	response, err := cloudTransferDownloadClient().Do(request)
	if err != nil {
		return fmt.Errorf("download cloud content: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("download cloud content returned HTTP %d", response.StatusCode)
	}
	if response.StatusCode == http.StatusPartialContent {
		if err = validateCloudContentRange(response.Header.Get("Content-Range"), offset, plan.SizeBytes); err != nil {
			return err
		}
	}
	if offset > 0 && response.StatusCode == http.StatusOK {
		offset = 0
	}
	flags := os.O_CREATE | os.O_WRONLY
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	output, err := os.OpenFile(partPath, flags, 0600)
	if err != nil {
		return fmt.Errorf("open cloud download part: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = output.Close()
		}
	}()
	if _, err = output.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek cloud download part: %w", err)
	}
	buffer := make([]byte, cloudTransferBufferSize)
	written := offset
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			count, writeErr := output.Write(buffer[:n])
			if writeErr != nil {
				return fmt.Errorf("write cloud download part: %w", writeErr)
			}
			if count != n {
				return io.ErrShortWrite
			}
			written += int64(count)
			if written > plan.SizeBytes {
				return errors.New("cloud download exceeded expected size")
			}
			if err = reporter.report(ctx, "running", written, "", false); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read cloud download: %w", readErr)
		}
	}
	if written != plan.SizeBytes {
		return fmt.Errorf("cloud download size mismatch: got %d want %d", written, plan.SizeBytes)
	}
	if err = output.Sync(); err != nil {
		return fmt.Errorf("sync cloud download part: %w", err)
	}
	if err = output.Close(); err != nil {
		return fmt.Errorf("close cloud download part: %w", err)
	}
	closed = true
	digest, err := publishCloudDownload(partPath, destinationPath, plan.SHA1)
	if err != nil {
		return err
	}
	return reporter.report(ctx, "completed", written, digest, true)
}

func publishCloudDownload(partPath, destinationPath, expectedSHA1 string) (string, error) {
	digest, err := sha1File(partPath)
	if err != nil {
		return "", err
	}
	if digest != strings.ToLower(expectedSHA1) {
		_ = os.Truncate(partPath, 0)
		return "", errors.New("cloud download SHA1 mismatch")
	}
	if _, err = os.Stat(destinationPath); err == nil {
		return "", errors.New("cloud download destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect cloud download destination: %w", err)
	}
	if err = os.Rename(partPath, destinationPath); err != nil {
		return "", fmt.Errorf("publish cloud download: %w", err)
	}
	return digest, nil
}

func executeCloudUpload(ctx context.Context, plan cloudTransferPlan, bootstrapURL, token string, reporter *cloudTransferReporter) error {
	if plan.SourcePath == "" {
		return errors.New("cloud upload plan is incomplete")
	}
	info, err := os.Stat(plan.SourcePath)
	if err != nil {
		return fmt.Errorf("inspect cloud upload source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != plan.SizeBytes {
		return errors.New("cloud upload source identity is inconsistent")
	}
	contentHash, err := sha1File(plan.SourcePath)
	if err != nil {
		return err
	}
	preHash, err := sha1FilePrefix(plan.SourcePath, 1024)
	if err != nil {
		return err
	}
	prepare := map[string]any{
		"file_name": filepath.Base(plan.SourcePath), "size_bytes": info.Size(),
		"modified_at_ms": info.ModTime().UnixMilli(), "pre_hash": preHash,
	}
	var upload cloudUploadSessionResponse
	if err = cloudTransferAPI(ctx, http.MethodPost, cloudTransferSubresource(bootstrapURL, "upload-session"), token, prepare, &upload); err != nil {
		return err
	}
	if err = validateCloudUploadSession(upload.Session, plan, info); err != nil {
		return err
	}
	if upload.Session.Status == "proof_required" {
		proof, proofErr := readCloudProof(plan.SourcePath, upload.Session.ProofStart, upload.Session.ProofEnd, uint64(info.Size()))
		if proofErr != nil {
			return proofErr
		}
		var proven cloudUploadSessionResponse
		if err = cloudTransferAPI(ctx, http.MethodPost, cloudTransferSubresource(bootstrapURL, "upload-session/rapid-proof"), token,
			map[string]string{"content_hash": contentHash, "proof_code": proof}, &proven); err != nil {
			return err
		}
		upload = proven
		if err = validateCloudUploadSession(upload.Session, plan, info); err != nil {
			return err
		}
	}
	if upload.Session.Status == "completed" {
		return reporter.report(ctx, "completed", info.Size(), contentHash, true)
	}
	if upload.Session.Status != "uploading" {
		return fmt.Errorf("cloud upload session state %q cannot continue", upload.Session.Status)
	}
	if !upload.Session.RapidUpload {
		if err = uploadCloudParts(ctx, plan.SourcePath, upload.Session, upload.Parts, bootstrapURL, token, reporter); err != nil {
			return err
		}
	}
	var completed struct{}
	if err = cloudTransferAPI(ctx, http.MethodPost, cloudTransferSubresource(bootstrapURL, "upload-session/complete"), token,
		map[string]string{"content_hash": contentHash}, &completed); err != nil {
		return err
	}
	return reporter.report(ctx, "completed", info.Size(), contentHash, true)
}

func uploadCloudParts(ctx context.Context, sourcePath string, session cloudUploadSession, initial []cloudUploadPart, bootstrapURL, token string, reporter *cloudTransferReporter) error {
	uploaded := make(map[int]bool)
	for _, part := range session.Parts {
		if part.Status == "uploaded" {
			uploaded[part.PartNumber] = true
		}
	}
	urls := make(map[int]string)
	for _, part := range initial {
		urls[part.PartNumber] = part.UploadURL
	}
	partNumbers := make([]int, 0, session.PartCount)
	for partNumber := 1; partNumber <= int(session.PartCount); partNumber++ {
		if !uploaded[partNumber] {
			partNumbers = append(partNumbers, partNumber)
		}
	}
	sort.Ints(partNumbers)
	for _, partNumber := range partNumbers {
		var lastErr error
		for attempt := 1; attempt <= cloudTransferMaxPartRetries; attempt++ {
			uploadURL := urls[partNumber]
			if uploadURL == "" || attempt > 1 {
				var refreshed struct {
					Parts []cloudUploadPart `json:"parts"`
				}
				if err := cloudTransferAPI(ctx, http.MethodPost, cloudTransferSubresource(bootstrapURL, "upload-session/parts/refresh"), token, struct{}{}, &refreshed); err != nil {
					lastErr = err
					continue
				}
				for _, part := range refreshed.Parts {
					urls[part.PartNumber] = part.UploadURL
				}
				uploadURL = urls[partNumber]
			}
			if !validCloudTransferDataURL(uploadURL) {
				lastErr = errors.New("cloud upload part URL is invalid")
				continue
			}
			start := int64(partNumber-1) * int64(session.PartSize)
			length := min(int64(session.PartSize), int64(session.SizeBytes)-start)
			status, err := putCloudPart(ctx, uploadURL, sourcePath, start, length)
			if err != nil {
				lastErr = err
				continue
			}
			if status != http.StatusOK && status != http.StatusConflict {
				lastErr = fmt.Errorf("cloud upload part returned HTTP %d", status)
				continue
			}
			var accepted struct{}
			partPath := fmt.Sprintf("upload-session/parts/%d", partNumber)
			if err = cloudTransferAPI(ctx, http.MethodPut, cloudTransferSubresource(bootstrapURL, partPath), token,
				map[string]int{"http_status": status}, &accepted); err != nil {
				lastErr = err
				continue
			}
			done := min(int64(session.SizeBytes), start+length)
			if err = reporter.report(ctx, "running", done, "", true); err != nil {
				return err
			}
			lastErr = nil
			break
		}
		if lastErr != nil {
			return lastErr
		}
	}
	return nil
}

func putCloudPart(ctx context.Context, uploadURL, sourcePath string, start, length int64) (int, error) {
	file, err := os.Open(sourcePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, io.NewSectionReader(file, start, length))
	if err != nil {
		return 0, err
	}
	request.ContentLength = length
	response, err := cloudTransferDataClient(false).Do(request)
	if err != nil {
		return 0, fmt.Errorf("upload cloud part: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, nil
}

func validateCloudUploadSession(session cloudUploadSession, plan cloudTransferPlan, info os.FileInfo) error {
	if session.SessionID == "" || session.OperationID == "" || session.FileName != filepath.Base(plan.SourcePath) ||
		session.SizeBytes != uint64(info.Size()) || session.ModifiedAt != uint64(info.ModTime().UnixMilli()) {
		return errors.New("cloud upload session is inconsistent")
	}
	if session.Status == "uploading" && !session.RapidUpload && (session.PartSize == 0 || session.PartCount == 0) {
		return errors.New("cloud upload multipart layout is invalid")
	}
	return nil
}

func readCloudProof(path string, start, end, size uint64) (string, error) {
	if end <= start || end > size || end-start > cloudTransferAPIBodyLimit {
		return "", errors.New("cloud upload proof range is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	buffer := make([]byte, end-start)
	if _, err = file.ReadAt(buffer, int64(start)); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buffer), nil
}

func (r *cloudTransferReporter) report(ctx context.Context, state string, bytesDone int64, digest string, force bool) error {
	now := time.Now()
	if !force && bytesDone-r.lastBytes < 4*cloudTransferBufferSize && now.Sub(r.lastAt) < time.Second {
		return nil
	}
	var output struct{}
	if err := cloudTransferAPI(ctx, http.MethodPost, cloudTransferSubresource(r.bootstrapURL, "progress"), r.token,
		cloudTransferProgress{State: state, BytesDone: bytesDone, SHA1: digest}, &output); err != nil {
		return err
	}
	r.lastAt = now
	r.lastBytes = bytesDone
	return nil
}

func cloudTransferAPI(ctx context.Context, method, endpoint, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := cloudTransferAPIClient().Do(request)
	if err != nil {
		return fmt.Errorf("cloud transfer API request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("cloud transfer API returned HTTP %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, cloudTransferAPIBodyLimit+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(payload) > cloudTransferAPIBodyLimit {
		return errors.New("cloud transfer API response is too large")
	}
	envelope := cloudTransferEnvelope[json.RawMessage]{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&envelope); err != nil {
		return errors.New("cloud transfer API response is invalid")
	}
	if err = requireCloudJSONEnd(decoder); err != nil || envelope.Code != 0 {
		return errors.New("cloud transfer API rejected the request")
	}
	if output == nil {
		return nil
	}
	if len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) {
		envelope.Data = []byte("{}")
	}
	decoder = json.NewDecoder(bytes.NewReader(envelope.Data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(output); err != nil {
		return errors.New("cloud transfer API data is invalid")
	}
	return requireCloudJSONEnd(decoder)
}

func cloudTransferAPIClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func cloudTransferDownloadClient() *http.Client {
	return cloudTransferDataClient(true)
}

func cloudTransferDataClient(followRedirects bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	client := &http.Client{Transport: transport, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= 5 || !validCloudTransferDataURL(request.URL.String()) {
			return errors.New("unsafe cloud download redirect")
		}
		request.Header.Del("Authorization")
		return nil
	}}
	return client
}

func validateCloudContentRange(value string, expectedStart, expectedSize int64) error {
	if expectedStart < 0 || expectedSize < 0 || expectedStart > expectedSize || !strings.HasPrefix(value, "bytes ") {
		return errors.New("cloud download Content-Range is invalid")
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(parts) != 2 {
		return errors.New("cloud download Content-Range is invalid")
	}
	rangeParts := strings.Split(parts[0], "-")
	if len(rangeParts) != 2 {
		return errors.New("cloud download Content-Range is invalid")
	}
	start, startErr := strconv.ParseInt(rangeParts[0], 10, 64)
	end, endErr := strconv.ParseInt(rangeParts[1], 10, 64)
	total, totalErr := strconv.ParseInt(parts[1], 10, 64)
	if startErr != nil || endErr != nil || totalErr != nil || start != expectedStart || total != expectedSize || end < start || end >= total {
		return errors.New("cloud download Content-Range is inconsistent")
	}
	return nil
}

func cloudTransferSubresource(base, suffix string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(suffix, "/")
}

func resumableCloudPartOffset(path string, expected int64) (int64, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > expected {
		return 0, errors.New("cloud download part identity is invalid")
	}
	return info.Size(), nil
}

func sha1File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha1.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sha1FilePrefix(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha1.New()
	if _, err = io.Copy(hash, io.LimitReader(file, limit)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validSHA1(value string) bool {
	if len(value) != sha1.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validCloudTransferID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	_, err := hex.DecodeString(compact)
	return len(compact) == 32 && err == nil
}

func validCloudTransferCredential(value string) bool {
	if !strings.HasPrefix(value, "fdtx_") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "fdtx_"))
	return err == nil && len(decoded) == 32
}

func validCloudTransferFileName(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsRune(value, 0)
}

func validCloudTransferBootstrapURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return validCloudTransferURLScheme(parsed)
}

func validCloudTransferDataURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return false
	}
	return validCloudTransferURLScheme(parsed)
}

func validCloudTransferURLScheme(parsed *url.URL) bool {
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func requireCloudJSONEnd(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("cloud transfer API response contains trailing data")
	}
	return nil
}
