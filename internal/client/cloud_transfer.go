package client

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	cloudTransferSchema            = "feidu.rdev-cloud-transfer.v1"
	cloudTransferDownload          = "cloud_to_device"
	cloudTransferUpload            = "device_to_cloud"
	cloudTransferAPIBodyLimit      = 2 * 1024 * 1024
	cloudTransferBufferSize        = 1024 * 1024
	cloudTransferMaxPartRetries    = 3
	cloudTransferResultRetention   = 10 * time.Minute
	cloudTransferAcceptanceTimeout = 7 * time.Second
)

var (
	cloudTransferAPIHTTPClient      = newCloudTransferHTTPClient(false, 30*time.Second)
	cloudTransferUploadHTTPClient   = newCloudTransferHTTPClient(false, 0)
	cloudTransferDownloadHTTPClient = newCloudTransferHTTPClient(true, 0)
	errUnsafeCloudDownloadRedirect  = errors.New("unsafe cloud download redirect")
)

type cloudTransferRun struct {
	transferID   string
	generation   uint64
	bootstrapURL string
	tokenHash    [sha256.Size]byte
	ctx          context.Context
	cancel       context.CancelFunc
	state        string
	requestIDs   map[string]struct{}
}

type cloudTransferStageError struct {
	stage string
	err   error
}

func (e *cloudTransferStageError) Error() string { return "cloud transfer " + e.stage + " failed" }
func (e *cloudTransferStageError) Unwrap() error { return e.err }

func cloudTransferFailure(stage string, err error) error {
	return &cloudTransferStageError{stage: stage, err: err}
}

func cloudTransferFailureStage(err error) string {
	var staged *cloudTransferStageError
	if errors.As(err, &staged) && staged.stage != "" {
		return staged.stage
	}
	return "unknown"
}

type cloudTransferCategoryError struct {
	category string
	err      error
}

func (e *cloudTransferCategoryError) Error() string { return "cloud transfer " + e.category + " error" }
func (e *cloudTransferCategoryError) Unwrap() error { return e.err }

func cloudTransferCategory(category string, err error) error {
	return &cloudTransferCategoryError{category: category, err: err}
}

func cloudTransferFailureCategory(err error) string {
	var categorized *cloudTransferCategoryError
	if errors.As(err, &categorized) && categorized.category != "" {
		return categorized.category
	}
	return "unknown"
}

type cloudTransferEnvelope[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
	TraceID string `json:"traceId,omitempty"`
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
	HTTPStatus int    `json:"http_status,omitempty"`
	UpdatedAt  uint64 `json:"updated_at_ms,omitempty"`
	UploadURL  string `json:"upload_url,omitempty"`
}

type cloudUploadSession struct {
	SessionID          string            `json:"session_id"`
	OperationID        string            `json:"operation_id"`
	Status             string            `json:"status"`
	UserID             uint64            `json:"user_id"`
	DeveloperTokenID   string            `json:"developer_token_id,omitempty"`
	ParentContentID    string            `json:"parent_content_id"`
	FileName           string            `json:"file_name"`
	SizeBytes          uint64            `json:"size_bytes"`
	ModifiedAt         uint64            `json:"modified_at_ms"`
	ContentType        string            `json:"content_type"`
	ProjectID          string            `json:"project_id"`
	AssetKind          string            `json:"asset_kind"`
	AssetTitle         string            `json:"asset_title"`
	AssetDescription   string            `json:"asset_description"`
	CapturedAt         uint64            `json:"captured_at_ms"`
	ProofStart         uint64            `json:"proof_start"`
	ProofEnd           uint64            `json:"proof_end"`
	PartSize           uint64            `json:"part_size"`
	PartCount          uint              `json:"part_count"`
	RapidUpload        bool              `json:"rapid_upload"`
	ResultContentID    string            `json:"result_content_id"`
	LifecycleAction    string            `json:"lifecycle_action"`
	LifecycleLifetime  uint64            `json:"lifecycle_lifetime_seconds"`
	LifecycleExpiresAt uint64            `json:"lifecycle_expires_at_ms"`
	ExpiresAt          uint64            `json:"expires_at_ms"`
	CreatedAt          uint64            `json:"created_at_ms"`
	UpdatedAt          uint64            `json:"updated_at_ms"`
	CompletedAt        uint64            `json:"completed_at_ms"`
	Parts              []cloudUploadPart `json:"parts"`
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
	if msg == nil || !validCloudTransferID(msg.TransferID) || msg.TransferGeneration == 0 ||
		!validCloudTransferRequestID(msg.RequestID) || !validCloudTransferBootstrapURL(msg.BootstrapURL) ||
		!validCloudTransferCredential(msg.TransferToken) {
		return
	}
	run, start := c.prepareCloudTransfer(msg)
	if !start {
		return
	}
	go c.runCloudTransfer(run, msg.BootstrapURL, msg.TransferToken)
}

func (c *Client) prepareCloudTransfer(msg *protocol.Message) (*cloudTransferRun, bool) {
	tokenHash := sha256.Sum256([]byte(msg.TransferToken))
	c.mu.Lock()
	if existing := c.cloudTransfers[msg.TransferID]; existing != nil {
		if msg.TransferGeneration < existing.generation {
			c.mu.Unlock()
			_ = c.sendCloudTransferResult(msg.RequestID, msg.TransferID, msg.TransferGeneration, "failed")
			return existing, false
		}
		if msg.TransferGeneration == existing.generation {
			if existing.bootstrapURL != msg.BootstrapURL || existing.tokenHash != tokenHash {
				c.mu.Unlock()
				_ = c.sendCloudTransferResult(msg.RequestID, msg.TransferID, msg.TransferGeneration, "failed")
				return existing, false
			}
			state := existing.state
			if state == "starting" {
				existing.requestIDs[msg.RequestID] = struct{}{}
				c.mu.Unlock()
				return existing, false
			}
			c.mu.Unlock()
			_ = c.sendCloudTransferResult(msg.RequestID, msg.TransferID, msg.TransferGeneration, state)
			return existing, false
		}
		existing.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &cloudTransferRun{
		transferID: msg.TransferID, generation: msg.TransferGeneration, bootstrapURL: msg.BootstrapURL,
		tokenHash: tokenHash, ctx: ctx, cancel: cancel,
		state: "starting", requestIDs: map[string]struct{}{msg.RequestID: {}},
	}
	c.cloudTransfers[msg.TransferID] = run
	c.mu.Unlock()
	return run, true
}

func (c *Client) runCloudTransfer(run *cloudTransferRun, bootstrapURL, token string) {
	c.mu.Lock()
	if c.cloudTransfers[run.transferID] != run {
		c.mu.Unlock()
		run.cancel()
		return
	}
	c.mu.Unlock()
	err := executeCloudTransferWithAccepted(run.ctx, bootstrapURL, token, run.transferID, func() error {
		return c.publishCloudTransferState(run, "running")
	})
	state := "completed"
	if err != nil {
		log.Printf("cloud transfer failed: stage=%s category=%s", cloudTransferFailureStage(err), cloudTransferFailureCategory(err))
		state = "failed"
	}
	_ = c.finishCloudTransfer(run, state)
}

func executeCloudTransfer(ctx context.Context, bootstrapURL, token, transferID string) error {
	return executeCloudTransferWithAccepted(ctx, bootstrapURL, token, transferID, nil)
}

func executeCloudTransferWithAccepted(ctx context.Context, bootstrapURL, token, transferID string, accepted func() error) error {
	if !validCloudTransferID(transferID) || !validCloudTransferBootstrapURL(bootstrapURL) || !validCloudTransferCredential(token) {
		return cloudTransferFailure("dispatch_validation", errors.New("invalid cloud transfer dispatch"))
	}
	acceptanceContext := ctx
	cancelAcceptance := func() {}
	if accepted != nil {
		acceptanceContext, cancelAcceptance = context.WithTimeout(ctx, cloudTransferAcceptanceTimeout)
	}
	defer cancelAcceptance()
	var plan cloudTransferPlan
	if err := cloudTransferAPI(acceptanceContext, http.MethodGet, bootstrapURL, token, nil, &plan); err != nil {
		return cloudTransferFailure("plan_fetch", err)
	}
	if plan.Schema != cloudTransferSchema || plan.TransferID != transferID || plan.SizeBytes < 0 {
		return cloudTransferFailure("plan_validation", errors.New("cloud transfer plan is inconsistent"))
	}
	reporter := &cloudTransferReporter{bootstrapURL: bootstrapURL, token: token}
	if err := reporter.report(acceptanceContext, "running", 0, "", true); err != nil {
		return cloudTransferFailure("initial_progress", err)
	}
	if accepted != nil {
		if err := accepted(); err != nil {
			return cloudTransferFailure("acknowledgement", err)
		}
	}
	cancelAcceptance()
	var err error
	switch plan.Direction {
	case cloudTransferDownload:
		if err = executeCloudDownload(ctx, plan, bootstrapURL, token, reporter); err != nil {
			err = cloudTransferFailure("download", err)
		}
	case cloudTransferUpload:
		if err = executeCloudUpload(ctx, plan, bootstrapURL, token, reporter); err != nil {
			err = cloudTransferFailure("upload", err)
		}
	default:
		err = cloudTransferFailure("plan_validation", errors.New("cloud transfer direction is invalid"))
	}
	if err != nil {
		_ = reporter.report(ctx, "failed", reporter.lastBytes, "", true)
		return err
	}
	return nil
}

func (c *Client) publishCloudTransferState(run *cloudTransferRun, state string) error {
	c.mu.Lock()
	if c.cloudTransfers[run.transferID] != run {
		c.mu.Unlock()
		return context.Canceled
	}
	run.state = state
	requestIDs := drainCloudTransferRequestIDs(run)
	c.mu.Unlock()
	var firstErr error
	for _, requestID := range requestIDs {
		if err := c.sendCloudTransferResult(requestID, run.transferID, run.generation, state); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Client) finishCloudTransfer(run *cloudTransferRun, state string) error {
	c.mu.Lock()
	active := c.cloudTransfers[run.transferID] == run
	run.state = state
	requestIDs := drainCloudTransferRequestIDs(run)
	c.mu.Unlock()
	var firstErr error
	for _, requestID := range requestIDs {
		if err := c.sendCloudTransferResult(requestID, run.transferID, run.generation, state); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if active {
		time.AfterFunc(cloudTransferResultRetention, func() {
			c.mu.Lock()
			if c.cloudTransfers[run.transferID] == run {
				delete(c.cloudTransfers, run.transferID)
			}
			c.mu.Unlock()
		})
	}
	return firstErr
}

func drainCloudTransferRequestIDs(run *cloudTransferRun) []string {
	requestIDs := make([]string, 0, len(run.requestIDs))
	for requestID := range run.requestIDs {
		requestIDs = append(requestIDs, requestID)
	}
	run.requestIDs = make(map[string]struct{})
	return requestIDs
}

func (c *Client) sendCloudTransferResult(requestID, transferID string, generation uint64, state string) error {
	result := &protocol.Message{
		Type: protocol.MsgCloudTransferResult, RequestID: requestID, TransferID: transferID,
		TransferGeneration: generation, TransferState: state,
	}
	if state == "failed" {
		result.Error = "cloud transfer failed"
	}
	return c.send(result)
}

func executeCloudDownload(ctx context.Context, plan cloudTransferPlan, bootstrapURL, token string, reporter *cloudTransferReporter) error {
	if plan.DestinationParentPath == "" || !validCloudTransferFileName(plan.FileName) || !validSHA1(plan.SHA1) {
		return cloudTransferCategory("plan_invalid", errors.New("cloud download plan is incomplete"))
	}
	destinationPath := filepath.Join(plan.DestinationParentPath, plan.FileName)
	partPath := destinationPath + ".rdev-cloud.part"
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0755); err != nil {
		return cloudTransferCategory("destination_directory", err)
	}
	offset, err := resumableCloudPartOffset(partPath, plan.SizeBytes)
	if err != nil {
		return cloudTransferCategory("resume_state", err)
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
		return cloudTransferCategory("content_request", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if offset > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	response, err := cloudTransferDownloadClient().Do(request)
	if err != nil {
		category := "content_network"
		if errors.Is(err, errUnsafeCloudDownloadRedirect) {
			category = "content_redirect"
		} else if errors.Is(err, context.DeadlineExceeded) {
			category = "content_timeout"
		}
		return cloudTransferCategory(category, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		category := "content_http_" + strconv.Itoa(response.StatusCode)
		if response.Request != nil && response.Request.URL.String() != request.URL.String() {
			category = "content_redirect_http_" + strconv.Itoa(response.StatusCode)
		}
		return cloudTransferCategory(category, errors.New("cloud content returned a non-success status"))
	}
	if response.StatusCode == http.StatusPartialContent {
		if err = validateCloudContentRange(response.Header.Get("Content-Range"), offset, plan.SizeBytes); err != nil {
			return cloudTransferCategory("content_range", err)
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
		return cloudTransferCategory("destination_open", err)
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
		category := "network"
		if errors.Is(err, context.DeadlineExceeded) {
			category = "timeout"
		}
		return cloudTransferCategory(category, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return cloudTransferCategory("http_"+strconv.Itoa(response.StatusCode), errors.New("cloud transfer API returned a non-success status"))
	}
	limited := io.LimitReader(response.Body, cloudTransferAPIBodyLimit+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return cloudTransferCategory("response_read", err)
	}
	if len(payload) > cloudTransferAPIBodyLimit {
		return cloudTransferCategory("response_too_large", errors.New("cloud transfer API response is too large"))
	}
	envelope := cloudTransferEnvelope[json.RawMessage]{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&envelope); err != nil {
		return cloudTransferCategory("response_envelope", errors.New("cloud transfer API response is invalid"))
	}
	if err = requireCloudJSONEnd(decoder); err != nil || envelope.Code != 0 {
		return cloudTransferCategory("api_rejected", errors.New("cloud transfer API rejected the request"))
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
		return cloudTransferCategory("response_data", errors.New("cloud transfer API data is invalid"))
	}
	if err = requireCloudJSONEnd(decoder); err != nil {
		return cloudTransferCategory("response_data", err)
	}
	return nil
}

func cloudTransferAPIClient() *http.Client {
	return cloudTransferAPIHTTPClient
}

func cloudTransferDownloadClient() *http.Client {
	return cloudTransferDownloadHTTPClient
}

func cloudTransferDataClient(followRedirects bool) *http.Client {
	if followRedirects {
		return cloudTransferDownloadHTTPClient
	}
	return cloudTransferUploadHTTPClient
}

func newCloudTransferHTTPClient(followRedirects bool, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.MaxIdleConns = 16
	transport.MaxIdleConnsPerHost = 4
	transport.MaxConnsPerHost = 8
	transport.IdleConnTimeout = 90 * time.Second
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= 5 || !validCloudTransferDataURL(request.URL.String()) {
			return errUnsafeCloudDownloadRedirect
		}
		request.Header.Del("Authorization")
		request.Header.Del("Referer")
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

func validCloudTransferRequestID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
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
