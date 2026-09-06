package protocol

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
)

// MessageType defines the type of WebSocket message (for text/JSON frames)
type MessageType string

const (
	// Control (text frames)
	MsgRegister      MessageType = "register"       // C->S: register with ID + password
	MsgRegisterError MessageType = "register_error" // S->C: registration rejected
	MsgNewSession    MessageType = "new_session"    // S->C: create a proxied SSH session

	MsgStdinClose MessageType = "stdin_close" // S->C: remote closed stdin (EOF)
	MsgClose      MessageType = "close"       // bidir: session done, clean up
	MsgResize     MessageType = "resize"      // S->C: terminal resize
	MsgExitCode   MessageType = "exit_code"   // C->S: command exit code

	// TCP port forwarding (text frames for control, binary for data)
	MsgTCPConnect  MessageType = "tcp_connect"   // S->C: dial a TCP target (for -L)
	MsgTCPOpen     MessageType = "tcp_open"      // C->S: TCP connection established
	MsgTCPFail     MessageType = "tcp_fail"      // C->S: TCP connection failed
	MsgTCPClose    MessageType = "tcp_close"     // bidir: close a TCP connection
	MsgTCPListen   MessageType = "tcp_listen"    // S->C: start TCP listener (for -R via device)
	MsgTCPListenOK MessageType = "tcp_listen_ok" // C->S: listener started
	MsgTCPAccept   MessageType = "tcp_accept"    // C->S: new connection on listener

	// Session management (S<->Browser)
	MsgSessionList   MessageType = "session_list"   // S->Browser: list active sessions
	MsgSessionAttach MessageType = "session_attach" // Browser->S: attach to a session

	// File distribution (text frames for control, binary for data)
	MsgFileResult MessageType = "file_result" // C->S: file write result {success, error}

	// File manager (text frames for control/metadata, binary for data)
	MsgFileListRequest    MessageType = "file_list"            // S->C: list a directory
	MsgFileListResult     MessageType = "file_list_result"     // C->S: directory listing
	MsgFileMkdir          MessageType = "file_mkdir"           // S->C: create a directory
	MsgFileMkdirResult    MessageType = "file_mkdir_result"    // C->S: directory creation result
	MsgFileDelete         MessageType = "file_delete"          // S->C: delete a file or directory
	MsgFileDeleteResult   MessageType = "file_delete_result"   // C->S: deletion result
	MsgFileRename         MessageType = "file_rename"          // S->C: rename or move a path
	MsgFileRenameResult   MessageType = "file_rename_result"   // C->S: rename result
	MsgFileUploadStart    MessageType = "file_upload_start"    // S->C: prepare resumable upload
	MsgFileUploadReady    MessageType = "file_upload_ready"    // C->S: upload resume offset
	MsgFileUploadEnd      MessageType = "file_upload_end"      // S->C: finish upload
	MsgFileDownloadStart  MessageType = "file_download_start"  // S->C: start/resume download
	MsgFileTransferEnd    MessageType = "file_transfer_end"    // bidir: transfer finished
	MsgFileTransferError  MessageType = "file_transfer_error"  // bidir: transfer failed
	MsgFileTransferCancel MessageType = "file_transfer_cancel" // bidir: cancel transfer

	// Cloud artifact transfer control. The server only dispatches an opaque,
	// short-lived Feidu task; the client transfers bytes directly over HTTPS.
	MsgCloudTransferStart  MessageType = "cloud_transfer_start"  // S->C: start or resume one cloud-backed transfer
	MsgCloudTransferResult MessageType = "cloud_transfer_result" // C->S: terminal dispatch result

	// Remote desktop (text frames for control, binary for frames)
	MsgDesktopStart     MessageType = "desktop_start"     // S->C: start desktop capture
	MsgDesktopReady     MessageType = "desktop_ready"     // C->S: desktop capture status/metadata
	MsgDesktopInput     MessageType = "desktop_input"     // S->C: inject desktop mouse/keyboard input
	MsgDesktopClose     MessageType = "desktop_close"     // bidir: close desktop session
	MsgDesktopClipboard MessageType = "desktop_clipboard" // bidir: request, set, or report session clipboard text

	// Remote peripherals. USB metadata is inventory-only; serial sessions are
	// explicitly opened and never restored automatically after reconnect.
	MsgPeripheralListRequest MessageType = "peripheral_list"        // S->C: enumerate serial ports and USB-backed serial assets
	MsgPeripheralListResult  MessageType = "peripheral_list_result" // C->S: current peripheral snapshot
	MsgSerialOpen            MessageType = "serial_open"            // S->C: open one serial port
	MsgSerialOpenResult      MessageType = "serial_open_result"     // C->S: serial open result
	MsgSerialClose           MessageType = "serial_close"           // S->C: close one serial session
	MsgSerialCloseResult     MessageType = "serial_close_result"    // C->S: serial close result
	MsgSerialWriteResult     MessageType = "serial_write_result"    // C->S: bytes accepted by the serial driver
	MsgSerialError           MessageType = "serial_error"           // C->S: asynchronous serial failure

	// GPU desktop tunnel over shared TCP/KCP transport.
	MsgGPUDesktopTunnel MessageType = "gpu_desktop_tunnel"

	// Client log collection / telemetry.
	MsgLogConfig MessageType = "log_config" // S->C: dynamic client log upload config
	MsgLogBatch  MessageType = "log_batch"  // C->S: client log entries batch

	// Legacy text-frame data types (kept for reference, use binary frames instead)
	MsgData       MessageType = "data"
	MsgStderrData MessageType = "stderr"
	MsgTCPData    MessageType = "tcp_data"
	MsgFilePut    MessageType = "file_put"
)

// Binary frame types for high-performance data transfer (OpcodeBinary frames)
// Layout: [1 byte type] [1 byte idLen] [idLen bytes: session/forward ID] [payload]
const (
	BinData      byte = 0x01 // Session data (stdin/stdout)
	BinStderr    byte = 0x02 // Session stderr
	BinTCPData   byte = 0x03 // TCP forwarding data
	BinFilePut   byte = 0x04 // File write to device (single-frame payload)
	BinFileStart byte = 0x05 // File write stream start (extended header)
	BinFileChunk byte = 0x06 // File write stream chunk
	BinFileEnd   byte = 0x07 // File write stream end
	BinFileAck   byte = 0x08 // File write stream chunk acknowledged

	// File manager binary frames. Layout:
	// [1 byte type] [1 byte idLen] [idLen bytes task ID] [8 bytes offset BE] [payload]
	BinFileUploadChunk    byte = 0x20
	BinFileUploadAck      byte = 0x21
	BinFileDownloadChunk  byte = 0x22
	BinFileTransferEnd    byte = 0x23
	BinFileTransferCancel byte = 0x24

	BinDesktopFrame byte = 0x30 // Remote desktop encoded frame bytes
	BinSerialData   byte = 0x40 // Raw serial bytes in either direction
)

// File binary extended layout after common header:
// [2 bytes pathLen BE] [pathLen bytes: path] [4 bytes mode BE] [optional file data]

// Message is the WebSocket protocol message (for text/JSON frames)
type Message struct {
	Type          MessageType `json:"type"`
	ClientID      string      `json:"clientId,omitempty"`
	SessionID     string      `json:"sessionId,omitempty"`
	ClientVersion string      `json:"clientVersion,omitempty"`
	Platform      string      `json:"platform,omitempty"`
	Architecture  string      `json:"architecture,omitempty"`

	// Client registration identity. InstanceID is a stable per-process token used
	// to distinguish duplicate IDs from reconnects of the same running client.
	InstanceID string `json:"instanceId,omitempty"`

	// Session creation
	Subsystem string           `json:"subsystem,omitempty"` // "", "sftp"
	Command   string           `json:"command,omitempty"`
	Pty       bool             `json:"pty,omitempty"`
	Env       []string         `json:"env,omitempty"`
	Term      string           `json:"term,omitempty"`
	Rows      int              `json:"rows,omitempty"`
	Cols      int              `json:"cols,omitempty"`
	Modes     map[uint8]uint32 `json:"modes,omitempty"` // SSH terminal modes

	// Auth
	Password     string `json:"password,omitempty"`
	DeviceSecret string `json:"deviceSecret,omitempty"`

	// Server info (S->C in MsgRegister response)
	SSHPort  string `json:"sshPort,omitempty"`  // e.g. "8422"
	HTTPHost string `json:"httpHost,omitempty"` // e.g. "1.2.3.4:8080"

	// Exit
	ExitCode int `json:"exitCode,omitempty"`

	// TCP forwarding
	ForwardID  string `json:"forwardId,omitempty"`
	ListenID   string `json:"listenId,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	SourceAddr string `json:"sourceAddr,omitempty"`
	Error      string `json:"error,omitempty"`

	// File distribution
	FilePath string `json:"filePath,omitempty"`
	FileMode int32  `json:"fileMode,omitempty"`
	Success  bool   `json:"success,omitempty"`

	// File manager
	RequestID   string      `json:"requestId,omitempty"`
	TaskID      string      `json:"taskId,omitempty"`
	Path        string      `json:"path,omitempty"`
	Location    string      `json:"location,omitempty"`
	ParentPath  string      `json:"parentPath,omitempty"`
	Name        string      `json:"name,omitempty"`
	Size        int64       `json:"size,omitempty"`
	Offset      int64       `json:"offset,omitempty"`
	SHA256      string      `json:"sha256,omitempty"`
	ModTime     string      `json:"modTime,omitempty"`
	IsDir       bool        `json:"isDir,omitempty"`
	Truncated   bool        `json:"truncated,omitempty"`
	Recursive   bool        `json:"recursive,omitempty"`
	HomePath    string      `json:"homePath,omitempty"`
	FileEntries []FileEntry `json:"entries,omitempty"`

	// Cloud artifact transfer. TransferToken is only present in the one-time
	// S->C dispatch and must never be persisted or logged.
	TransferID         string `json:"transferId,omitempty"`
	TransferGeneration uint64 `json:"transferGeneration,omitempty"`
	BootstrapURL       string `json:"bootstrapUrl,omitempty"`
	TransferToken      string `json:"transferToken,omitempty"`
	TransferState      string `json:"transferState,omitempty"`
	BytesDone          int64  `json:"bytesDone,omitempty"`

	// Session management
	SessionType string        `json:"sessionType,omitempty"` // "shell", "exec", "sftp"
	AttachMode  string        `json:"attachMode,omitempty"`  // "monitor" (read-only) or "takeover" (read-write)
	Sessions    []SessionInfo `json:"sessions,omitempty"`

	// Remote desktop
	DesktopCapabilities *DesktopCapabilities `json:"desktop,omitempty"`
	Width               int                  `json:"width,omitempty"`
	Height              int                  `json:"height,omitempty"`
	Format              string               `json:"format,omitempty"`
	Source              string               `json:"source,omitempty"`
	Quality             int                  `json:"quality,omitempty"`
	FPS                 int                  `json:"fps,omitempty"`
	InputType           string               `json:"inputType,omitempty"`
	InputBackend        string               `json:"inputBackend,omitempty"`
	ShowCursor          bool                 `json:"showCursor,omitempty"`
	X                   int                  `json:"x,omitempty"`
	Y                   int                  `json:"y,omitempty"`
	Button              int                  `json:"button,omitempty"`
	DeltaX              int                  `json:"deltaX,omitempty"`
	DeltaY              int                  `json:"deltaY,omitempty"`
	Key                 string               `json:"key,omitempty"`
	Code                string               `json:"code,omitempty"`
	CtrlKey             bool                 `json:"ctrlKey,omitempty"`
	AltKey              bool                 `json:"altKey,omitempty"`
	ShiftKey            bool                 `json:"shiftKey,omitempty"`
	MetaKey             bool                 `json:"metaKey,omitempty"`
	PointerType         string               `json:"pointerType,omitempty"`
	PointerID           int                  `json:"pointerId,omitempty"`
	Pressure            float64              `json:"pressure,omitempty"`

	ClipboardAction string          `json:"clipboardAction,omitempty"`
	Text            string          `json:"text,omitempty"`
	ClipboardItems  []ClipboardItem `json:"clipboardItems,omitempty"`

	// Remote peripheral inventory and serial console.
	PeripheralV1 bool             `json:"peripheralV1,omitempty"`
	SerialPorts  []SerialPortInfo `json:"serialPorts,omitempty"`
	SerialPortID string           `json:"serialPortId,omitempty"`
	SerialConfig *SerialConfig    `json:"serialConfig,omitempty"`
	ErrorCode    string           `json:"errorCode,omitempty"`
	DroppedBytes uint64           `json:"droppedBytes,omitempty"`

	// Client log collection
	LogSupported    bool       `json:"logSupported,omitempty"`
	CloudTransferV1 bool       `json:"cloudTransferV1,omitempty"`
	LogEnabled      bool       `json:"logEnabled,omitempty"`
	LogLevel        string     `json:"logLevel,omitempty"`
	SampleRate      float64    `json:"sampleRate,omitempty"`
	MaxLineBytes    int        `json:"maxLineBytes,omitempty"`
	FlushIntervalMs int        `json:"flushIntervalMs,omitempty"`
	Logs            []LogEntry `json:"logs,omitempty"`

	// Legacy fields (text frames)
	Data   string `json:"data,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

// SerialPortInfo is a read-only serial asset snapshot. SerialNumber is
// intentionally omitted so the browser does not receive a hardware identifier
// that is not needed to open the current port.
type SerialPortInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	USB          bool   `json:"usb"`
	VendorID     string `json:"vendorId,omitempty"`
	ProductID    string `json:"productId,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
}

// SerialConfig is the portable subset implemented by the client on every
// supported platform. FlowControl currently accepts only "none".
type SerialConfig struct {
	BaudRate    int    `json:"baudRate"`
	DataBits    int    `json:"dataBits"`
	Parity      string `json:"parity"`
	StopBits    string `json:"stopBits"`
	FlowControl string `json:"flowControl"`
}

// ClipboardItem is one base64-encoded clipboard representation.
type ClipboardItem struct {
	MIME string `json:"mime"`
	Data string `json:"data"`
}

// LogEntry is one client-side log event uploaded to the server.
type LogEntry struct {
	Timestamp string            `json:"ts,omitempty"`
	Level     string            `json:"level,omitempty"`
	Target    string            `json:"target,omitempty"`
	Module    string            `json:"module,omitempty"`
	Message   string            `json:"msg,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// DesktopCapabilities describes remote desktop support reported by a device.
type DesktopCapabilities struct {
	Platform        string                `json:"platform"`
	DisplayServer   string                `json:"displayServer,omitempty"`
	Supported       bool                  `json:"supported"`
	ViewOnly        bool                  `json:"viewOnly"`
	Input           bool                  `json:"input"`
	Clipboard       bool                  `json:"clipboard"`
	Backends        []string              `json:"backends,omitempty"`
	InputBackends   []string              `json:"inputBackends,omitempty"`
	InputOptions    []DesktopInputBackend `json:"inputOptions,omitempty"`
	VideoCodecs     []string              `json:"videoCodecs,omitempty"`
	EncoderBackends []string              `json:"encoderBackends,omitempty"`
	Reason          string                `json:"reason,omitempty"`
	Sources         []DesktopSource       `json:"sources,omitempty"`
}

// DesktopInputBackend describes one selectable desktop input backend.
type DesktopInputBackend struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Kinds    []string `json:"kinds,omitempty"`
	Requires []string `json:"requires,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// DesktopSource describes a selectable capture source.
type DesktopSource struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Kind    string `json:"kind,omitempty"`
	Backend string `json:"backend,omitempty"`
	X       int    `json:"x,omitempty"`
	Y       int    `json:"y,omitempty"`
	Width   int    `json:"width,omitempty"`
	Height  int    `json:"height,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SessionInfo describes an active session for the management API.
type SessionInfo struct {
	ID         string `json:"id"`
	ClientID   string `json:"clientId"`
	Type       string `json:"type"`    // "shell", "exec", "sftp"
	Command    string `json:"command"` // for exec
	Pty        bool   `json:"pty"`
	Term       string `json:"term"`
	Rows       int    `json:"rows"`
	Cols       int    `json:"cols"`
	CreatedAt  string `json:"createdAt"`
	HasMonitor bool   `json:"hasMonitor"` // true if someone is monitoring
	HasControl bool   `json:"hasControl"` // true if someone has takeover
}

// FileEntry describes one remote filesystem entry for the file manager.
type FileEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	ModTime string `json:"modTime"`
}

// --- JSON encoding (for text frames) ---

func Encode(m *Message) ([]byte, error) {
	return json.Marshal(m)
}

func Decode(data []byte) (*Message, error) {
	var m Message
	err := json.Unmarshal(data, &m)
	return &m, err
}

func EncodeData(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func DecodeData(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// --- Binary encoding (for OpcodeBinary frames) ---

// EncodeBinFrame encodes a binary data frame
// Layout: [1 byte type] [1 byte idLen] [idLen bytes ID] [payload]
func EncodeBinFrame(typ byte, id string, payload []byte) []byte {
	idb := []byte(id)
	buf := make([]byte, 2+len(idb)+len(payload))
	buf[0] = typ
	buf[1] = byte(len(idb))
	copy(buf[2:], idb)
	copy(buf[2+len(idb):], payload)
	return buf
}

// DecodeBinFrame decodes a binary data frame
func DecodeBinFrame(raw []byte) (typ byte, id string, payload []byte, err error) {
	if len(raw) < 2 {
		return 0, "", nil, io.ErrUnexpectedEOF
	}
	typ = raw[0]
	idLen := int(raw[1])
	if len(raw) < 2+idLen {
		return 0, "", nil, io.ErrUnexpectedEOF
	}
	id = string(raw[2 : 2+idLen])
	payload = raw[2+idLen:]
	return
}

// EncodeBinFrameOffset encodes a binary frame carrying an int64 byte offset.
func EncodeBinFrameOffset(typ byte, id string, offset int64, payload []byte) []byte {
	idb := []byte(id)
	buf := make([]byte, 2+len(idb)+8+len(payload))
	buf[0] = typ
	buf[1] = byte(len(idb))
	copy(buf[2:], idb)
	binary.BigEndian.PutUint64(buf[2+len(idb):], uint64(offset))
	copy(buf[2+len(idb)+8:], payload)
	return buf
}

// DecodeBinFrameOffset decodes a binary frame carrying an int64 byte offset.
func DecodeBinFrameOffset(raw []byte) (typ byte, id string, offset int64, payload []byte, err error) {
	typ, id, payload, err = DecodeBinFrame(raw)
	if err != nil {
		return 0, "", 0, nil, err
	}
	if len(payload) < 8 {
		return 0, "", 0, nil, io.ErrUnexpectedEOF
	}
	offset = int64(binary.BigEndian.Uint64(payload[:8]))
	payload = payload[8:]
	return
}

// EncodeBinFilePut encodes a single-frame file put binary frame.
// Layout: [0x04] [1 idLen] [id] [2 pathLen BE] [path] [4 mode BE] [file data]
func EncodeBinFilePut(id, path string, mode int32, fileData []byte) []byte {
	buf, pos := encodeBinFileHeader(BinFilePut, id, path, mode, len(fileData))
	copy(buf[pos:], fileData)
	return buf
}

// EncodeBinFileStart encodes the first frame of a streamed file write.
func EncodeBinFileStart(id, path string, mode int32) []byte {
	buf, _ := encodeBinFileHeader(BinFileStart, id, path, mode, 0)
	return buf
}

func encodeBinFileHeader(typ byte, id, path string, mode int32, extra int) ([]byte, int) {
	idb := []byte(id)
	pathb := []byte(path)
	n := 2 + len(idb) + 2 + len(pathb) + 4 + extra
	buf := make([]byte, n)
	pos := 0
	buf[pos] = typ
	pos++
	buf[pos] = byte(len(idb))
	pos++
	copy(buf[pos:], idb)
	pos += len(idb)
	binary.BigEndian.PutUint16(buf[pos:], uint16(len(pathb)))
	pos += 2
	copy(buf[pos:], pathb)
	pos += len(pathb)
	binary.BigEndian.PutUint32(buf[pos:], uint32(mode))
	pos += 4
	return buf, pos
}

// DecodeBinFilePut decodes a file header followed by optional data.
func DecodeBinFilePut(payload []byte) (path string, mode int32, fileData []byte, err error) {
	if len(payload) < 2 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	pathLen := int(binary.BigEndian.Uint16(payload[:2]))
	if len(payload) < 2+pathLen+4 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	path = string(payload[2 : 2+pathLen])
	mode = int32(binary.BigEndian.Uint32(payload[2+pathLen : 2+pathLen+4]))
	fileData = payload[2+pathLen+4:]
	return
}

// BinFrameHeaderLen returns the header length for a binary frame with given id
func BinFrameHeaderLen(id string) int {
	return 2 + len(id)
}

// MustDecodeBinFrame is like DecodeBinFrame but panics on error (for testing)
func MustDecodeBinFrame(raw []byte) (byte, string, []byte) {
	typ, id, payload, err := DecodeBinFrame(raw)
	if err != nil {
		panic(err)
	}
	return typ, id, payload
}
