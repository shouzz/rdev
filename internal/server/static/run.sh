#!/bin/sh
# rdev-client one-click runner
# Download → run, no install needed
# Compatible with: POSIX sh, bash, dash, ash, zsh, ksh, busybox sh
#
# Usage:
#   curl -sL http://SERVER:PORT/run.sh | sh -s -- ws://SERVER:PORT
#   curl -sL http://SERVER:PORT/run.sh | sh -s -- ws://SERVER:PORT --client rs
#   wget -qO- http://SERVER:PORT/run.sh | sh -s -- ws://SERVER:PORT

set -e

# ── Defaults ────────────────────────────────────────────────
RDEV_SERVER=""
RDEV_ID=""
RDEV_PASSWORD=""
RDEV_SHELL=""
RDEV_SSH_PORT=""
RDEV_VERSION=""
RDEV_CLIENT="go"
RDEV_ENROLL=0
RDEV_PERSIST=0
RDEV_IDENTITY_FILE=""
RDEV_ENROLLMENT_CODE="${RDEV_ENROLLMENT_CODE:-}"
RDEV_REPO="icepie/rdev"
LOCAL_CLIENT_REVISION="feidu-20260903-scp3"
LOCAL_MANAGED_CLIENT_REVISION="feidu-20260904-managed1"
LOCAL_WINDOWS_AMD64_ASSET="rdev-client-windows-amd64.exe"
LOCAL_WINDOWS_AMD64_SHA256="d85e262d4b39b065ba0f7cef5bd4f79fba435cd5956080c6f3f1dca908d61d3b"

# CN GitHub mirrors (tried first, fallback to direct)
# Override with: RDEV_MIRRORS="mirror1 mirror2" sh run.sh ...
MIRRORS="${RDEV_MIRRORS:-gh.idayer.com gh.ddlc.top gh-proxy.com ghfast.top ghproxy.net ghproxy.cc gh-proxy.net ghproxy.cfd github.moeyy.xyz hub.gitmirror.com ghproxy.1888866.xyz ghproxy.sakuramoe.dev}"

# ── Parse arguments ─────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--server)   RDEV_SERVER="$2"; shift 2 ;;
        -i|--id)       RDEV_ID="$2"; shift 2 ;;
        -p|--password) RDEV_PASSWORD="$2"; shift 2 ;;
        -S|--shell)    RDEV_SHELL="$2"; shift 2 ;;
        --ssh-port)    RDEV_SSH_PORT="$2"; shift 2 ;;
        -v|--version)  RDEV_VERSION="$2"; shift 2 ;;
        --client)      RDEV_CLIENT="$2"; shift 2 ;;
        --go)          RDEV_CLIENT="go"; shift ;;
        --rs)          RDEV_CLIENT="rs"; shift ;;
        --no-mirror)   MIRRORS=""; shift ;;
        --enroll)      RDEV_ENROLL=1; shift ;;
        --persist)     RDEV_ENROLL=1; RDEV_PERSIST=1; shift ;;
        --identity-file) RDEV_IDENTITY_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: sh run.sh SERVER_URL [options]"
            echo ""
            echo "  Downloads a client to /tmp and runs it directly."
            echo "  Default client is compatible Go; use --client rs for performance Rust."
            echo "  No installation or root required."
            echo ""
            echo "Options:"
            echo "  -s, --server URL     Server URL or comma-separated URL group"
            echo "  -i, --id ID          Device ID (default: hostname)"
            echo "  -p, --password PW    Password for SSH auth"
            echo "  -S, --shell PATH     Shell path (e.g. /bin/bash)"
            echo "  --ssh-port PORT      Server SSH port hint (Go client only)"
            echo "  -v, --version VER    Client version (default: latest)"
            echo "  --client go|rs       Client flavor: compatible Go or performance Rust"
            echo "  --go, --rs           Shorthand for --client go|rs"
            echo "  --no-mirror          Skip CN mirrors (direct server/GitHub sources remain)"
            echo "  --enroll             Prompt for a one-time enrollment code"
            echo "  --persist            Enroll and install a systemd service (Linux)"
            echo "  --identity-file PATH Protected managed-device identity path"
            echo ""
            echo "Examples:"
            echo "  curl -sL http://SERVER/run.sh | sh -s -- ws://SERVER:8080"
            echo "  curl -sL http://SERVER/run.sh | sh -s -- ws://SERVER:8080 -i my-pc -p secret"
            echo "  curl -sL http://SERVER/run.sh | sh -s -- ws://SERVER:8080 --client rs"
            exit 0 ;;
        ws://*|wss://*|tcp://*|kcp://*|udp://*) RDEV_SERVER="$1"; shift ;;
        http://*|https://*) RDEV_SERVER="$1"; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

case "$RDEV_CLIENT" in
    go|GO|Go) RDEV_CLIENT="go" ;;
    rs|RS|Rust|rust) RDEV_CLIENT="rs" ;;
    *) echo "Error: unsupported client: $RDEV_CLIENT (expected go or rs)" >&2; exit 1 ;;
esac

if [ -z "$RDEV_SERVER" ]; then
    echo "Error: server URL required" >&2
    echo "Usage: curl -sL http://SERVER/run.sh | sh -s -- ws://SERVER:PORT" >&2
    exit 1
fi

ANDROID_ENV=0
if [ "$(uname -o 2>/dev/null || true)" = "Android" ] || [ -n "${ANDROID_ROOT:-}" ]; then
    ANDROID_ENV=1
fi

# ── Optional elevation prompt ───────────────────────────────
RDEV_ELEVATE=0

wait_elevation_key() {
    (: </dev/tty) 2>/dev/null || return 1
    printf '%s' "  Not running as root. Press any key within 3 seconds to run elevated; waiting continues normal mode... " >/dev/tty
    old_stty="$(stty -g </dev/tty 2>/dev/null || true)"
    if [ -n "$old_stty" ]; then
        stty raw -echo min 0 time 30 </dev/tty 2>/dev/null || true
        key_file="${TMPDIR:-/tmp}/rdev-key-$$"
        dd bs=1 count=1 of="$key_file" 2>/dev/null </dev/tty || true
        stty "$old_stty" </dev/tty 2>/dev/null || true
        printf '\n' >/dev/tty
        if [ -s "$key_file" ]; then
            rm -f "$key_file" 2>/dev/null
            return 0
        fi
        rm -f "$key_file" 2>/dev/null
        return 1
    fi
    # POSIX sh has no timed read; probe the active shell before using its -t extension.
    # shellcheck disable=SC3045
    if (IFS= read -r -t 0 _ </dev/tty) 2>/dev/null; then
        # shellcheck disable=SC3045
        if IFS= read -r -t 3 _ </dev/tty; then
            printf '\n' >/dev/tty
            return 0
        fi
        printf '\n' >/dev/tty
    fi
    return 1
}

if [ "$RDEV_ENROLL" != "1" ] && [ "$RDEV_PERSIST" != "1" ] && [ "$ANDROID_ENV" != "1" ] && [ "$(id -u 2>/dev/null || echo 1)" != "0" ]; then
    if wait_elevation_key; then
        RDEV_ELEVATE=1
        echo "  Elevation requested; will start client with sudo/doas after download." >&2
    else
        echo "  Continuing in normal user mode." >&2
    fi
fi

# ── Detect OS / Arch ────────────────────────────────────────
OS="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"

case "$OS" in
    Linux*)
        if [ "$ANDROID_ENV" = "1" ]; then OS="android"; else OS="linux"; fi
        ;;
    Darwin*)  OS="darwin" ;;
    FreeBSD*) OS="freebsd" ;;
    OpenBSD*) OS="openbsd" ;;
    NetBSD*)  OS="netbsd" ;;
    MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
    *)        echo "Error: unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64|x64)       ARCH="amd64" ;;
    aarch64|arm64|armv8l)    ARCH="arm64" ;;
    armv7l|armv7|armhf)      ARCH="armv7" ;;
    armv6l|armv6)            ARCH="armv6" ;;
    i386|i686|x86)           ARCH="386" ;;
    *) echo "Error: unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# ── Detect download tool ────────────────────────────────────
DL_TOOL=""
if command -v curl >/dev/null 2>&1; then DL_TOOL="curl"
elif command -v wget >/dev/null 2>&1; then DL_TOOL="wget"
elif command -v fetch >/dev/null 2>&1; then DL_TOOL="fetch"
elif command -v busybox >/dev/null 2>&1 && busybox --list 2>/dev/null | grep -q wget; then DL_TOOL="busybox_wget"
else echo "Error: need curl, wget, or fetch" >&2; exit 1
fi

dl() {
    case "$DL_TOOL" in
        curl)         curl -fsSL --connect-timeout 10 --max-time 120 "$1" -o "$2" ;;
        wget)         wget -q --timeout=120 -O "$2" "$1" ;;
        fetch)        fetch -o "$2" "$1" ;;
        busybox_wget) busybox wget -O "$2" "$1" ;;
    esac
}

mirror_url() {
    echo "https://$1/$2"
}

server_http_base() {
    first_ws=""
    first_any=""
    old_ifs=$IFS
    IFS=','
    for endpoint in $RDEV_SERVER; do
        endpoint=$(printf '%s' "$endpoint" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -n "$endpoint" ] || continue
        [ -n "$first_any" ] || first_any="$endpoint"
        case "$endpoint" in
            wss://*|ws://*|http://*|https://*) first_ws="$endpoint"; break ;;
        esac
    done
    IFS=$old_ifs
    endpoint="${first_ws:-$first_any}"
    case "$endpoint" in
        wss://*) base="https://${endpoint#wss://}" ;;
        ws://*)  base="http://${endpoint#ws://}" ;;
        http://*|https://*) base="$endpoint" ;;
        tcp://*|kcp://*|udp://*) return 1 ;;
        *) return 1 ;;
    esac
    proto="${base%%://*}"
    rest="${base#*://}"
    host="${rest%%/*}"
    host="${host%%\?*}"
    host="${host%%#*}"
    [ -n "$host" ] || return 1
    echo "$proto://$host"
}

release_proxy_url() {
    base="$(server_http_base 2>/dev/null || true)"
    [ -n "$base" ] || return 1
    asset="$1"
    tag="$TAG"
    [ -n "$tag" ] || tag="latest"
    echo "$base/download-release-proxy?asset=$asset&tag=$tag"
}

release_direct_url() {
    base="$(server_http_base 2>/dev/null || true)"
    [ -n "$base" ] || return 1
    asset="$1"
    tag="${RESOLVED_TAG:-${TAG:-latest}}"
    echo "$base/download-release?asset=$asset&tag=$tag"
}

local_release_url() {
    base="$(server_http_base 2>/dev/null || true)"
    [ -n "$base" ] || return 1
    echo "$base/local-release?asset=$1"
}

client_supports_managed_enrollment() {
    managed_client_path="$1"
    [ -s "$managed_client_path" ] || return 1
    chmod +x "$managed_client_path" 2>/dev/null || true
    help_output="$($managed_client_path --help 2>&1 || true)"
    printf '%s\n' "$help_output" | grep -F -- '--enroll-stdin' >/dev/null 2>&1 &&
        printf '%s\n' "$help_output" | grep -F -- '--identity-file' >/dev/null 2>&1 &&
        printf '%s\n' "$help_output" | grep -F -- '--replace-existing' >/dev/null 2>&1
}

sha256_file() {
    file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | sed 's/^.*= //'
    else
        return 1
    fi
}

json_tag_value() {
    sed -n 's/.*"tag"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

resolve_latest_tag() {
    if [ "$TAG" != "latest" ]; then
        RESOLVED_TAG="$TAG"
        return
    fi
    RESOLVED_TAG=""
    base="$(server_http_base 2>/dev/null || true)"
    tmp_latest="${TMPBASE:-${TMPDIR:-/tmp}}/rdev-latest-$$.json"
    if [ -n "$base" ]; then
        if dl "$base/api/release/latest" "$tmp_latest" 2>/dev/null && [ -s "$tmp_latest" ]; then
            RESOLVED_TAG="$(json_tag_value < "$tmp_latest")"
        fi
        rm -f "$tmp_latest" 2>/dev/null
    fi
    if [ -z "$RESOLVED_TAG" ]; then
        tmp_hdr="${TMPBASE:-${TMPDIR:-/tmp}}/rdev-latest-$$.hdr"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSLI --connect-timeout 5 --max-time 12 "https://github.com/${RDEV_REPO}/releases/latest" > "$tmp_hdr" 2>/dev/null || true
            RESOLVED_TAG="$(sed -n 's|^[Ll]ocation: .*/tag/\(v[^[:space:]\r]*\).*|\1|p' "$tmp_hdr" | tail -1)"
        fi
        rm -f "$tmp_hdr" 2>/dev/null
    fi
    if [ -z "$RESOLVED_TAG" ]; then
        RESOLVED_TAG="latest"
        echo "  Latest tag could not be resolved; using cache key 'latest'." >&2
    fi
}

safe_name() {
    printf '%s' "$1" | sed 's/[^A-Za-z0-9_.-]/-/g'
}

cache_lock_acquire() {
    lock_dir="$1.lock"
    i=0
    while ! mkdir "$lock_dir" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -ge 50 ] && return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
    CACHE_LOCK_DIR="$lock_dir"
    return 0
}

cache_lock_release() {
    if [ -n "${CACHE_LOCK_DIR:-}" ]; then
        rmdir "$CACHE_LOCK_DIR" 2>/dev/null || true
    fi
    CACHE_LOCK_DIR=""
}

cache_complete() {
    bin="$1"
    dir="$2"
    [ -f "$dir/.complete" ] && [ -s "$bin" ] && [ -x "$bin" ]
}

# ── Determine version ──────────────────────────────────────
if [ -n "$RDEV_VERSION" ]; then
    case "$RDEV_VERSION" in v*) TAG="$RDEV_VERSION" ;; *) TAG="v${RDEV_VERSION}" ;; esac
else
    TAG="latest"
fi

release_url() {
    if [ "$TAG" = "latest" ]; then
        echo "https://github.com/${RDEV_REPO}/releases/latest/download/$1"
    else
        echo "https://github.com/${RDEV_REPO}/releases/download/${TAG}/$1"
    fi
}

download_with_fallback() {
    url="$1"
    out="$2"
    asset="$3"
    [ -n "$asset" ] || asset="${url##*/}"
    ok=0
    if [ "$RDEV_CLIENT" = "go" ] && [ "$RDEV_ENROLL" = "1" ] && [ "$OS" = "linux" ]; then
        local_url="$(local_release_url "$asset" 2>/dev/null || true)"
        if [ -n "$local_url" ]; then
            echo "  Trying managed RDev client..." >&2
            if dl "$local_url" "$out" && client_supports_managed_enrollment "$out"; then
                ok=1
                echo "  ok via managed RDev client" >&2
            fi
            [ "$ok" = "1" ] || rm -f "$out" 2>/dev/null
        fi
    fi
    if [ "$ok" = "0" ] && [ "$asset" = "$LOCAL_WINDOWS_AMD64_ASSET" ]; then
        local_url="$(local_release_url "$asset" 2>/dev/null || true)"
        if [ -n "$local_url" ]; then
            echo "  Trying verified RDev client..." >&2
            if dl "$local_url" "$out" && [ -s "$out" ]; then
                actual_hash="$(sha256_file "$out" 2>/dev/null || true)"
                if [ "$actual_hash" = "$LOCAL_WINDOWS_AMD64_SHA256" ]; then
                    ok=1
                    echo "  ok via verified RDev client" >&2
                else
                    echo "  Local client SHA-256 verification failed" >&2
                fi
            fi
            [ "$ok" = "1" ] || rm -f "$out" 2>/dev/null
        fi
    fi
    direct_url="$(release_direct_url "$asset" 2>/dev/null || true)"
    if [ "$ok" = "0" ] && [ -n "$direct_url" ]; then
        echo "  Selecting fastest release source..." >&2
        if dl "$direct_url" "$out" && [ -s "$out" ]; then ok=1; echo "  ok via measured release source" >&2; fi
        [ "$ok" = "1" ] || rm -f "$out" 2>/dev/null
    fi
    for m in $MIRRORS; do
        [ "$ok" = "1" ] && break
        [ -z "$m" ] && continue
        echo "  Trying ${m}..." >&2
        if dl "$(mirror_url "$m" "$url")" "$out" 2>/dev/null && [ -s "$out" ]; then
            ok=1
            echo "  ok via ${m}" >&2
            break
        fi
        rm -f "$out" 2>/dev/null
    done
    if [ "$ok" = "0" ]; then
        echo "  Trying github.com..." >&2
        if dl "$url" "$out" && [ -s "$out" ]; then ok=1; echo "  ok via github.com" >&2; fi
    fi
    if [ "$ok" = "0" ]; then
        proxy_url="$(release_proxy_url "$asset" 2>/dev/null || true)"
        if [ -n "$proxy_url" ]; then
            echo "  Trying RDev server proxy (last resort)..." >&2
            if dl "$proxy_url" "$out" && [ -s "$out" ]; then ok=1; echo "  ok via RDev server proxy" >&2; fi
            [ "$ok" = "1" ] || rm -f "$out" 2>/dev/null
        fi
    fi
    if [ "$ok" = "1" ] && [ "$RDEV_CLIENT" = "go" ] && [ "$RDEV_ENROLL" = "1" ] && ! client_supports_managed_enrollment "$out"; then
        echo "  Downloaded client does not support managed enrollment." >&2
        rm -f "$out" 2>/dev/null
        ok=0
    fi
    [ "$ok" = "1" ]
}

linux_rs_asset_suffix() {
    [ "$OS" = "linux" ] || { echo ""; return; }
    if [ -r /etc/os-release ] && grep -Eq '^ID=(arch|"arch")$' /etc/os-release 2>/dev/null; then
        echo ""
        return
    fi
    ver=""
    if command -v getconf >/dev/null 2>&1; then
        ver="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
    fi
    [ -n "$ver" ] || ver="$(ldd --version 2>/dev/null | sed -n '1s/.* //p')"
    case "$ver" in
        [0-9]*.[0-9]*) ;;
        *) echo "-debian11"; return ;;
    esac
    major=${ver%%.*}
    minor=${ver#*.}; minor=${minor%%.*}
    if [ "$major" -lt 2 ] 2>/dev/null || { [ "$major" -eq 2 ] 2>/dev/null && [ "$minor" -lt 28 ] 2>/dev/null; }; then
        if [ "$ARCH" = "amd64" ]; then echo "-centos7"; else echo "-centos8"; fi
    elif [ "$major" -eq 2 ] 2>/dev/null && [ "$minor" -lt 31 ] 2>/dev/null; then
        echo "-centos8"
    elif [ "$major" -eq 2 ] 2>/dev/null && [ "$minor" -lt 36 ] 2>/dev/null; then
        echo "-debian11"
    elif [ "$major" -eq 2 ] 2>/dev/null && [ "$minor" -lt 41 ] 2>/dev/null; then
        echo "-debian12"
    else
        echo ""
    fi
}

extract_zip() {
    zip_file="$1"
    dest_dir="$2"
    if command -v unzip >/dev/null 2>&1 && unzip -q "$zip_file" -d "$dest_dir" 2>/dev/null; then
        return 0
    fi
    # Windows 10+ ships bsdtar as tar.exe and it reads zip; GNU tar does not,
    # so probe by running it rather than by presence.
    for tar_bin in bsdtar tar; do
        command -v "$tar_bin" >/dev/null 2>&1 || continue
        if (cd "$dest_dir" && "$tar_bin" -xf "$zip_file") 2>/dev/null; then
            return 0
        fi
    done
    for zip_bin in 7z 7za 7zz; do
        command -v "$zip_bin" >/dev/null 2>&1 || continue
        if "$zip_bin" x -y -o"$dest_dir" "$zip_file" >/dev/null 2>&1; then
            return 0
        fi
    done
    # Last resort for Windows shells (Git Bash / busybox) with no archiver.
    for ps_bin in powershell.exe pwsh.exe powershell pwsh; do
        command -v "$ps_bin" >/dev/null 2>&1 || continue
        ps_zip="$zip_file"
        ps_dest="$dest_dir"
        if command -v cygpath >/dev/null 2>&1; then
            ps_zip="$(cygpath -w "$zip_file" 2>/dev/null || echo "$zip_file")"
            ps_dest="$(cygpath -w "$dest_dir" 2>/dev/null || echo "$dest_dir")"
        fi
        if "$ps_bin" -NoProfile -NonInteractive -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('$ps_zip','$ps_dest')" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# ── Resolve asset and download ─────────────────────────────
TMPBASE="${TMPDIR:-/tmp}"
CACHE_BASE="$TMPBASE/rdev-cache"
mkdir -p "$CACHE_BASE" 2>/dev/null || true
resolve_latest_tag
SAFE_TAG="$(safe_name "$RESOLVED_TAG")"
RUN_BIN=""
CLIENT_LABEL="rdev-client"

if [ "$RDEV_CLIENT" = "rs" ]; then
    CLIENT_LABEL="rdev-client-gpu"
    case "$OS/$ARCH" in
        linux/amd64|linux/arm64)
            ASSET="rdev-client-gpu-${OS}-${ARCH}$(linux_rs_asset_suffix).tar.gz"
            ARCHIVE="$TMPBASE/rdev-client-gpu-${SAFE_TAG}-${OS}-${ARCH}-$$.tar.gz"
            ;;
        android/amd64|android/arm64|android/armv7|android/386)
            ASSET_ARCH="$ARCH"
            [ "$ARCH" = "386" ] && ASSET_ARCH="x86"
            ASSET="rdev-client-gpu-${OS}-${ASSET_ARCH}.tar.gz"
            ARCHIVE="$TMPBASE/rdev-client-gpu-${SAFE_TAG}-${OS}-${ASSET_ARCH}-$$.tar.gz"
            ;;
        darwin/amd64|darwin/arm64)
            ASSET="rdev-client-gpu-${OS}-${ARCH}.tar.gz"
            ARCHIVE="$TMPBASE/rdev-client-gpu-${SAFE_TAG}-${OS}-${ARCH}-$$.tar.gz"
            ;;
        windows/amd64|windows/arm64)
            ASSET="rdev-client-gpu-windows-${ARCH}.zip"
            ARCHIVE="$TMPBASE/rdev-client-gpu-${SAFE_TAG}-windows-${ARCH}-$$.zip"
            ;;
        *)
            echo "Error: performance Rust client is not published for ${OS}/${ARCH}" >&2
            exit 1
            ;;
    esac
    GH_URL="$(release_url "$ASSET")"
    CACHE_KEY="rs-${SAFE_TAG}-${OS}-${ARCH}-$(safe_name "$ASSET")"
    CACHE_DIR="$CACHE_BASE/$CACHE_KEY"
    CACHE_BIN="$CACHE_DIR/rdev-client-gpu"
    [ "$OS" = "windows" ] && CACHE_BIN="$CACHE_DIR/rdev-client-gpu.exe"
    if cache_complete "$CACHE_BIN" "$CACHE_DIR"; then
        RUN_BIN="$CACHE_BIN"
        echo "  Using cached ${CLIENT_LABEL} (${RESOLVED_TAG}, ${OS}/${ARCH})." >&2
    else
    echo "  Downloading ${CLIENT_LABEL} package (${OS}/${ARCH})..." >&2
    if ! download_with_fallback "$GH_URL" "$ARCHIVE" "$ASSET"; then
        echo "Error: download failed" >&2
        rm -f "$ARCHIVE" 2>/dev/null
        exit 1
    fi

    EXTRACT_DIR="$TMPBASE/rdev-client-gpu-${SAFE_TAG}-${OS}-${ARCH}-$$"
    rm -rf "$EXTRACT_DIR" 2>/dev/null
    mkdir -p "$EXTRACT_DIR"
    case "$ASSET" in
        *.tar.gz)
            command -v tar >/dev/null 2>&1 || { echo "Error: tar is required for Rust client package" >&2; exit 1; }
            tar -xzf "$ARCHIVE" -C "$EXTRACT_DIR"
            RUN_BIN="$(find "$EXTRACT_DIR" -type f -name rdev-client-gpu | head -1)"
            ;;
        *.zip)
            extract_zip "$ARCHIVE" "$EXTRACT_DIR" || { echo "Error: need unzip, bsdtar, 7z, or PowerShell to extract Rust client package" >&2; exit 1; }
            RUN_BIN="$(find "$EXTRACT_DIR" -type f -name rdev-client-gpu.exe | head -1)"
            ;;
    esac
    [ -n "$RUN_BIN" ] || { echo "Error: rdev-client-gpu binary not found in package" >&2; exit 1; }
    chmod +x "$RUN_BIN" 2>/dev/null || true
    if cache_lock_acquire "$CACHE_DIR"; then
        rm -rf "$CACHE_DIR.part" 2>/dev/null
        mkdir -p "$CACHE_DIR.part"
        cp "$RUN_BIN" "$CACHE_DIR.part/$(basename "$CACHE_BIN")"
        chmod +x "$CACHE_DIR.part/$(basename "$CACHE_BIN")" 2>/dev/null || true
        : > "$CACHE_DIR.part/.complete"
        rm -rf "$CACHE_DIR" 2>/dev/null
        mv "$CACHE_DIR.part" "$CACHE_DIR"
        cache_lock_release
        RUN_BIN="$CACHE_BIN"
    fi
    rm -f "$ARCHIVE" 2>/dev/null || true
    rm -rf "$EXTRACT_DIR" 2>/dev/null || true
    fi
else
    ASSET_ARCH="$ARCH"
    if [ "$OS" = "android" ]; then
        case "$ARCH" in
            amd64|arm64|armv7) ;;
            386) ASSET_ARCH="x86" ;;
            *) echo "Error: compatible Go client is not published for ${OS}/${ARCH}" >&2; exit 1 ;;
        esac
    fi
    BINARY="rdev-client-${OS}-${ASSET_ARCH}"
    [ "$OS" = "windows" ] && BINARY="${BINARY}.exe"
    GH_URL="$(release_url "$BINARY")"
    CACHE_KEY="go-${SAFE_TAG}-${OS}-${ASSET_ARCH}-$(safe_name "$BINARY")"
    [ "$BINARY" = "$LOCAL_WINDOWS_AMD64_ASSET" ] && CACHE_KEY="${CACHE_KEY}-${LOCAL_CLIENT_REVISION}"
    [ "$RDEV_ENROLL" = "1" ] && CACHE_KEY="${CACHE_KEY}-${LOCAL_MANAGED_CLIENT_REVISION}"
    CACHE_DIR="$CACHE_BASE/$CACHE_KEY"
    CACHE_BIN="$CACHE_DIR/$BINARY"
    if cache_complete "$CACHE_BIN" "$CACHE_DIR" && { [ "$RDEV_ENROLL" != "1" ] || client_supports_managed_enrollment "$CACHE_BIN"; }; then
        RUN_BIN="$CACHE_BIN"
        echo "  Using cached rdev-client (${RESOLVED_TAG}, ${OS}/${ARCH})." >&2
    else
    RUN_BIN="$TMPBASE/rdev-client-${SAFE_TAG}-${OS}-${ASSET_ARCH}-$$"
    echo "  Downloading rdev-client (${OS}/${ARCH})..." >&2
    if ! download_with_fallback "$GH_URL" "$RUN_BIN" "$BINARY"; then
        echo "Error: download failed" >&2
        rm -f "$RUN_BIN" 2>/dev/null
        exit 1
    fi
    chmod +x "$RUN_BIN"
    if cache_lock_acquire "$CACHE_DIR"; then
        rm -rf "$CACHE_DIR.part" 2>/dev/null
        mkdir -p "$CACHE_DIR.part"
        cp "$RUN_BIN" "$CACHE_DIR.part/$BINARY"
        chmod +x "$CACHE_DIR.part/$BINARY" 2>/dev/null || true
        : > "$CACHE_DIR.part/.complete"
        rm -rf "$CACHE_DIR" 2>/dev/null
        mv "$CACHE_DIR.part" "$CACHE_DIR"
        cache_lock_release
        rm -f "$RUN_BIN" 2>/dev/null || true
        RUN_BIN="$CACHE_BIN"
    fi
    fi
fi

# ── Build args & run ───────────────────────────────────────
if [ "$RDEV_CLIENT" = "rs" ] && [ -z "$RDEV_ID" ]; then
    RDEV_ID="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo rdev-client-gpu)"
fi

if [ "$OS" = "android" ] && [ -z "$RDEV_SHELL" ]; then
    if [ -x "${PREFIX:-}/bin/bash" ]; then
        RDEV_SHELL="${PREFIX}/bin/bash"
    elif [ -x "${PREFIX:-}/bin/sh" ]; then
        RDEV_SHELL="${PREFIX}/bin/sh"
    elif [ -x /system/bin/sh ]; then
        RDEV_SHELL="/system/bin/sh"
    fi
fi

if [ "$RDEV_CLIENT" = "rs" ]; then
    set -- -s "$RDEV_SERVER"
    [ -n "$RDEV_ID" ] && set -- "$@" -i "$RDEV_ID"
    [ -n "$RDEV_PASSWORD" ] && set -- "$@" -p "$RDEV_PASSWORD"
    [ -n "$RDEV_SHELL" ] && set -- "$@" --shell "$RDEV_SHELL"
else
    set -- -s "$RDEV_SERVER"
    [ -n "$RDEV_ID" ] && set -- "$@" -i "$RDEV_ID"
    [ -n "$RDEV_PASSWORD" ] && set -- "$@" -p "$RDEV_PASSWORD"
    [ -n "$RDEV_SHELL" ] && set -- "$@" -S "$RDEV_SHELL"
    [ -n "$RDEV_SSH_PORT" ] && set -- "$@" --ssh-port "$RDEV_SSH_PORT"
    [ -n "$RDEV_IDENTITY_FILE" ] && set -- "$@" --identity-file "$RDEV_IDENTITY_FILE"
fi

echo "" >&2
echo "  Starting ${CLIENT_LABEL}..." >&2
printf '  Binary: %s\n\n' "$RUN_BIN" >&2

read_enrollment_code() {
    if [ -n "$RDEV_ENROLLMENT_CODE" ]; then
        ENROLLMENT_CODE="$RDEV_ENROLLMENT_CODE"
        RDEV_ENROLLMENT_CODE=""
        return 0
    fi
    [ -r /dev/tty ] || { echo "Error: enrollment requires an interactive terminal" >&2; return 1; }
    printf '%s' "  One-time enrollment code: " >/dev/tty
    old_stty="$(stty -g </dev/tty 2>/dev/null || true)"
    if [ -n "$old_stty" ]; then
        stty -echo </dev/tty 2>/dev/null || true
    fi
    IFS= read -r ENROLLMENT_CODE </dev/tty
    if [ -n "$old_stty" ]; then
        stty "$old_stty" </dev/tty 2>/dev/null || true
    fi
    printf '\n' >/dev/tty
    [ -n "$ENROLLMENT_CODE" ] || { echo "Error: enrollment code is empty" >&2; return 1; }
}

run_as_root() {
    if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    elif command -v doas >/dev/null 2>&1; then
        doas "$@"
    else
        echo "Error: persistent installation requires root, sudo, or doas" >&2
        return 1
    fi
}

if [ "$RDEV_PERSIST" = "1" ]; then
    [ "$RDEV_CLIENT" = "go" ] || { echo "Error: persistent enrollment requires the compatible Go client" >&2; exit 1; }
    [ "$OS" = "linux" ] || { echo "Error: persistent mode currently requires Linux and systemd" >&2; exit 1; }
    command -v systemctl >/dev/null 2>&1 || { echo "Error: systemd is required for persistent mode" >&2; exit 1; }
    read_enrollment_code
    INSTALL_DIR="/usr/local/lib/rdev"
    INSTALLED_BIN="$INSTALL_DIR/rdev-client"
    IDENTITY_PATH="${RDEV_IDENTITY_FILE:-/var/lib/rdev/identity.json}"
    case "$IDENTITY_PATH" in *[[:space:]]*) echo "Error: persistent identity path must not contain whitespace" >&2; exit 1 ;; esac
    UNIT_TMP="${TMPDIR:-/tmp}/rdev-client-$$.service"
    trap 'rm -f "$UNIT_TMP" 2>/dev/null' EXIT HUP INT TERM
    run_as_root mkdir -p "$INSTALL_DIR" "$(dirname "$IDENTITY_PATH")"
    run_as_root install -m 0755 "$RUN_BIN" "$INSTALLED_BIN"
    set -- -s "$RDEV_SERVER"
    [ -n "$RDEV_ID" ] && set -- "$@" -i "$RDEV_ID"
    set -- "$@" --enroll-stdin --enroll-only --replace-existing --identity-file "$IDENTITY_PATH"
    printf '%s\n' "$ENROLLMENT_CODE" | run_as_root "$INSTALLED_BIN" "$@"
    ENROLLMENT_CODE=""
    umask 077
    printf '%s\n' \
        '[Unit]' \
        'Description=RDev Remote Debug Client' \
        'After=network-online.target' \
        'Wants=network-online.target' \
        '' \
        '[Service]' \
        'Type=simple' \
        "ExecStart=$INSTALLED_BIN --identity-file $IDENTITY_PATH" \
        'Restart=always' \
        'RestartSec=2' \
        '' \
        '[Install]' \
        'WantedBy=multi-user.target' > "$UNIT_TMP"
    run_as_root install -m 0644 "$UNIT_TMP" /etc/systemd/system/rdev-client.service
    run_as_root systemctl daemon-reload
    run_as_root systemctl enable --now rdev-client.service
    echo "  RDev is installed and will reconnect automatically." >&2
    exit 0
fi

if [ "$RDEV_ENROLL" = "1" ]; then
    [ "$RDEV_CLIENT" = "go" ] || { echo "Error: enrollment requires the compatible Go client" >&2; exit 1; }
    read_enrollment_code
    set -- "$@" --enroll-stdin
    printf '%s\n' "$ENROLLMENT_CODE" | "$RUN_BIN" "$@"
    status=$?
    ENROLLMENT_CODE=""
    exit "$status"
fi

if [ "$RDEV_ELEVATE" = "1" ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo "$RUN_BIN" "$@"
    elif command -v doas >/dev/null 2>&1; then
        exec doas "$RUN_BIN" "$@"
    else
        echo "  sudo/doas not found; continuing in normal user mode." >&2
    fi
fi

exec "$RUN_BIN" "$@"
