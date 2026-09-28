#!/usr/bin/env python3
"""Build the go-win7 client with pre-KB2533623 system-DLL loading support.

Only a private copy of the supplied go-win7 toolchain is patched. The normal
Go installation, module cache, launcher, and production assets are untouched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise RuntimeError('Unexpected toolchain source; patch must be reviewed: ' + before[:70])
    return text.replace(before, after, 1)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--toolchain', type=Path, required=True)
parser.add_argument('--output', type=Path, default=Path('work/win7-rtm'))
parser.add_argument('--version', default='win7-rtm-compat-1')
parser.add_argument('--arch', choices=['amd64', '386'], default='amd64')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
source = args.toolchain.resolve()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
toolchain = output / '_go-win7-rtm'
if not toolchain.exists():
    subprocess.run(['cp', '-a', '--reflink=auto', str(source), str(toolchain)], check=True)

patches = {}
runtime_path = 'src/runtime/os_windows.go'
runtime = (source / runtime_path).read_text()
assert sha(runtime.encode()) == '09606a0fa068bb0b2e930e41e786c3ab25be59f5667285791dca13a46e11b834', 'Unexpected go-win7 runtime source'
runtime = replace_once(runtime,
    '//go:cgo_import_dynamic runtime._GetSystemDirectoryA GetSystemDirectoryA%2 "kernel32.dll"',
    '//go:cgo_import_dynamic runtime._GetSystemDirectoryA GetSystemDirectoryA%2 "kernel32.dll"\n//go:cgo_import_dynamic runtime._GetSystemDirectoryW GetSystemDirectoryW%2 "kernel32.dll"')
runtime = replace_once(runtime, '\t_GetSystemDirectoryA,', '\t_GetSystemDirectoryA,\n\t_GetSystemDirectoryW,')
runtime = replace_once(runtime, '''	const _LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
	return stdcall(_LoadLibraryExW, uintptr(unsafe.Pointer(&name[0])), 0, _LOAD_LIBRARY_SEARCH_SYSTEM32)''', r'''	// Win7 RTM lacks LOAD_LIBRARY_SEARCH_SYSTEM32 until KB2533623.
	// Resolve the system directory directly, before initSysDirectory runs.
	var path [_MAX_PATH + 64]uint16
	n := stdcall(_GetSystemDirectoryW, uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	if n == 0 || n+1+uintptr(len(name)) > uintptr(len(path)) {
		throw("Unable to determine system DLL path")
	}
	path[n] = 0x5c
	copy(path[n+1:], name)
	return stdcall(_LoadLibraryExW, uintptr(unsafe.Pointer(&path[0])), 0, 0)''')
patches[runtime_path] = runtime

syscall_path = 'src/syscall/dll_windows.go'
syscall = (source / syscall_path).read_text()
assert sha(syscall.encode()) == 'fea84c96a3b8cbe83e7670fdf87db829de71e192d099d9e8ef1539dd9991a5ca', 'Unexpected go-win7 syscall source'
syscall = replace_once(syscall,
    '//go:cgo_import_dynamic syscall.__LoadLibraryExW LoadLibraryExW%3 "kernel32.dll"',
    '//go:cgo_import_dynamic syscall.__LoadLibraryExW LoadLibraryExW%3 "kernel32.dll"\n//go:cgo_import_dynamic syscall.__GetSystemDirectoryW GetSystemDirectoryW%2 "kernel32.dll"')
syscall = replace_once(syscall, '\t__LoadLibraryExW unsafe.Pointer', '\t__LoadLibraryExW unsafe.Pointer\n\t__GetSystemDirectoryW unsafe.Pointer')
syscall = replace_once(syscall, '''	const _LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
	handle, _, err := SyscallN(uintptr(__LoadLibraryExW), uintptr(unsafe.Pointer(filename)), 0, _LOAD_LIBRARY_SEARCH_SYSTEM32)''', r'''	// Resolve system DLLs without the post-Win7-RTM loader flag.
	var path [MAX_PATH + 64]uint16
	n, _, err := SyscallN(uintptr(__GetSystemDirectoryW), uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	if n == 0 {
		return 0, err
	}
	if n+1 >= uintptr(len(path)) {
		return 0, ENAMETOOLONG
	}
	path[n] = 0x5c
	n++
	for i := uintptr(0); ; i++ {
		if n >= uintptr(len(path)) {
			return 0, ENAMETOOLONG
		}
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(filename), i*2))
		path[n] = c
		n++
		if c == 0 {
			break
		}
	}
	handle, _, err := SyscallN(uintptr(__LoadLibraryExW), uintptr(unsafe.Pointer(&path[0])), 0, 0)''')
patches[syscall_path] = syscall

socket_path = 'src/net/sock_windows.go'
socket = (source / socket_path).read_text()
assert sha(socket.encode()) == 'c24d90f9a90da5aefbe40d45c84c26e1ea5869a20e142f1f1101e7fd0f2f981d', 'Unexpected go-win7 socket source'
socket = replace_once(socket, '''	s, err := wsaSocketFunc(int32(family), int32(sotype), int32(proto),
		nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)''', '''	s, err := wsaSocketNoInherit(int32(family), int32(sotype), int32(proto), nil, 0)''')
socket += '''
// wsaSocketNoInherit also supports Win7 RTM, where NO_HANDLE_INHERIT is
// rejected as WSAEINVAL or WSAEPROTOTYPE. Other errors are not retried.
func wsaSocketNoInherit(family, sotype, proto int32, info *syscall.WSAProtocolInfo, group uint32) (syscall.Handle, error) {
	s, err := wsaSocketFunc(family, sotype, proto, info, group, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != windows.WSAEINVAL && err != syscall.Errno(10041) {
		return s, err
	}
	s, err = wsaSocketFunc(family, sotype, proto, info, group, windows.WSA_FLAG_OVERLAPPED)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	// CloseOnExec discards this error; check it so a failed conversion never
	// returns an inheritable socket to the caller.
	if err = syscall.SetHandleInformation(s, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
		syscall.Closesocket(s)
		return syscall.InvalidHandle, err
	}
	return s, nil
}
'''
patches[socket_path] = socket

file_path = 'src/net/file_windows.go'
file_socket = (source / file_path).read_text()
assert sha(file_socket.encode()) == '33005305d01549b938d1f6c08fa7b3ac0dd899f4575ebf9cf9522ec1cbac23e8', 'Unexpected go-win7 duplicated socket source'
file_socket = replace_once(file_socket, '\treturn windows.WSASocket(-1, -1, -1, &info, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)', '\treturn wsaSocketNoInherit(-1, -1, -1, &info, 0)')
patches[file_path] = file_socket

for name, data in patches.items():
    (toolchain / name).write_text(data)
subprocess.run([str(toolchain / 'bin/gofmt'), '-w'] + [str(toolchain / name) for name in patches], check=True)
env = dict(os.environ, GOROOT=str(toolchain), GOTOOLCHAIN='local', GOOS='windows', GOARCH=args.arch, CGO_ENABLED='0')
module_info = json.loads(subprocess.check_output([str(toolchain / 'bin/go'), 'list', '-m', '-json', 'golang.org/x/sys'], cwd=repo, env=env, text=True))
xsys_loader = Path(module_info['Dir']) / 'windows/dll_windows.go'
xsys_hash = sha(xsys_loader.read_bytes())
assert module_info['Version'] == 'v0.47.0' and xsys_hash == '1c62d9345dd0c1d8e660792c1955a407b2049210c3bd2d8000004375f07afed9', 'Review x/sys system-DLL fallback before updating the dependency'
exe = output / ('rdev-client-windows-win7-rtm-' + args.arch + '.exe')
subprocess.run([str(toolchain / 'bin/go'), 'build', '-trimpath', '-buildvcs=false', '-ldflags', '-s -w -X main.version=' + args.version, '-o', str(exe), './cmd/rdev-client'], cwd=repo, env=env, check=True)
data = exe.read_bytes()
assert data[:2] == b'MZ', 'Missing DOS header'
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert data[pe:pe+4] == b'PE\0\0', 'Missing PE header'
assert struct.unpack_from('<H', data, pe+4)[0] == (0x8664 if args.arch == 'amd64' else 0x14c), 'Wrong PE architecture'
manifest = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
    'version': args.version,
    'toolchain': (source / 'VERSION').read_text().strip(),
    'patched_sources': {name: sha((toolchain / name).read_bytes()) for name in patches},
    'x_sys_version': module_info['Version'], 'x_sys_dll_loader_sha256': xsys_hash,
    'artifact': str(exe), 'size': len(data), 'sha256': sha(data),
    'pe_machine': args.arch, 'validated_on_win7': False,
}
(output / ('build-manifest-' + args.arch + '.json')).write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
