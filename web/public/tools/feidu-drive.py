#!/usr/bin/env python3
"""Minimal Feidu developer API client with no third-party dependencies."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import mimetypes
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class APIError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def json_request(self, method: str, path: str, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                envelope = json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise APIError(f"HTTP {error.code}: {detail}") from error
        if envelope.get("code") != 0:
            raise APIError(f"API {envelope.get('code')}: {envelope.get('message')}")
        return envelope.get("data") or {}

    def download(self, content_id: str, destination: pathlib.Path) -> None:
        api_url = self.base_url + "/developer/v1/contents/" + urllib.parse.quote(content_id) + "/download"
        request = urllib.request.Request(api_url, headers={"Authorization": f"Bearer {self.token}"})
        opener = urllib.request.build_opener(NoRedirect)
        try:
            opener.open(request, timeout=60)
            raise APIError("download endpoint did not return a redirect")
        except urllib.error.HTTPError as response:
            if response.code != 302:
                detail = response.read().decode("utf-8", "replace")
                raise APIError(f"HTTP {response.code}: {detail}") from response
            direct_url = response.headers.get("Location")
        if not direct_url:
            raise APIError("download redirect did not contain Location")
        direct_target = urllib.parse.urlsplit(direct_url)
        if direct_target.scheme != "https" or not direct_target.hostname:
            raise APIError("download redirect must contain an HTTPS URL")
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(destination.name + ".part")
        try:
            with urllib.request.urlopen(urllib.request.Request(direct_url), timeout=120) as source:
                with partial.open("wb") as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)
            partial.replace(destination)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
            partial.unlink(missing_ok=True)
            raise APIError(f"direct download failed: {type(error).__name__}") from None

    def upload(
        self,
        source: pathlib.Path,
        parent_id: str,
        lifecycle_action: str,
        lifetime_seconds: int,
        operation_id: str = "",
        resume_session_id: str = "",
    ) -> dict:
        size = source.stat().st_size
        modified_at_ms = int(source.stat().st_mtime * 1000)
        digest = hashlib.sha1()
        with source.open("rb") as handle:
            first_kib = handle.read(min(1024, size))
            digest.update(first_kib)
            while True:
                chunk = handle.read(8 * 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        content_hash = digest.hexdigest()
        pre_hash = hashlib.sha1(first_kib).hexdigest() if size > 100 * 1024 else ""
        if resume_session_id:
            data = self.json_request("GET", f"/developer/v1/direct-upload-sessions/{resume_session_id}")
            session = data["session"]
            self._validate_resume_file(session, source.name, size, modified_at_ms)
            operation_id = session["operation_id"]
            parts = []
        else:
            operation_id = operation_id or str(uuid.uuid4())
            payload = {
                "operation_id": operation_id,
                "file_name": source.name,
                "size_bytes": size,
                "modified_at_ms": modified_at_ms,
                "content_type": mimetypes.guess_type(source.name)[0] or "application/octet-stream",
                "pre_hash": pre_hash,
                "lifecycle_action": lifecycle_action,
                "lifetime_seconds": lifetime_seconds,
            }
            if parent_id:
                payload["parent_content_id"] = parent_id
            data = self.json_request("POST", "/developer/v1/direct-upload-sessions", payload)
            session = data["session"]
            parts = data.get("parts") or []
        session_id = session["session_id"]
        print(f"operation_id={operation_id} session_id={session_id}", file=sys.stderr)

        if session["status"] == "proof_required":
            with source.open("rb") as handle:
                handle.seek(session["proof_start"])
                proof = handle.read(session["proof_end"] - session["proof_start"])
            data = self.json_request(
                "POST",
                f"/developer/v1/direct-upload-sessions/{session_id}/rapid-proof",
                {"content_hash": content_hash, "proof_code": base64.b64encode(proof).decode("ascii")},
            )
            session = data["session"]
            parts = data.get("parts") or []

        if session["status"] == "completed":
            return {
                "content_id": session["result_content_id"],
                "operation_id": operation_id,
                "session_id": session_id,
            }
        if session["status"] != "uploading":
            raise APIError(f"upload session cannot continue from status {session['status']}")

        uploaded = {part["part_number"] for part in session.get("parts", []) if part["status"] == "uploaded"}
        if not session["rapid_upload"]:
            if not parts:
                parts = self.json_request(
                    "POST", f"/developer/v1/direct-upload-sessions/{session_id}/parts/refresh"
                )["parts"]
            urls = {part["part_number"]: part["upload_url"] for part in parts}
            with source.open("rb") as handle:
                for part_number in range(1, session["part_count"] + 1):
                    if part_number in uploaded:
                        continue
                    start = (part_number - 1) * session["part_size"]
                    handle.seek(start)
                    chunk = handle.read(min(session["part_size"], size - start))
                    status = self._put_part_with_retry(session_id, part_number, chunk, urls)
                    self.json_request(
                        "PUT",
                        f"/developer/v1/direct-upload-sessions/{session_id}/parts/{part_number}",
                        {"http_status": status},
                    )
                    print(f"part={part_number}/{session['part_count']}", file=sys.stderr)

        completed = self.json_request(
            "POST",
            f"/developer/v1/direct-upload-sessions/{session_id}/complete",
            {"content_hash": content_hash},
        )
        return {
            "content": completed["content"],
            "operation_id": operation_id,
            "session_id": session_id,
        }

    @staticmethod
    def _validate_resume_file(session: dict, name: str, size: int, modified_at_ms: int) -> None:
        if (
            session.get("file_name") != name
            or session.get("size_bytes") != size
            or session.get("modified_at_ms") != modified_at_ms
        ):
            raise APIError("selected file does not match the upload session name, size, and modified time")

    def _put_part_with_retry(self, session_id: str, part_number: int, data: bytes, urls: dict) -> int:
        last_status = 0
        for attempt in range(1, 4):
            upload_url = urls.get(part_number)
            if not upload_url:
                refreshed = self.json_request(
                    "POST", f"/developer/v1/direct-upload-sessions/{session_id}/parts/refresh"
                )["parts"]
                urls.update({part["part_number"]: part["upload_url"] for part in refreshed})
                upload_url = urls.get(part_number)
            if not upload_url:
                raise APIError(f"part {part_number} did not receive an upload URL")
            try:
                last_status = put_without_content_type(upload_url, data)
            except APIError:
                last_status = 0
            if last_status in (200, 409):
                return last_status
            urls.pop(part_number, None)
            if attempt < 3:
                time.sleep(attempt)
        raise APIError(f"part {part_number} failed after 3 attempts with HTTP {last_status}")


def put_without_content_type(url: str, data: bytes) -> int:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise APIError("upload URL must be HTTPS")
    path = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=120)
    try:
        connection.request("PUT", path, body=data, headers={"Content-Length": str(len(data))})
        response = connection.getresponse()
        response.read()
        return response.status
    except (OSError, http.client.HTTPException) as error:
        raise APIError(f"upload part request failed: {type(error).__name__}") from None
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Feidu developer API client")
    parser.add_argument("--base-url", default="https://pan.feidu.fit")
    parser.add_argument("--token", default=os.environ.get("FEIDU_DRIVE_TOKEN", ""))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capabilities")
    list_parser = commands.add_parser("list")
    list_parser.add_argument("--parent", default="")
    list_parser.add_argument("--search", default="")
    list_parser.add_argument("--limit", type=int, default=30)
    download_parser = commands.add_parser("download")
    download_parser.add_argument("content_id")
    download_parser.add_argument("destination", type=pathlib.Path)
    upload_parser = commands.add_parser("upload")
    upload_parser.add_argument("source", type=pathlib.Path)
    upload_parser.add_argument("--parent", default="")
    upload_parser.add_argument("--lifecycle", choices=("none", "hide", "archive"), default="")
    upload_parser.add_argument("--lifetime", type=int, default=0)
    upload_parser.add_argument("--operation-id", default="")
    resume_parser = commands.add_parser("resume-upload")
    resume_parser.add_argument("session_id")
    resume_parser.add_argument("source", type=pathlib.Path)
    args = parser.parse_args()
    if not args.token:
        parser.error("--token or FEIDU_DRIVE_TOKEN is required")
    client = Client(args.base_url, args.token)
    if args.command == "capabilities":
        result = client.json_request("GET", "/developer/v1/capabilities")
    elif args.command == "list":
        query = urllib.parse.urlencode(
            {key: value for key, value in {"parent_content_id": args.parent, "search": args.search, "limit": args.limit}.items() if value != ""}
        )
        result = client.json_request("GET", "/developer/v1/contents" + ("?" + query if query else ""))
    elif args.command == "download":
        client.download(args.content_id, args.destination)
        result = {"path": str(args.destination), "size_bytes": args.destination.stat().st_size}
    elif args.command == "upload":
        if not args.source.is_file():
            parser.error("upload source must be an existing file")
        result = client.upload(
            args.source,
            args.parent,
            args.lifecycle,
            args.lifetime,
            operation_id=args.operation_id,
        )
    else:
        if not args.source.is_file():
            parser.error("upload source must be an existing file")
        result = client.upload(args.source, "", "", 0, resume_session_id=args.session_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
