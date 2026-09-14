#!/usr/bin/env python3
"""Package and execute a verified archive."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

SECRET = "B5K8QD"
VERSION = "V6R8XT"
ARCHIVE_LIMIT = 16 * 1024 * 1024
CONTENT_LIMIT = 64 * 1024 * 1024
EXCLUDED = {"node_modules", "__pycache__", "artifacts", "tests"}
SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".sh", ".json", ".txt", ".onnx"}


class InputError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InputError("Redirects are forbidden.")


def relative_path(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name
            or any(part in (".", "..") for part in path.parts)
            or "\\" in name or any(ord(char) < 32 for char in name)):
        raise InputError("Invalid archive path.")
    return path


def pack(directory):
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise InputError("Expected a directory.")
    output = io.BytesIO()
    total = 0
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if any(part.startswith(".") or part in EXCLUDED for part in relative.parts):
                continue
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise InputError("Only regular files can be packaged.")
            if path.suffix not in SUFFIXES:
                raise InputError("Unsupported package file.")
            total += info.st_size
            if total > CONTENT_LIMIT:
                raise InputError("Expanded archive exceeds limit.")
            entry = zipfile.ZipInfo(relative_path(relative.as_posix()).as_posix())
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (stat.S_IFREG | (0o700 if info.st_mode & 0o111 else 0o600)) << 16
            archive.writestr(entry, path.read_bytes(), compresslevel=9)
        if "run.sh" not in archive.namelist():
            raise InputError("Entrypoint is missing.")
    payload = output.getvalue()
    if len(payload) > ARCHIVE_LIMIT:
        raise InputError("Archive exceeds limit.")
    return payload


def download(config, digest):
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise InputError("Invalid version.")
    url, token = config["url"], config["token"]
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not isinstance(token, str) or not token
            or any(ord(char) < 32 for char in token)):
        raise InputError("Invalid download configuration.")
    request = Request(f"{url.rstrip('/')}/{digest}.zip", headers={
        "Authorization": f"Bearer {token}", "User-Agent": "botpool-account-worker/1.0"})
    with build_opener(NoRedirect).open(request, timeout=60) as response:
        if response.status != 200:
            raise InputError("Unexpected download status.")
        payload = response.read(ARCHIVE_LIMIT + 1)
    if len(payload) > ARCHIVE_LIMIT or hashlib.sha256(payload).hexdigest() != digest:
        raise InputError("Archive integrity check failed.")
    return payload


def execute(payload):
    with zipfile.ZipFile(io.BytesIO(payload)) as archive, tempfile.TemporaryDirectory(prefix="x-") as directory:
        entries = archive.infolist()
        names = [relative_path(entry.filename).as_posix() for entry in entries]
        if len(names) != len(set(names)) or "run.sh" not in names:
            raise InputError("Missing entrypoint or duplicate paths.")
        if sum(entry.file_size for entry in entries) > CONTENT_LIMIT:
            raise InputError("Expanded archive exceeds limit.")
        for entry in entries:
            mode = entry.external_attr >> 16
            if not stat.S_ISREG(mode) or entry.flag_bits & 1:
                raise InputError("Only unencrypted regular files are supported.")
        for entry in entries:
            path = Path(directory, entry.filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.read(entry))
            path.chmod(0o700 if (entry.external_attr >> 16) & 0o111 else 0o600)
        env = dict(os.environ)
        env.pop(SECRET, None)
        result = subprocess.run(["bash", str(Path(directory, "run.sh"))], cwd=directory, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pack_parser = sub.add_parser("pack")
    pack_parser.add_argument("directory")
    pack_parser.add_argument("output")
    sub.add_parser("run")
    args = parser.parse_args()
    try:
        if args.command == "pack":
            payload = pack(args.directory)
            with open(args.output, "xb") as output:
                output.write(payload)
            print(hashlib.sha256(payload).hexdigest())
            return 0
        config = json.loads(os.environ.pop(SECRET))
        code = execute(download(config, os.environ[VERSION]))
        print(f"Finished with exit code {code}.")
        return code
    except InputError as error:
        print(str(error), file=sys.stderr)
    except Exception:
        print("Unable to package, download, or execute archive.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
