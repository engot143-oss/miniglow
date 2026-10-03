"""Trusted setup/launcher; the worker cannot launch this or any other program."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import zipfile
from worker import safe_path

base = Path(__file__).absolute().parent.parent
ai = base / "ai"
safe_path(ai, base)
key = ai / "local-api.key"
safe_path(key, ai)
if not key.exists():
    key.write_text(secrets.token_hex(32), encoding="utf-8")
def healthy():
    connection = http.client.HTTPConnection("127.0.0.1", 18183, timeout=2)
    try:
        connection.request("GET", "/v1/models", headers={"Authorization": "Bearer " + key.read_text().strip()})
        reply = connection.getresponse()
        body = reply.read()
        return reply.status == 200 and b'miniglow-qwen3-1.7b' in body
    except OSError:
        return False
    finally:
        connection.close()
model = safe_path(ai / "Qwen3-1.7B-Q8_0.gguf", ai)
with model.open("rb") as f:
    if hashlib.file_digest(f, "sha256").hexdigest() != "061b54daade076b5d3362dac252678d17da8c68f07560be70818cace6590cb1a":
        raise SystemExit("Model hash mismatch")
archive = safe_path(ai / 'llama-b11366-bin-win-cpu-x64.zip', ai)
with archive.open('rb') as f:
    if hashlib.file_digest(f, 'sha256').hexdigest() != '33dbed3c969e394e2977105e89f5c4b5dbbb5233d038d14b6954b3d32bbde9ec':
        raise SystemExit('Runtime archive checksum mismatch')
with zipfile.ZipFile(archive) as z:
    expected = {n for n in z.namelist() if not n.endswith('/')}
    actual = {p.relative_to(ai/'runtime').as_posix() for p in (ai/'runtime').rglob('*') if p.is_file()}
    if actual != expected:
        raise SystemExit('Runtime file set mismatch')
    for name in expected:
        p = safe_path(ai/'runtime'/name, ai/'runtime')
        if p.read_bytes() != z.read(name):
            raise SystemExit('Runtime file checksum mismatch')
exe = ai / "runtime" / "llama-server.exe"
for name in ('model.stdout.log', 'model.stderr.log', 'model-process.json'):
    safe_path(ai/name, ai)
if healthy():
    print("Local model already ready")
    raise SystemExit(0)
env = {k: v for k, v in os.environ.items() if not k.startswith(("LLAMA_", "GGML_"))}
env.update({"HF_HUB_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1"})
args = [str(exe), "-m", str(model), "--host", "127.0.0.1", "--port", "18183",
        "--alias", "miniglow-qwen3-1.7b", "--api-key-file", str(key), "--offline", "--no-webui",
        "--no-agent", "--no-ui-mcp-proxy", "--reasoning", "off", "--log-disable",
        "-c", "4096", "-t", "4", "-np", "1"]
with (ai / "model.stdout.log").open("ab") as out, (ai / "model.stderr.log").open("ab") as err:
    process = subprocess.Popen(args, cwd=ai / "runtime", env=env,
                               stdout=out, stderr=err, creationflags=subprocess.CREATE_NO_WINDOW)
(ai / "model-process.json").write_text(json.dumps({"pid": process.pid, "exe": str(exe)}))
for _ in range(45):
    if healthy():
        print("Local model ready on this computer only")
        raise SystemExit(0)
    if process.poll() is not None:
        raise SystemExit("Local model exited; check runtime logs")
    time.sleep(1)
raise SystemExit("Local model startup timed out")
