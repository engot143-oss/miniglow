"""One-time, user-approved download. Never imported by the offline worker."""
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

root = Path(__file__).absolute().parent.parent / "ai"
root.mkdir(exist_ok=True)
artifacts = [
    ("llama-b11366-bin-win-cpu-x64.zip", "https://github.com/ggml-org/llama.cpp/releases/download/b11366/llama-b11366-bin-win-cpu-x64.zip", "33dbed3c969e394e2977105e89f5c4b5dbbb5233d038d14b6954b3d32bbde9ec"),
    ("Qwen3-1.7B-Q8_0.gguf", "https://huggingface.co/Qwen/Qwen3-1.7B-GGUF/resolve/90862c4b9d2787eaed51d12237eafdfe7c5f6077/Qwen3-1.7B-Q8_0.gguf", "061b54daade076b5d3362dac252678d17da8c68f07560be70818cace6590cb1a"),
]
for name, url, expected in artifacts:
    dest = root / name
    if not dest.exists():
        part = dest.with_suffix(dest.suffix + ".partial")
        print("Downloading " + name, flush=True)
        h = hashlib.sha256()
        count = 0
        with urllib.request.urlopen(url, timeout=60) as response, part.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
                h.update(block)
                count += len(block)
                if count % (100 * 1024 * 1024) == 0:
                    print(str(count // (1024 * 1024)) + " MiB received", flush=True)
        if h.hexdigest() != expected:
            raise RuntimeError("Artifact checksum mismatch")
        part.replace(dest)
    with dest.open("rb") as f:
        actual = hashlib.file_digest(f, "sha256").hexdigest()
    if actual != expected:
        raise RuntimeError("Existing artifact checksum mismatch")
    print("SHA-256 PASS: " + name, flush=True)
runtime = root / "runtime"
if not runtime.exists():
    with zipfile.ZipFile(root / artifacts[0][0]) as z:
        for name in z.namelist():
            if ".." in Path(name).parts or Path(name).is_absolute():
                raise RuntimeError("Unsafe runtime archive path")
        z.extractall(runtime)
(root / "downloads.json").write_text(json.dumps([
    {"file": n, "source": u, "sha256": h} for n, u, h in artifacts
], indent=2), encoding="utf-8")
print("Local model and runtime ready", flush=True)
