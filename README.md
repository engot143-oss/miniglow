# MiniGlow

Verified local Windows task-management and bounded AI automation built on
Python and SQLite. This repository is source code, not a deployed online agent.

## Included

- `mini-glow/`: the unchanged, approved MG-001 v0.2.0 source/test/documentation package.
- `automation/`: the companion inbox worker, local-model adapter and tests.
- A local-only workflow for text copies, inventories, source-grounded summaries,
  proposed checklist ordering and excerpt-based drafts.

No live database, inbox contents, generated outputs, credentials, downloaded
runtime or model weights are included. Test credentials in the test suite are
synthetic fixtures. The original package SHA-256 was
`7ba2b4e6ab8c2e2e0eaf03ffd8625f41fad2e840a5a4de313a14742f5679ed28`.
The original package README's Windows status describes its historical baseline;
subsequent Windows verification passed 50 core tests, 27 worker/AI tests and
four real model inference fixtures.

## Local setup

Install Python 3.10+; use Python 3.14 for the verified configuration.
From the repository root:

```powershell
python automation/worker.py setup
python automation/worker.py once
python automation/worker.py status
```

Place UTF-8 `.txt` or `.md` files directly in `workspace/inbox`. Outputs are
created in `workspace/outputs`; persistent state is in `data/mini_glow.db`.
The worker never modifies source files. Folders are not traversed. Source files
are limited to 1 MiB and the inbox to 200 entries.

Continuous processing: `python automation/worker.py run`.
Stop: `python automation/worker.py stop`. A manual run resumes a persistent Stop.

## Optional local AI

Only after approving online setup downloads:

```powershell
python automation/download_model.py
python automation/start_model.py
python automation/verify_real_model.py
```

The download script uses pinned official llama.cpp and Qwen artifacts and
checks their published SHA-256 values. The CPU model download is about 1.83 GB.
If the real inference verification passes, create `ai/ENABLED` and run the
worker again. `automation/start.ps1` starts a hidden Windows worker and, when
enabled, the local model. Automatic Windows login startup is not configured.

The model listens only at the authenticated `127.0.0.1:18183` endpoint, with
offline mode, no web interface, no agent tools and no MCP proxy. Inference uses
no external paid API. File contents do not grant permissions or invoke tools.

AI outputs use existing source excerpts; the model can select line IDs but cannot
insert new factual prose. Names containing `todo`, `checklist` or `.plan` select
proposed ordering of unchecked checklist lines; names containing `draft` select
draft excerpts; other names select summaries. AI source limits are 8,000
characters, 60 nonblank lines and 1,000 characters per line. Outputs are labeled
as source statements and suggestions, not independently verified facts or
actions already performed.

## Verify

```powershell
Push-Location mini-glow
python -m unittest discover -s tests -v
Pop-Location
python -m unittest discover -s automation -p 'test_*.py' -v
```

These checks do not download a model. Actual model inference is tested separately
using `automation/verify_real_model.py`. General free-form AI behavior and a full
Windows reboot have not been verified.

Buying, messaging, email, arbitrary program execution, remote paths and outside
source folders remain blocked. Only the fixed local model endpoint is permitted
in AI mode. Approver labels are honor-system and sensitive-data detection uses
patterns. Application guardrails do not isolate malicious programs running under
the same operating-system account.

## Online version

GitHub is the source-control foundation. An online service still requires a
chosen host, authentication, persistent storage, explicit network scope and
deployment verification. This source upload does not expose the local worker or
its data to the internet and does not create a paid service.
