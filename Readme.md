# RemeLLM

**A personal memory assistant that runs entirely on your own machine.**

*The repo is RemeLLM; the tool itself is `mind`.*

It quietly records the things you tell it to record — what you copied, which app
you were in, the pages you visited, the files you edit — embeds them locally, and
lets you ask questions about your own past.

```
› what was I doing tuesday around 5pm?

● mind  You were in Visual Studio for about 90 minutes on renderer.cpp,
        then read three pages on Vulkan descriptor sets.

  sources:
   [1] Tue 17:03 · focus     devenv.exe — renderer.cpp
   [2] Tue 18:12 · browser   Vulkan descriptor sets — documentation
```

Nothing leaves your machine. No account, no telemetry, no cloud. One Python file,
no pip installs required, public domain.

---

## Why this exists

Your computer already knows what you did last Tuesday. It just refuses to tell you.
Browser history only matches titles, clipboard managers forget, and the search box
can't answer *"what was that thing I read about descriptor indexing?"*

Cloud assistants can answer questions like that — by uploading your life. This one
does it without the upload.

It is **retrieval, not training.** Nothing is fine-tuned into model weights, so
"forget this" actually means the row is deleted and it is gone. That is deliberate:
data baked into weights can never really be removed.

## Install

You need [Ollama](https://ollama.com) and Python 3.8+.

```bash
ollama pull qwen2.5:7b        # or any chat model that supports tools
ollama pull nomic-embed-text  # embeddings

python3 mind.py setup         # pick models, sources, retention
python3 mind.py doctor        # verify everything, with fixes for what's broken
python3 mind.py install       # run capture at login
python3 mind.py chat          # talk to it
```

`doctor` is the one to run when anything misbehaves — it checks the whole stack
layer by layer and tells you exactly what to fix.

## What it can do

**Ask about your own history.** Time ranges are resolved in Python and never by the
model, so "tuesday around 5pm" means the same thing every time.

```bash
mind ask "what was I working on yesterday afternoon?"
mind ask "how long was I in Blender last week?"
mind search "descriptor"          # no model involved, just retrieval
mind screentime --days 7
```

**Research the open web when the answer isn't in your history.** It decides in
Python — not by asking the model to be honest about what it knows — whether a
question needs the web, then searches, opens the top results, reads them, and
answers with citations. If the first pass doesn't cover it, it works out what's
missing and searches again.

**Learn who you are.** A nightly pass distils durable facts from your activity,
with confidence that decays if they stop being true, and a firewall that refuses
to store sensitive categories at all.

**Stay yours.** Secrets are dropped before they're stored, capture is suppressed
while a password manager is focused, and the database can be encrypted at rest.

## Turning things on

Every capture source is **off until you turn it on**, and so is web access. A tool
that records your activity should never surprise you with what it recorded —
`mind status` prints exactly what's live.

Two things before you start:

```bash
mind config --path      # where the config lives
mind doctor             # checks every layer and tells you what to fix
```

`doctor` is the answer to almost every "why isn't this working."

Two gotchas that catch nearly everyone:

- **The daemon reads its config at start.** Changing a source does nothing to a
  daemon that's already running. After any `config --set` that touches capture:
  `mind pause && mind resume`.
- **PowerShell strips quotes** before Python sees them, so a bracketed value
  arrives as a string and gets read one character at a time. Wrap the whole
  assignment: `mind config --set 'network.searxng_instances=["https://searx.be"]'`

### Capture sources

```bash
mind config --set sources.clipboard.enabled=true   # what you copy
mind config --set sources.focus.enabled=true       # active window + duration
mind config --set sources.browser.enabled=true     # browser history
mind watch ~/notes ~/projects/renderer             # index folders (enables the source)
```

**Browser history backfills** — unlike the others, turning it on gives you history
going back as far as your retention window, so day one is useful instead of
empty. Query strings are stripped by default because they carry session tokens,
except where the parameter *is* the content (YouTube's `?v=`, Google's `?q=`).
Private and incognito titles are never recorded.

**Focus capture** is what powers `screentime` and most "what was I doing"
answers. On macOS it needs Accessibility and Automation permission, granted to
the *specific interpreter binary* — a grant to Terminal doesn't transfer to the
one launchd starts. `doctor` prints the path that needs it.

<details>
<summary>Tuning</summary>

```bash
mind config --set sources.clipboard.min_chars=12       # ignore trivial copies
mind config --set sources.focus.min_seconds=8          # ignore alt-tab flickers
mind config --set 'sources.browser.browsers=["firefox","chrome"]'
mind config --set 'sources.browser.domain_denylist=["bank.example.com"]'
mind config --set 'sources.files.extensions=[".md",".py",".cpp",".glsl"]'
mind watch                       # list indexed folders
mind watch --remove ~/notes
```

Folder indexing skips `.git`, `node_modules`, `__pycache__`, `venv`, `dist`,
`build` and friends, caps files at 4 MB, and rescans every five minutes. Point it
at a large tree and the first pass takes a while — `runtime.max_embeds_per_min`
(default 300) exists so it doesn't pin your GPU while you're using the machine.
</details>

### Web access and research

Off by default. It never sends your captured data out — only the search query it
builds.

```bash
mind config --set network.enabled=true
mind netcheck                                  # DNS, TLS, proxy, layer by layer
mind websearch "best guns in the finals"       # runs every engine, shows results
```

If the public engines are blocked on your network, point it at a SearXNG
instance. These are tried first and are by far the most reliable option:

```bash
mind config --set 'network.searxng_instances=["https://searx.be"]'
```

Self-hosting one is better still — a container on your LAN and search stops being
a coin flip.

<details>
<summary>Research depth and the answer cache</summary>

Deep research is on once the network is on: it reads what it found, works out
what's missing, and searches again. Bounded on every axis.

```bash
mind config --set knowledge.max_rounds=2               # extra rounds after the first
mind config --set knowledge.deep_max_total_sources=8   # hard cap on pages opened
mind config --set knowledge.max_sources=3              # sources cited per answer
```

Answers are cached with a TTL by category so asking twice in an hour doesn't
re-scrape the web:

```bash
mind knowledge                    # what's cached
mind knowledge --prune            # drop expired
mind knowledge --forget "the finals"
mind config --set knowledge.volatile_ttl_sec=3600     # prices, "latest", "who is now"
mind config --set knowledge.stable_ttl_sec=604800     # definitions, history
```
</details>

### The profile layer

On by default, but it needs material. The first pass lands about fifteen minutes
after the daemon starts, daily after that. Fresh install — don't wait:

```bash
mind profile --reflect --force
mind profile --why                # each fact with age and confidence
mind profile --add "prefers Vulkan over OpenGL" --category tools
mind profile --forget "Blender"
mind config --set profile.inject=false    # keep learning, stop using it in answers
```

Facts decay: `profile.half_life_days` (30) halves the weight of anything unseen,
and `profile.min_confidence` (0.4) prunes what falls below it. A sensitivity
firewall refuses whole categories regardless of what turns up in captures.

### Encryption at rest

```bash
pip install sqlcipher3        # not sqlcipher3-binary — that one is Linux-only

mind pause
mind encrypt on
mind resume
```

Pause first: a running daemon holds the file handle and the swap fails on
Windows. Migration rewrites the database, verifies a row census against the
original, and only then swaps it in, with rollback if anything goes wrong.

The real decision is where the key lives:

```bash
mind encrypt on --provider dpapi        # Windows — sealed to your login
mind encrypt on --provider keychain     # macOS Keychain
mind encrypt on --provider passphrase   # typed, every time you read your history
mind encrypt on --provider file         # key file, mode 0600
```

`dpapi` and `keychain` let capture start at login. `passphrase` means nothing
reads your history without a human present — which also means unattended capture
can't run. Pick the one matching what you're actually defending against.

### Other machines you own

Federated query, not sync. Every machine keeps its own captures and its own
database; this one asks the others the same question and merges the answers.
Nothing is pooled, nothing is uploaded, and each result says which machine it
came from.

On the machine that should answer:

```bash
mind peer token --new     # generates a shared secret; print it
mind serve                # read-only, 127.0.0.1:7717 by default
```

On the machine doing the asking:

```bash
mind config --set peers.token=<the same token>
mind peer add laptop http://laptop:7717
mind peer ping            # check they answer
```

That's it — `ask`, `chat` and `search` now include peer results:

```
1  ████████  Tue 17:03 · files · shader.glsl · on laptop
   descriptor indexing bindless sampler array notes
```

Add `--local` to any of them to stay on this machine.

**Reach peers over Tailscale or WireGuard**, not by opening a port. The
endpoint answers questions about everything a machine has captured, so it binds
to loopback by default and *refuses* to bind anywhere else without a token. A
private network gives you identity, encryption and NAT traversal that this file
has no business reimplementing.

Things worth knowing:

- **Peers need not agree on an embedding model.** The question crosses the wire
  as text; each node embeds it with whatever it has and searches its own index.
- **A sleeping machine is not an error.** Peers are queried in parallel with a
  timeout, and anything that doesn't answer is simply absent from the results.
- **Results merge by rank, not by score.** Each node normalises scores against
  its own best hit, so a nearly-empty machine's top result would otherwise tie
  your real local context. Reciprocal rank fusion across nodes avoids that;
  ties go to the machine you're sitting at.
- **The endpoint is read-only.** Two routes, a read-only database handle, no
  writes and no file paths.

<details>
<summary>Tuning</summary>

```bash
mind serve --host 0.0.0.0 --port 7717     # needs a token; prefer not to
mind config --set peers.peer_top_k=6      # results requested per peer
mind config --set peers.timeout_sec=8
mind config --set peers.node_name=studio  # how this machine introduces itself
mind config --set peers.max_top_k=25      # ceiling this node will serve
mind peer remove laptop
```
</details>

### Speed, and running at login

```bash
pip install numpy    # vector search over 50k entries: ~51 ms -> ~8 ms
mind install         # Task Scheduler / LaunchAgent / systemd
mind capture         # or run it in the foreground and watch
```

### Model and context

```bash
mind config --set chat_model=qwen2.5:14b
mind config --set runtime.num_ctx=8192
```

`num_ctx` is the setting people miss. Ollama defaults to a small context — often
4096 — and silently drops tokens off the **front** of an oversized prompt, which
eats the system prompt and the oldest retrieved context first. Always set it.
Raise it for more context, lower it if the KV cache pushes your model out of
VRAM.

### Retention and deletion

```bash
mind config --set retention_days=30
mind export > mind.jsonl
mind forget --all
```

Old rows are deleted, not archived.

## Privacy, concretely

- **Every source is off until you turn it on.** `status` always shows exactly
  what's enabled.
- **No microphone, no camera, no ambient capture.** Recording other people
  without their consent isn't a problem local storage solves.
- **Secrets are dropped at capture time** — API keys, private key headers, bearer
  tokens, password assignments, and high-entropy secret-shaped strings never reach
  the database.
- **Password managers blank the capture.** Clipboard and window titles are skipped
  entirely while a denylisted app is in front, and private/incognito titles are
  never recorded.
- **Encryption at rest** with `mind encrypt on` — SQLCipher, AES-256 over whole
  pages, so keyword search keeps working. The key lives in Windows DPAPI or the
  macOS Keychain so capture still starts at login, or behind a passphrase you type
  if you want reading your history to require a human.
- **Retention is a window.** Old rows are deleted, not archived.
- `mind export` dumps everything as JSONL. `mind forget --all` destroys it.

Encryption at rest is a *second* lock. For a lost or stolen laptop, full-disk
encryption is what actually protects you — `doctor` tells you whether it's on.

## Being honest about what it isn't

- **The model is the ceiling.** A 7B will call the tools and lose the plot on
  synthesis. 14B is usable. If answers feel thin, that's the model, not retrieval —
  try a bigger one before filing a bug.
- **It only knows what it captured.** Install it today and it knows nothing about
  last month. Browser history is backfilled within your retention window; the rest
  starts now.
- **Web search scrapes.** DuckDuckGo, Bing and Mojeek all block scrapers to varying
  degrees on any given day and any given network. It tries several and falls back
  to Wikipedia. `mind websearch "query"` shows exactly which engines your network
  allows. For reliability, point it at a SearXNG instance.
- **macOS needs per-binary permissions.** Automation and Accessibility are granted
  to the *specific interpreter*, so a grant to Terminal doesn't transfer to the
  launchd-started one. `doctor` prints the path that needs them.
- **This is not a productivity tracker.** It won't tell you how much time you
  wasted unless you ask.

## Requirements

Python 3.8+ and Ollama. No pip installs required.

`numpy` makes vector search several times faster if present (~8 ms vs ~51 ms over
50,000 entries) and is optional. `sqlcipher3` is only needed if you turn on
encryption.

## Under the hood

One file, standard library only. A bounded queue feeds a batching ingest worker, so
capture never blocks on the model — and if Ollama is down, rows are still stored and
embeddings backfill when it returns. Embeddings are L2-normalized float32 with a
1-bit sign quantization for fast candidate filtering. Retrieval fuses vector
similarity and BM25 with reciprocal rank fusion and a recency weight. SQLite runs
in WAL mode so chat reads while the daemon writes.

Anything deterministic — date arithmetic, ranking, whether a question needs the web —
happens in Python. The model only decides which tool to call, which is the part small
models do reliably.

```bash
python3 mind.py selftest     # 488 checks, no network required
```

## License

Public domain (CC0). Do whatever you want with it.