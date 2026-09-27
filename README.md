# ⏱️ Time-Travel CLI v1.5 — Autotags + Metadata Encryption

"TimeTravel is for the battle; Git is for after the battle."

**"Ctrl+Z for your entire project folder — with semantic autotags, transparent metadata encryption, content dedup, and payload encryption."**

Pure C11. Static binary, ~274 KB (musl + xdelta3 + BLAKE2b + XChaCha20-Poly1305 statically linked). Zero runtime dependencies. Linux only.

---

## 📖 What it is
Time-Travel is a real-time file versioning daemon. It watches a directory tree via `inotify` and records every change as a compact `xdelta3` delta — no `git init`, no staging, no commits. Edit files normally; every save is captured automatically, and you can restore any file (or an entire directory) to any point in its history. 

It is **not a backup tool** and doesn't try to be one. It's a local undo buffer for active development — pair it with a real backup tool (BareSnap, Restic, Borg) for actual disaster recovery.

---

## 🚀 What's new in v1.5 — Autotags + Metadata Encryption

### Semantic Autotags
The `log` command now shows semantic tags extracted *only* from the changed lines of each event, giving you instant context without opening the file:
```text
MODIFY  +1/-1 lines 3 #max_retries                          worker.c
CREATE  CREATE (176 B) #futex_lock #PTHREAD_MUTEX_INITIALIZER worker.c
```
*Tags are filtered (no language keywords), capped at 4 per event, and sorted by frequency.*

### Transparent Metadata Encryption
Repository metadata is now automatically encrypted at rest using a per-repo 32-byte key (`repo.key`):
* `annotations.enc` (Semantic autotags)
* `baseline.enc` (Baseline file paths for `--initial` prune)
* `exclude.enc` (Exclusion patterns)
*Zero user interaction required. Backward compatible with legacy plaintext files.*

### Unified Reconstruction Engine
A modular architecture refactor introduced `tt_reconstruct.c`, replacing 4 duplicated implementations. A single engine now handles `undo`, `diff`, `dump`, and `verify`, with proper error propagation for corrupted dedup blocks.

### Expanded Test Battery
Validated with **124 assertions across 44 sections** (up from 116/43), including new coverage for exclude pattern persistence and metadata encryption.

---

## 🏃 Quick start

```bash
# Compile (needs musl-gcc + xdelta3)
./compile.sh

# Start watching a project (starts the multi-repo monolith)
./build/timetravel start /path/to/project

or multiple directory at start:
./build/timetravel start src/ bin/

# Hot-add more repositories to the same daemon
./build/timetravel add /path/to/docs
./build/timetravel add /mnt/data/notes

# See the whole swarm from ANY directory
./build/timetravel status

# Edit files normally, then undo
./build/timetravel undo /path/to/file.c --last --repo /path/to/project
./build/timetravel undo /path/to/file.c --to "10 minutes ago" --repo /path/to/project

# Compare versions
./build/timetravel diff /path/to/file.c --repo /path/to/project

# See what changed, and when (with semantic autotags)
./build/timetravel log /path/to/file.c --repo /path/to/project

# Export all versions + diffs
./build/timetravel dump /path/to/file.c --out /tmp/versions --with-diff --repo /path/to/project

# Verify integrity
./build/timetravel verify --repo /path/to/project

# Compact delta chains + GC orphan dedup blocks
./build/timetravel compact --repo /path/to/project

# Create an encrypted repository (prompts for passphrase)
./build/timetravel start /path/to/secret --encrypt
```
*Full command reference — restoration, diffing, tags, dump, maintenance — is in the manual.*

---

## 🛠️ Design highlights

* **Copy-on-first-change:** No initial snapshot on startup. Nothing is written to disk until a file actually changes.
* **Atomic restores:** Every write goes through `mkstemp -> write -> fsync -> chmod -> rename`. Zero window for half-written files, even under `kill -9`.
* **No fsync per record:** Records are visible via page cache immediately. A 500-file burst capture finishes in under 2 seconds.
* **Per-file directory undo:** `undo <dir> --last` reverts each file to its *own* previous version, matching "undo my last edits" rather than "rewind to a moment."
* **Baseline prune:** `undo <dir> --initial` restores to the exact state at first adoption. Files added after startup are deleted.
* **Content dedup (BLAKE2b):** Files >= 1 MiB are captured as 64 KiB content-addressed blocks. Identical blocks are shared across files and versions.
* **Optional payload encryption (XChaCha20-Poly1305):** AEAD encryption for record payloads and dedup blocks. Key derivation uses PBKDF2-HMAC-BLAKE2b (100,000 iterations).
* **Multi-repo monolith (v1.3):** A single daemon watches up to 16 repositories at once. Hot add/remove via IPC. Concurrent startups are serialized by a boot lock.
* **Unified Reconstruction (v1.5):** Single `tt_reconstruct_file()` engine powers undo, diff, dump, and verify.

---

## 📊 How it compares

| Feature | Time-Travel | git | Restic | BareSnap |
| :--- | :--- | :--- | :--- | :--- |
| **Purpose** | Real-time file undo | Version control | Backup | Backup |
| **Language** | Pure C11 | C/Perl | Go | Pure C11 |
| **Static binary** | ~274 KB | ~40 MB | ~40 MB | ~2.1 MB |
| **Runtime deps** | NONE | perl | none | none |
| **Real-time capture** | YES (inotify) | NO | NO | NO |
| **Multi-repo daemon** | YES (v1.3) | NO | NO | NO |
| **Hot add/remove** | YES (v1.3) | NO | NO | NO |
| **Delta encoding** | xdelta3 | binary | NO | xdelta3 |
| **Deduplication** | YES (BLAKE2b) | YES | YES | YES |
| **Encryption** | XChaCha20 + Metadata | NO* | AES-256 | XChaCha20 |
| **Semantic Autotags** | YES (v1.5) | NO | NO | NO |
| **Per-file undo** | YES | checkout | extract | extract |
| **Directory undo** | YES | checkout | restore | restore |
| **Baseline prune** | YES (v1.4.1) | NO | NO | NO |
| **Store verification** | YES (verify) | fsck | check | YES |
| **Export versions** | YES (dump) | export | extract | extract |

*\*git supports GPG signing but not repository encryption.*

---

## 🛡️ Forensic Memory Audit & Testing Matrix

Time-Travel targets raw performance without a managed runtime. Every dynamic queue, cache, and IPC channel is audited at the instruction level.

```text
==============================================================================
  VALGRIND MEMCHECK & SANITIZER AUDIT REPORT -- v1.5 AUTOTAGS + METADATA
==============================================================================
  [SYSTEM]    Target Host:   2007 Core 2 Duo T7500 (Mechanical HDD Baseline)
  [PIPELINE]  Toolchain:     gcc / musl-gcc -std=c11 -O0 -ggdb3 Hardened
  [CONTEXT]   Architecture:  x86_64 static binary (~274 KB linked)
  [ENGINE]    Auditors:      Valgrind Memcheck + ASan/UBSan + TSan
  [EXECUTION] 124 assertions across 44 sections

              Coverage includes:
              - Semantic autotag generation & annotation persistence
              - Transparent metadata encryption (repo.key, AEAD)
              - Unified reconstruction engine error propagation
              - Multi-repo boot-lock stampede synchronization
              - BLAKE2b dedup block capture + restore + GC
              - XChaCha20-Poly1305 payload encryption + AEAD tamper detection

==============================================================================
   VALGRIND MEMCHECK SUMMARY
==============================================================================
   HEAP SUMMARY:
     in use at exit: 0 bytes in 0 blocks
     total heap allocs: all freed
   LEAK SUMMARY:
     definitely lost:  0 bytes in 0 blocks
     indirectly lost:  0 bytes in 0 blocks
     possibly lost:    0 bytes in 0 blocks
     still reachable:  0 bytes in 0 blocks
   ERROR SUMMARY: 0 errors from 0 contexts (suppressions: 0)

==============================================================================
   TEST BATTERY HARDENING VERDICT
==============================================================================
   Passed:    124/124 assertions
   Failed:    0
   Skipped:   0 (native) / 1 (Valgrind section under TSan)
   Duration:  ~12m (native)
   Log:       test_battery.log

==============================================================================
  VERDICT: 100% CLEAN C11 MEMORY MAP -- REGRESSION TESTING PASSED
==============================================================================
```

### Sanitizer matrix
| Mode | Sections evaluated | Skipped |
| :--- | :--- | :--- |
| **Native** | 1-44 (all) | none |
| **ASan** | 1-44 (all) | Valgrind section (41) |
| **TSan** | 1-40, 42-44 | Valgrind section (41) |
| **Valgrind** | 1-38, 41-44 | Crypto sections (39, 40) |

*ASan/UBSan: zero memory errors, zero undefined behavior.*
*TSan: zero data races across the multi-repo monolith.*
*Valgrind Memcheck: zero leaks, zero errors.*

### Run the audit suite locally
```bash
# Native battery (all 124 assertions)
./mega_test.sh ./build/timetravel

# ASan + UBSan
./compile_asan.sh
./mega_test.sh ./build_san/timetravel

# TSan
./compile_tsan.sh
./mega_test.sh ./build_tsan/timetravel

# Valgrind (crypto sections auto-skipped)
./compile_valgrind.sh
./mega_test.sh ./build_valgrind/timetravel_valgrind
```
**Important:** Do NOT combine Valgrind with ASan or TSan. Do NOT combine ASan with TSan. `mega_test.sh` auto-detects sanitizer builds and skips incompatible sections.

---

## ⚠️ Known limitations — read before relying on this

* **Linux only.** Built directly on `inotify`, `timerfd`, and POSIX `rename()` atomicity. No portability layer, no plans for one.
* **inotify doesn't work over NFS/SSHFS.** The daemon still runs and falls back to a 10-second periodic rescan, but with real latency.
* **Not a sync mechanism.** You can rsync the `.timetravel` directory as a crude copy, but two machines writing to it concurrently will corrupt the store.
* **Encryption does not provide full metadata privacy.** File paths, timestamps, and sizes remain visible (authenticated but not encrypted). Content, dedup blocks, and v1.5 metadata files are encrypted.
* **Passphrase is unrecoverable.** If lost, the encrypted repository cannot be opened. Back up `crypto.meta` alongside the repo.

*Full detail on all of these — plus binary format, on-disk layout, every CLI flag, and the complete FAQ — is in the manual.*

---

## ⚖️ License

* **Source code (`src/`):** GPLv3
* **Manual and assets:** GFDL v1.3

### Part of the toolchain
Built alongside [BareSnap](https://github.com/johna124/baresnap) — Time-Travel handled real-time source versioning during BareSnap's own development, in place of Git.
