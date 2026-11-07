# ⏱️ Time-Travel CLI v1.6 — FILE REPOS + EXTLOG + AUTOTAGS + METADATA ENCRYPTION

Pure C11 engine. Static binary (~292 KB). Zero runtime dependencies. Linux only.

"TimeTravel is for the battle; Git is for after the battle."

"Serious versioning for those who want Ctrl+Z across their entire project."

## 🚀 What's new in v1.6

+ FILE REPOS: Watch individual files instead of entire directories. Perfect for config files, single scripts, or isolated modules. Shares the same daemon and store infrastructure as directory repos.
  
+ EXTLOG: New command for detailed semantic history. Shows scope, revision, size, delta ratio, elapsed time, and a semantic summary of changes. Works with --since filter.
  
+ AUTO TAG CLEANLINESS: Improved token extraction and filtering. Better handling of binary files and garbage tokens ensures cleaner log output.


## 📖 What it is

Time-Travel is a real-time file versioning daemon. It watches a directory tree or individual files via inotify and records every change as compact xdelta3 deltas.

Think of it as "Ctrl+Z for your entire project folder"


### Core capture and restoration:
- Every edit, creation, and deletion is captured automatically.
- Restore any file or entire directory to any previous point in time.
- Named checkpoints (tags) for semantic rollback points.
- Diff between any two versions of a file.
- Full export of reconstructed versions and consecutive diffs.
- Atomic writes: restorations never leave corrupted files.
- No initial backup: only changes are recorded (copy-on-first-change).
- Per-file directory undo: each file reverts to its own previous version.

### Multi-repo monolith (v1.3):
- ONE daemon watches up to 16 repositories at once.
- Hot add/remove of repositories without restarting.
- Global status across the whole swarm from any directory.
- Per-repo isolation: corruption in one repo never affects the others.

### File Repos (v1.6):
- Watch individual files instead of entire directories.
- Perfect for config files, single scripts, or isolated modules.
- Shares the same daemon and store infrastructure as directory repos.

### Dedup and encryption (v1.4):
- Files >= 1 MiB are stored as 64 KiB BLAKE2b content-addressed blocks.
- Optional per-repository XChaCha20-Poly1305 encryption (AEAD).
- PBKDF2-HMAC-BLAKE2b key derivation; the passphrase is never stored.
- Store verification: detect corrupted or tampered .ttd files.
- Atomic compaction with fail-closed orphan-block GC.

### Reliability and hygiene:
- Robust exclusions: .git, node_modules, __pycache__, target, .cache.
- Enhanced status showing daemon state, CPU, RAM, records, and bytes.
- Self-cleaning test battery: 170 assertions across 51 sections.
- Audited with ASan/UBSan, ThreadSanitizer and Valgrind (0 leaks).

### 🎖️ MEDALS AWARDED
* **Weight of Silicon**:  375,454 bytes of raw C11 source code ( 9,369  lines according to `cloc`).
* **Dependency Rejection**: Includes statically compiled xdelta3, BLAKE2b, and the XChaCha20-Poly1305 crypto core), with zero external runtime dependencies. (`ldd` verified). Purely static compile-time enucleation. Sanitizer builds link libasan/libubsan for instrumentation only, 
* **Binary Size**: ~292kb x86_64 static stripped.
* **Supported Architectures**: x86_64, ARM64, RISCV, MIPS64

## 🏃 Quick start

```bash
Compile:
./compile.sh test      # Fast KDF for tests (~100x faster crypto tests)
./compile.sh release   # Full security for production (default if no arg provided)

Watch a single directory (starts the monolith):
./build/timetravel start /path/to/project

Or watch a single file (v1.6):
./build/timetravel start /path/to/project/file.c

Or multiple targets at start:
./build/timetravel start src/ bin/ main.c

Add MORE repositories/files hot to the same daemon:
./build/timetravel add /path/to/another/project
./build/timetravel add /path/to/docs/readme.md

See the whole swarm from ANY directory:
./build/timetravel status

Edit files normally. To undo:
./build/timetravel undo /path/to/file.c --last --repo /path/to/project
./build/timetravel undo /path/to/file.c --to "2026-09-13 00:07:08" --repo /path/to/project
./build/timetravel undo /path/to/file.c --to "10 minutes ago" --repo /path/to/project
./build/timetravel undo /path/to/project --tag before-refactor --force --repo /path/to/project

To compare versions:
./build/timetravel diff /path/to/file.c --repo /path/to/project
./build/timetravel diff /path/to/file.c --to prev --repo /path/to/project
./build/timetravel diff /path/to/file.c --to 15 --repo /path/to/project
# To see inter-revision deltas, use dump --with-diff instead.

To view history and status:
./build/timetravel log /path/to/file.c --repo /path/to/project
./build/timetravel extlog /path/to/file.c --repo /path/to/project  # New in v1.6
./build/timetravel status --repo /path/to/project
./build/timetravel tag release-v1.0 --repo /path/to/project

To export all versions and diffs:
./build/timetravel dump /path/to/file.c --repo /path/to/project \
--out /tmp/tt_dump --with-diff

Lifecycle and maintenance:
./build/timetravel stop                    # stop the whole monolith
./build/timetravel stop --repo <dir>       # remove ONLY that repo
./build/timetravel restart <dir>
./build/timetravel tags [--repo <dir>]
./build/timetravel compact [--repo <dir>]  # manual (no more 03:00 auto-run)

Create an encrypted repository:
./build/timetravel start /path/to/project --encrypt
This prompts for a passphrase twice and creates:
/path/to/project/.timetravel/crypto.meta

Verify repository integrity:
./build/timetravel verify --repo /path/to/project

Compact a repository and run dedup GC:
./build/timetravel compact --repo /path/to/project
For encrypted repositories, compact/undo/verify may request the passphrase.

Run regression tests:
./compile.sh test
./mega_test.sh ./build/timetravel

Run sanitizer and concurrency audits:
# AddressSanitizer + UndefinedBehaviorSanitizer
./compile_asan.sh
./mega_test.sh ./build_san/timetravel

# ThreadSanitizer
./compile_tsan.sh

TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1" \
./mega_test.sh ./build_tsan/timetravel

Important:
- Do not combine Valgrind with ASan or TSan.
- Do not combine ASan with TSan.
- When mega_test detects a TSan build, it automatically skips the Valgrind emory audit section.
- Sanitizer builds are audit builds, not the production static binary.
```

## 🛠️ Design highlights

* Copy-on-first-change: No initial snapshot on startup. Nothing is written to disk until a file actually changes.
* Atomic restores: Every write goes through mkstemp -> write -> fsync -> chmod   -> rename. Zero window for half-written files, even under kill -9.
* No fsync per record: Records are visible via page cache immediately. A 500-file burst capture finishes in under 2 seconds.
* Per-file directory undo: undo <dir> --last reverts each file to its own previous version, matching "undo my last edits" rather than "rewind to a moment."
* Baseline prune: undo <dir> --initial restores to the exact state at first adoption. Files added after startup are deleted.
* Content dedup (BLAKE2b): Files >= 1 MiB are captured as 64 KiB content-addressed blocks. Identical blocks are shared across files and versions.
* Optional payload encryption (XChaCha20-Poly1305): AEAD encryption for record payloads and dedup blocks. Key derivation uses PBKDF2-HMAC-BLAKE2b.
* Multi-repo monolith (v1.3): A single daemon watches up to 16 repositories at once. Hot add/remove via IPC. Concurrent startups are serialized by a boot lock.
* Unified Reconstruction (v1.5): Single tt_reconstruct_file() engine powers undo, diff, dump, and verify.

## 📊 How it compares

| Feature | Time-Travel | git | Restic | BareSnap |
| :--- | :--- | :--- | :--- | :--- |
| **Purpose** | Real-time file undo | Version control | Backup | Backup |
| **Language** | Pure C11 | C/Perl | Go | Pure C11 |
| **Static binary** | ~292 KB | ~40 MB | ~40 MB | ~2.1 MB |
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

* git supports GPG signing but not repository encryption.

Time-Travel occupies a unique niche: real-time per-file undo for active development, now across many folders from a single daemon. It is NOT a 
backup tool. Use it alongside a proper backup solution (BareSnap, Restic, Borg) for disaster recovery.

## 🛡️ Forensic Memory Audit & Testing Matrix

Time-Travel targets raw performance without a managed runtime. Every dynamic 
queue, cache, and IPC channel is audited at the instruction level.

VALGRIND MEMCHECK & SANITIZER AUDIT REPORT -- v1.6
```text
[SYSTEM]    Target Host:   2007 Core 2 Duo T7500 (Mechanical HDD Baseline)
[PIPELINE]  Toolchain:     gcc / musl-gcc -std=c11 -O0 -ggdb3 Hardened
[CONTEXT]   Architecture:  x86_64 static binary (~293 KB linked)
[ENGINE]    Auditors:      Valgrind Memcheck + ASan/UBSan + TSan
[EXECUTION] 124 assertions across 51 sections

Coverage includes:
- Semantic autotag generation & annotation persistence
- Transparent metadata encryption (repo.key, AEAD)
- Unified reconstruction engine error propagation
- Multi-repo boot-lock stampede synchronization
- BLAKE2b dedup block capture + restore + GC
- XChaCha20-Poly1305 payload encryption + AEAD tamper detection
- File repos isolation and overlap protection
- Extlog semantic summary validation

VALGRIND MEMCHECK SUMMARY
-------------------------
HEAP SUMMARY:
  in use at exit: 0 bytes in 0 blocks
  total heap allocs: all freed
LEAK SUMMARY:
  definitely lost:  0 bytes in 0 blocks
  indirectly lost:  0 bytes in 0 blocks
  possibly lost:    0 bytes in 0 blocks
  still reachable:  0 bytes in 0 blocks
ERROR SUMMARY: 0 errors from 0 contexts (suppressions: 0)

TEST BATTERY HARDENING VERDICT
------------------------------
Passed:    169/170 assertions
Failed:    0
Skipped:   0 (native) / 1 (Valgrind section under TSan)
Duration:  ~12m (native)
Log:       test_battery.log

VERDICT: 100% CLEAN C11 MEMORY MAP -- REGRESSION TESTING PASSED
```

Sanitizer matrix:

| Mode | Sections evaluated | Skipped |
| :--- | :--- | :--- |
| **Native** | 1-51 (all) | none |
| **ASan** | 1-51 (all) | Valgrind section (41) |
| **TSan** | 1-40, 42-51 | Valgrind section (41) |
| **Valgrind**| 1-38, 41-51 | Crypto sections (39,40) |

*ASan/UBSan: zero memory errors, zero undefined behavior.*
*TSan: zero data races across the multi-repo monolith.*
*Valgrind Memcheck: zero leaks, zero errors.*

Run the audit suite locally:
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

**Important**: Do NOT combine ASan with TSan. mega_test.sh auto-detects sanitizer builds and skips incompatible sections.

⚠️ KNOWN LIMITATIONS — READ BEFORE RELYING ON THIS

* **Linux only.** Built directly on `inotify`, `timerfd`, and POSIX `rename()` atomicity. No portability layer.
* **inotify doesn't work over NFS/SSHFS.** The daemon still runs and falls back to a 10-second periodic rescan, but with real latency.
* **Not a sync mechanism.** You can rsync the `.timetravel` directory as a crude copy, but two machines writing to it concurrently will corrupt the store.
* **Passphrase is unrecoverable.** If lost, the encrypted repository cannot be opened. Back up `crypto.meta` alongside the repo.

*Full detail on all of these — plus binary format, on-disk layout, every CLI flag, and the complete FAQ — is in the manual.*


📜 Need more? Read the Full Technical Manual (33 pages of pure shrapnel, 50 bookmarks, and 50 internal links!). 
Generated natively from plain text by our very own static 'txt2pdf'.

## ⚖️ License

* **Source code (`src/`):** GPLv3
* **Manual and assets:** GFDL v1.3

### Part of the toolchain
Built alongside [BareSnap](https://github.com/johna124/baresnap) — Time-Travel handled real-time source versioning during BareSnap's own development, in place of Git.
