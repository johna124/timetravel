⏱️ Time-Travel CLI v1.4 — Dedup + Crypto Core

"Ctrl+Z for your entire project folder — with content dedup and encryption."

Pure C11. Static binary, ~250 KB (musl + xdelta3 + BLAKE2b + XChaCha20-Poly1305
statically linked). Zero runtime dependencies. Linux only.

## What it is

Time-Travel is a real-time file versioning daemon. It watches a directory tree via
`inotify` and records every change as a compact `xdelta3` delta — no `git init`,
no staging, no commits. Edit files normally; every save is captured automatically,
and you can restore any file (or an entire directory) to any point in its history.

It is not a backup tool and doesn't try to be one. It's a local undo buffer for
active development — pair it with a real backup tool (BareSnap, Restic, Borg)
for actual disaster recovery.

## What's new in v1.4 — Dedup + Encryption

### Content-addressed dedup (BLAKE2b)
Files >= 1 MiB are captured as 64 KiB content-addressed blocks. Identical blocks
are shared across files and versions — no duplicate storage.

    .timetravel/blocks/
    ├── 0c/
    │   ├── 499523519a12d6ef...
    │   └── b9bfe6729f9c4bfe...
    ├── 0d/
    │   └── 5e85a227d320bf3c...
    └── 15/
        └── 10d9883f0b26bc6f...

### Optional encryption (XChaCha20-Poly1305)
Repositories can be encrypted at creation time with a passphrase. Key derivation
uses PBKDF2-HMAC-BLAKE2b (100,000 iterations). The passphrase is never stored.

    timetravel start ~/secret --encrypt   # prompts passphrase twice

### Store verification

    timetravel verify --repo ~/project    # integrity check

Detects corrupted .ttd files, invalid magic, missing dedup blocks, failed AEAD
authentication, and broken delta chains.

### Atomic compaction + orphan GC

    timetravel compact --repo ~/project   # collapse delta chains + GC blocks

Compaction is atomic (temp + rename). For encrypted repos, GC is fail-closed:
if history can't be read/authenticated, no blocks are deleted.

## What's in v1.3 — the multi-repo monolith

Earlier versions ran one daemon per watched folder. v1.3 replaced that with a
single daemon that watches up to 16 repositories at once, attached and detached
live:

    timetravel start ~/src
    timetravel add ~/docs
    timetravel add /mnt/data/notes
    timetravel status        # sees the whole swarm, from any directory

Each repo keeps its own isolated .timetravel store, cache, and debounce queue —
corruption or deletion in one never touches the others. Concurrent start/add
calls are serialized by a boot lock, so five processes racing to start a daemon
converge on exactly one, never a duplicate.

## Quick start

    # Compile (needs musl-gcc + xdelta3)
    ./compile.sh

    # Start watching a project
    ./build/timetravel start /path/to/project

    # Edit files normally, then undo
    ./build/timetravel undo /path/to/file.c --last --repo /path/to/project
    ./build/timetravel undo /path/to/file.c --to "10 minutes ago" --repo /path/to/project

    # Compare versions
    ./build/timetravel diff /path/to/file.c --repo /path/to/project

    # See what changed, and when
    ./build/timetravel log /path/to/file.c --repo /path/to/project

    # Export all versions + diffs
    ./build/timetravel dump /path/to/file.c --out /tmp/versions --with-diff --repo /path/to/project

    # Verify integrity
    ./build/timetravel verify --repo /path/to/project

    # Encrypted repo
    ./build/timetravel start /path/to/secret --encrypt

Full command reference — restoration, diffing, tags, dump, maintenance — is in the manual.

## Design highlights

**Copy-on-first-change**: no initial snapshot on startup. Nothing is written to disk
until a file actually changes, so watching a folder that never changes costs zero
storage.

**Atomic restores**: every write goes through mkstemp -> write -> fsync -> chmod ->
rename. There is no window where a restore can leave a half-written file, including
under kill -9.

**No fsync per record**: records are visible via page cache immediately; durability
is bounded by file rotation instead. This is what makes a 500-file burst capture
finish in under 2 seconds instead of minutes.

**Per-file directory undo**: undo <dir> --last reverts each file to its own previous
version, not the whole directory to one shared timestamp — matches "undo my last
edits" rather than "rewind to a moment."

**Baseline prune**: undo <dir> --initial restores to the exact state at first
adoption. Files added after startup are deleted. Uses .timetravel/baseline.list.

**Content dedup**: files >= 1 MiB are split into 64 KiB BLAKE2b content-addressed
blocks. Identical blocks are shared across files and versions, eliminating duplicate
storage for large files with repeated content.

**Optional encryption**: repositories can be encrypted at creation time with
XChaCha20-Poly1305 (AEAD). Key derivation uses PBKDF2-HMAC-BLAKE2b with 100,000
iterations. The passphrase is never stored.

**Store verification**: the verify command performs read-only integrity checks on
the entire store: magic validation, record chain consistency, dedup block existence
and hash verification, delta decoding, and AEAD authentication for encrypted repos.

**Atomic compaction + fail-closed GC**: compact collapses delta chains and rewrites
the store atomically (temp + rename). For encrypted repos, GC is fail-closed: if
history cannot be read or authenticated, no blocks are deleted.

## How it compares

| Feature | Time-Travel | git | Restic | BareSnap |
| :--- | :---: | :---: | :---: | :---: |
| Purpose | Real-time file undo | Version control | Backup | Backup |
| Language | Pure C11 | C/Perl | Go | Pure C11 |
| Static binary | ~250 KB | ~40 MB | ~40 MB | ~2.1 MB |
| Runtime deps | NONE | perl | none | none |
| Real-time capture | YES (inotify) | NO | NO | NO |
| Multi-repo daemon | YES (v1.3) | NO | NO | NO |
| Hot add/remove | YES (v1.3) | NO | NO | NO |
| Delta encoding | xdelta3 | binary | NO | xdelta3 |
| Deduplication | YES (BLAKE2b) | YES | YES | YES |
| Encryption | XChaCha20 | NO* | AES-256 | XChaCha20 |
| Remote support | NO | YES | S3/SFTP | Native SSH |
| Per-file undo | YES | checkout | extract | extract |
| Directory undo | YES | checkout | restore | restore |
| Baseline prune | YES (v1.4.1) | NO | NO | NO |
| Named checkpoints | YES (tags) | YES | YES | YES |
| Diff | YES | YES | NO | YES |
| Inter-revision diff | YES (dump) | YES | NO | NO |
| Store verification | YES (verify) | fsck | check | YES |
| Export versions | YES (dump) | export | extract | extract |
| Manual compaction | YES | gc | prune | prune |
| Initial backup | NO | clone | init | init |

\* git supports GPG signing but not repository encryption.


Time-Travel occupies a unique niche: real-time per-file undo for active
development, now across many folders from a single daemon, with content
dedup and optional encryption. It is NOT a backup tool. Use it alongside
a proper backup solution (BareSnap, Restic, Borg) for disaster recovery.

## Forensic Memory Audit & Testing Matrix

Time-Travel targets raw performance without the safety net of a managed runtime
or a garbage collector. Every dynamic queue, cache, and IPC channel is audited
at the instruction level to guarantee absolute memory safety and leak-free daemon
states.

    ==============================================================================
     VALGRIND MEMCHECK & SANITIZER AUDIT REPORT -- v1.4 DEDUP + CRYPTO
    ==============================================================================
     [SYSTEM]    Target Host:   2007 Core 2 Duo T7500 (Mechanical HDD Baseline)
     [PIPELINE]  Toolchain:     gcc / musl-gcc -std=c11 -O0 -ggdb3 Hardened
     [CONTEXT]   Architecture:  x86_64 static binary (~230 KB linked)
     [ENGINE]    Auditors:      Valgrind Memcheck + ASan/UBSan + TSan
     [EXECUTION] 116 assertions across 43 sections

                 Coverage includes:
                 - Real-time inotify overflow buffer stress
                 - Multi-repo boot-lock stampede synchronization
                 - Inter-process communication (IPC) messaging protocol
                 - Crash recovery (kill -9 isolation testing)
                 - xdelta3 sub-block rotation boundaries
                 - BLAKE2b dedup block capture + restore + GC
                 - XChaCha20-Poly1305 encryption + AEAD tamper detection
                 - Store verification with corrupted/tampered files
                 - Baseline prune (undo dir --initial)

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
      Passed:    116/116 assertions
      Failed:    0
      Skipped:   0 (native) / 2 (under Valgrind: crypto sections)
      Duration:  ~11m (native) / ~45m (Valgrind, crypto skipped)
      Log:       test_battery.log
    ==============================================================================
     VERDICT: 100% CLEAN C11 MEMORY MAP -- REGRESSION TESTING PASSED
    ==============================================================================

### Sanitizer matrix

    +----------+----------------------------+----------------------------+
    | Mode     | Sections evaluated         | Skipped                    |
    +----------+----------------------------+----------------------------+
    | Native   | 1-43 (all)                 | none                       |
    | ASan     | 1-43 (all)                 | Valgrind section (41)      |
    | TSan     | 1-40, 42-43                | Valgrind section (41)      |
    | Valgrind | 1-38, 41-43                | Crypto sections (39, 40)   |
    +----------+----------------------------+----------------------------+

- **ASan/UBSan**: zero memory errors, zero undefined behavior.
- **TSan**: zero data races across the multi-repo monolith.
- **Valgrind Memcheck**: zero leaks, zero errors. Crypto sections skipped
  due to KDF cost under Valgrind (~20x slowdown).
- **Crypto sections (39-40)**: fully tested in native and ASan runs.

### Run the audit suite locally

    # Native battery (all 116 assertions)
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

**Important:**
- Do NOT combine Valgrind with ASan or TSan.
- Do NOT combine ASan with TSan.
- mega_test.sh auto-detects sanitizer builds and skips incompatible sections.
- To force crypto under Valgrind (very slow): set
  SKIP_CRYPTO_UNDER_VALGRIND=0 and reduce KDF iterations.

## Known limitations — read before relying on this

- Linux only. Built directly on inotify, timerfd, and POSIX rename()
  atomicity. No portability layer, no plans for one.
- inotify doesn't work over NFS/SSHFS. The daemon still runs and falls
  back to a 10-second periodic rescan, but with real latency — not the
  real-time capture you get locally.
- Not a sync mechanism. You can rsync the .timetravel directory as a
  crude copy, but two machines writing to it concurrently will corrupt
  the store.
- Encryption does not provide full metadata privacy. File paths,
  timestamps, and sizes remain visible (authenticated but not encrypted).
  Content and dedup blocks are encrypted.
- Passphrase is unrecoverable. If lost, the encrypted repository cannot
  be opened. Back up crypto.meta alongside the repo.

Full detail on all of these — plus binary format, on-disk layout, every
CLI flag, and the complete FAQ — is in the manual.

## License

- Source code (src/): GPLv3
- Manual and assets: GFDL v1.3

## Part of the toolchain

Built alongside BareSnap (https://github.com/johna124/baresnap) —
Time-Travel handled real-time source versioning during BareSnap's own
development, in place of Git.
