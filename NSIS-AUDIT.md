# NSIS audit in progress

The inventory covers microsoft/winget-pkgs snapshot
`a6057a417b4da1550a556fc5ad1373a0269b6f0b`: **137,091 NSIS references,
119,636 distinct SHA256 artifacts, and 4,162 package identifiers**. It includes
historical versions and ZIPs containing NSIS installers. The exhaustive binary
and ARP correctness audit is **not complete**.

## What the results establish

`target/nsis-audit/results.jsonl` is the persistent journal. Each record includes
artifact and analyzer hashes, manifest references, process status, raw output,
interpreter warnings/errors, and an `arp_verified` field. A successful process
means it returned metadata; it does not establish that metadata is correct.
No real-artifact record currently has complete independent runtime verification.
`scripts/independent_nsis.py` separately decodes supported installer headers and
literal registry-write instructions without using Komac or manifest values as
expectations. Corroborated fields establish encoded values only: branches,
reachability, later overwrites/deletion, plugins, and installation modes can
change registry effects. Unsupported layouts and dynamic values are explicit.

Existing manifests are comparison hints, including when they match Komac.
They may themselves contain output from an earlier faulty Komac version.
Source-based regression expectations come from explicit NSIS registry writes,
not manifests. No downloaded Windows installer has been executed here. There is
no Windows registry capture for any installer or installation mode.

Get current deduplicated counts with:

```sh
python3 scripts/summarize_nsis_audit.py target/nsis-audit/results.jsonl
```

## Live progress

The dashboard is served locally at <http://localhost:8765>. In Codespaces, open
port 8765 through the Ports panel. It refreshes every five seconds and shows
distinct installer coverage, current jobs, latest outcomes, independent literal
ARP checks, and memory/disk headroom. It reads the running audit's existing files;
the audit does not need to be restarted.

```sh
python3 scripts/nsis_progress.py --watch       # live terminal view; Ctrl-C closes only this view
python3 scripts/nsis_progress.py               # one snapshot
python3 scripts/nsis_progress.py --serve 8765  # start the browser dashboard if it is stopped
```

The dashboard also updates `target/nsis-audit/progress.txt` and `progress.json`
every five seconds. Counts distinguish unique analyzed installers from total runs,
download failures, and rechecks. A literal match is not runtime ARP verification.
The results browser searches every recorded artifact and filters outcomes,
interpreter findings, and manifest differences. Open a result to inspect Komac
metadata, independent ARP evidence, manifest references/differences, diagnostics,
raw records, and historical runs. Saved compressed traces can be downloaded.
The monitor uses only the Python standard library, tails newly appended journal
records, reads detailed records on demand, and does not control analysis processes
or serve arbitrary local files.

Counts distinguish attempted binaries, binaries ever returning output, latest
statuses, and independent ARP verification. Repeated analyses do not inflate the
unique counts. Initial journals under `/tmp` were lost between environment
continuations and are excluded from current persistent counts. Sandbox resolver
failures are retained separately in `sandbox-network-errors.jsonl`; they do not
count as installer analyses. URL encoding failures in older runner versions are
marked `audit_error` and retried.

## Fixes and independent regression checks

`tests/fixtures/nsis/arp.nsi`, its INI input, and
`scripts/check_nsis_fixture.py` exercise actual source instructions through six
zlib/bzip2/LZMA solid and non-solid builds. They check:

- ARP fields belonging to the same immediate uninstall key, including multiple
  entries and case-insensitive registry overwrites.
- Registry value types, missing-read output/error behavior, SHCTX, registry views,
  enumeration, recursive deletion, and conditional key deletion.
- Selected sections and sections enabled by `.onInit`.
- Unicode expansion, UTF-16 string lengths/slices, and clamped negative offsets.
- Assigned and empty internal variables, initial language, and `$OUTDIR`.
- Known-folder resolution used by NSIS MultiUser initialization.
- INI reads/writes/deletions, case-insensitive names, empty/error outputs, and
  extracted INI contents.
- File enumeration, corrected FindFirst operand positions, exhausted searches,
  missing searches, output clearing, and error flags.
- Corrected GetFullPathName operand positions and normalized symbolic paths.
- Hexadecimal/octal conversion, wrapping 32-bit values, and numeric prefixes.
- Logical negation, division/remainder error flags, numeric formatting from
  resolved values, and signed/unsigned integer comparison widths.
- Shared `$APPDATA` resolving to `%ProgramData%` in the all-users context.
- ARP writes under HKCU/HKLM only, excluding lookalike paths under HKCR.
- Nonrecursive directory removal, protected working directories, wildcard file
  deletion, and filesystem error flags.

`termination.nsi` adds four Abort/Quit cases. Unreachable sections and success
callbacks must not invent ARP entries after termination; section failure runs
the failure callback. These cases reference the [NSIS installation flow](https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/Ui.c).
Numeric formatting follows a bounded subset of [Windows wsprintf](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-wsprintfw),
with unsupported conversions or ambiguous flags explicitly warned about.
The six compression cases, four termination cases, and padded-header case pass.
The library suite contains 347 passing tests; current output is in
`target/nsis-audit/system-tests.log`. Three additional compiled System plugin
fixtures cover ANSI x86, Unicode x86, and Unicode AMD64.

The independent reader checks four zlib/LZMA fixtures and detects deliberately
incorrect metadata even when that metadata could have come from a manifest.

Reference semantics: [NSIS interpreter](https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/exec.c)
and the compiler/interpreter sources retained under `target/nsis-audit/reference`.
Short Windows filenames, unknown drive contexts, and external filesystem state
remain explicitly warned about; symbolic normalization is not a Windows API run.
The simulated wildcard matcher supports common `*`/`?` and `*.*` patterns, not
every DOS wildcard edge case.

Other parser fixes include bounded iterative calls and string expansion,
malformed block/instruction validation, preventing removal of filesystem roots
and active working directories, PE signature/machine validation, streaming NSIS-specific
DEFLATE, Park Unicode/opcode layouts, and NSISBI headers, 64-bit file positions,
extended instructions, and chunked multithread LZMA streams. Non-solid LZMA2
records and indexed multipart payloads in the Garena fork are now supported.
Decoder allocations and extracted-file sizes are bounded.

[7-Zip's NSIS parser](https://github.com/ip7z/7zip/blob/main/CPP/7zip/Archive/Nsis/NsisIn.cpp)
provides an independent format reference. NSISBI source also documents its
additional header/operand layouts; the retained source is from its 3.12.1 release.

Configured 7-Zip SFX wrappers explicitly launching setup.exe are now inspected.
Komac uses the inner NSIS metadata and identifies a unique core application's
architecture rather than assuming the wrapper's architecture. Tiny independent
archives cover configuration parsing and ARM64 architecture detection. External
payload file operations are still unmodeled and produce a warning.

## Real reproductions and remaining gaps

- DocuSign.DocusignPKI and QNAP.QVRProClient: removed-directory crashes fixed;
  metadata now returned, with simulation gaps still recorded.
- Piriform.Speccy and Bytello.BytelloShare: Park parsing panics fixed; simulated
  execution remains incomplete.
- GNU.Octave 10.1.0 and Unity.Unity.2023 2023.2.10f1: complete hash-verified
  binaries now parse after NSISBI fixes. Prefix-only development probes are not
  counted as full-artifact analyses.
- Mozilla Firefox and Thunderbird: SFX extraction and registry/INI enumeration
  fixes exposed OS-version gates. The expanded System model now passes these
  gates for the retained Firefox 137.0.2 (sl) and ESR 115.10.0 (pt-BR) binaries,
  returning their source-encoded ARP names, versions, publisher Mozilla, and
  product codes. Their machine scope and ProgramFiles(x86) location are modeled;
  neither result is runtime verified. UAC, CityHash, external payloads, and other
  filesystem/plugin gaps remain explicit. CharUpper/Lower models cover ASCII
  path normalization; non-ASCII Windows NLS casing remains unmodeled.
- Stardesk.Stardesk 1.0.4: LZMA2 decoding, NSISBI file offsets, and a root-removal
  crash are fixed. The retained full installer now returns metadata; unsupported
  plugin behavior still prevents a verified ARP result.
- Garena.Garena: indexed-fork header and multipart payload decoding are fixed.
  The retained installer returns metadata. Its HKLM uninstall writes encode
  Garena (remove only), publisher Garena, version 2.0.1909.2618, and product code
  gxx. The separate reader corroborates these values; the embedded PE manifest
  requests administrator execution. A machine-scope manifest correction is
  prepared in `target/nsis-audit/manifest-fixes/Garena.Garena.patch` and passes
  the official winget 1.1.0 installer schema. It has not been published.
- QuodLibet.QuodLibet: the branch was rebased onto `anthelion/anthelion`
  (`116e5b1e`). Its existing `FirstHeaderFinder` replaces the duplicate audit
  implementation. It searches at 512-byte file boundaries in the first 1 MiB
  of the executable. The separate reader finds machine-scope ARP literals
  matching the release source. All four complete hash-verified artifacts (4.4.0,
  4.5.0, 4.6.0, 4.7.1) return NSIS metadata with no interpreter warnings/errors
  after rebase. Their encoded ARP fields are independently corroborated. No
  extra Komac header-search changes remain.
- Huawei.DevEco: a previously timed-out artifact now returns output; interpreter
  aborts and other simulation gaps remain recorded.
- Unsupported plugins, external payloads, OS checks, prerequisites, unavailable
  downloads, and additional interpreter errors remain open. Registry effects of
  upgrades, different component selections, and user/machine modes need separate
  independent validation.

Unsupported System and other plugin calls now emit explicit warnings. The existing
NSISdl approximation assumes download success to explore later code, also with
an explicit warning. It does not download or execute prerequisites and cannot
establish what ARP writes would occur if the prerequisite fails.

## Resource limits and continuation

The runner reserves CPUs 6 and 7, uses CPUs 0–5 at reduced priority, permits sixteen
downloads and up to four shared analysis/independent-check slots, caps aggregate downloads at 128 MiB/s, waits
when available RAM is below 4 GiB, and limits each analysis to 6 GiB of virtual
address space. Independent header reads are limited to 64 MiB. Downloads stop
before exhausting a 3 GiB disk reserve. Builds use one job and a 10 GiB address-space ceiling. Disk I/O
uses idle priority; traces stream to bounded files and are gzip-compressed.
No network configuration or connection-management services are changed.

See `tests/fixtures/nsis/README.md` for commands. The runner snapshots the analyzer
and both reader scripts by SHA256, locks its journal against concurrent writers, and checkpoints on
SIGINT/SIGTERM. Normal resumption skips results for the same binary.
`--reuse-previous` advances breadth across analyzer versions, preserving each
result's provenance; `--recheck-id` reruns affected package families after fixes.
`--recheck-errors` also reruns older interpreter errors and unsuccessful analyses.
Broad rechecks are disabled for the ongoing scan. Prior analyses are retained;
independent checks run alongside each new artifact. `--recheck-static` is an
explicit optional recheck mode and is not used in the current queue. Rechecks
are reserved for targeted regression checks after relevant code changes. Older successes must not be described as tested with a newer analyzer.
A DNS failure stops submissions instead of misclassifying the whole corpus as
unavailable. Multi-installer outputs and Unicode download URLs are handled, and
compared string fields are loaded without YAML 1.1 scalar coercion.
For ZIPs, the exact manifest-selected nested installer is streamed to a fixed
temporary filename, then analyzed and hashed separately. All 452 ZIP artifacts
in this snapshot name one unique nested installer. Ambiguous or missing members
are reported as archive errors. Earlier generic ZIP analyses are retried.

The ongoing corpus scan uses an optimized release binary. `RUST_LOG=warn` is now
honored by CLI logging; the previous fixed TRACE filter ignored the runner's level
and formatted verbose interpreter and filesystem traces. Detailed logging remains
available for targeted reproductions. Phase timings distinguish downloads, queue
wait, analysis, and the independent reader. Vendor-only DNS failures are recorded
without stopping a healthy resolver; failed independent DNS health checks still
stop submissions. New artifacts are scheduled before optional rechecks.

While a build is running, use two analysis slots. Four slots are used after the
build finishes. Keep builds to one job, CPUs 6–7 reserved, and 4 GiB memory headroom.

## System and StdUtils plugin models

Sunsama 2.3.4 exposed numeric install roots such as `0\sunsama`. Its bytecode
sets a valid fallback directory, runs `System::Store S`, uses temporary API
registers, and then runs `System::Store L`. The missing save/restore left a
temporary zero in the directory register. System Store now uses a bounded private
register stack, restoring all 20 general registers while preserving NSIS's data
stack and internal variables. The source fixture fails against the old binary.
Semantics follow [System's Buffers.c](https://github.com/NSIS-Dev/nsis/blob/master/Contrib/System/Source/Buffers.c).

System now has a shared declaration parser and bounded interpreter rather than
special cases for individual call strings. It handles inline and legacy arguments,
quoted strings, register aliases, reverse-order stack outputs, initialized
references (`*i0s`), saved Get/Call declarations and overrides, `?r`/`?e`/`?n`
options, packed/aligned structures, size fields, ANSI/UTF-16 strings, GUIDs,
Alloc/StrAlloc/Copy/Free, Store's register and execution-flag commands, and the
Int64Op operations. The simulated heap has 8 MiB per-block and 64 MiB total
limits, checked aliases and lifetimes, and a read-only shared architecture page.
No installer DLL, host pointer, or Windows process is executed.

Useful Windows API models share this state: OS versions and process/native
architecture, default folders and paths, environment variables, string/encoding
helpers, mutex/process handles, module/procedure lookup, virtual clocks, native
registry reads/writes/enumeration, and ShellLink/PersistFile shortcut operations.
Native Reg* writes enter the same registry used for ordinary NSIS instructions
and ARP extraction. Interface encoding comes from the COM IID, independently of
the declaration's string type. Ordinary API return values and referenced outputs
follow the target pointer width. Semantics follow
[System.c](https://github.com/NSIS-Dev/nsis/blob/master/Contrib/System/Source/System.c).

The default profile is Windows 11 26H2, build 26300.9818, on native x64, with the
installer PE's process architecture, string encoding, and compatibility manifest. ANSI strings
use Windows-1252. Version APIs report NT version 10.0.26300; the update revision
is recorded in simulation diagnostics. The default follows Microsoft's
[latest release table](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information),
checked on 2026-11-06. `KOMAC_NSIS_WINDOWS_VERSION=X.Y.BUILD[.REVISION]` and
`KOMAC_NSIS_NATIVE_ARCH=x86|x64|arm64` select another profile; native ARM64 is
automatic for an ARM64 stub. GetVersionEx honors Win8/8.1/10 compatibility
reporting; RtlGetVersion reports the configured profile. Environment-dependent
models emit explicit simulation warnings, including OS, locale, process state,
virtual clocks, and default folder assumptions. Symbolic folders do not observe
actual redirection. A fresh simulated registry and application process list do
not establish upgrade behavior or prerequisite availability.

Unsupported DLL calls, callbacks, register-memory buffers, external pointers,
folder IDs, signatures, and COM interfaces remain explicitly unmodeled.
Declared unknown outputs become `$ERROR`, and reachable output memory is marked
unknown; an unsupported call must not silently look like a successful zero.
Neither simulation nor manifest agreement proves runtime ARP equivalence.
`system.nsi` compiles real plugin instructions and stock WinVer/x64 macros for
ANSI x86, Unicode x86, and Unicode AMD64. Expected ARP comes from its source
writes, independently of manifests; the executables are not run on Windows.

StdUtils handles GetParameter, TestParameter, GetAllParameters, ParameterCnt,
ParameterStr, NormalizePath, and GetParentPath for default invocation without
extra switches. Path helpers resolve absolute or symbolic-rooted Windows paths;
unknown relative contexts remain unmodeled. Stack effects and path behavior
follow the [plugin source](https://github.com/lordmulder/stdutils/blob/master/Contrib/StdUtils/src/StdUtils.cpp)
and [PathUtils.cpp](https://github.com/lordmulder/stdutils/blob/master/Contrib/StdUtils/src/PathUtils.cpp).

The dashboard flags numeric install roots as suspicious. Only the exact affected
artifact hashes are selected for the current regression pass using
`--regression-shas target/nsis-audit/path-regressions.txt`. Broader prior analyses
remain retained; new artifacts continue after these targeted repairs.
