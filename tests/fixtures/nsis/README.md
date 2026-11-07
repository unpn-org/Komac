The ARP regression oracle is `arp.nsi`, not a winget manifest. Its explicit writes
exercise unrelated registry keys, case-insensitive overwrites, registry reads,
conditional deletion, Unicode with variable expansion, default section selection,
and a section enabled by `.onInit`. It also covers INI operations, file and
registry enumeration, predefined variables, shared app data, numeric conversion,
UTF-16 slicing, and full-path operand layout. `arp.ini` is an extracted input.

Run from the repository root after building Komac:

```sh
python3 scripts/check_nsis_fixture.py --makensis /path/to/makensis --komac target/debug/komac
```

Requires PyYAML and NSIS 3. The script compiles all six solid/non-solid compression
combinations into a temporary directory. It analyzes the executables; it does not
run them. Expected values are specified independently in the script from the NSIS
source. This is a static semantic check, not an observed Windows registry capture.

Reference interpreter: https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/exec.c
(WriteReg, ReadReg, SectionSet). Park string and opcode layouts:
https://github.com/ip7z/7zip/blob/main/CPP/7zip/Archive/Nsis/NsisIn.cpp

The corpus runner is `scripts/audit_nsis.py`. Index a checkout or snapshot archive:

```sh
python3 scripts/audit_nsis.py --source /path/to/winget-pkgs.tar.gz --index target/nsis-audit/index.jsonl
python3 scripts/audit_nsis.py --index target/nsis-audit/index.jsonl --results target/nsis-audit/results.jsonl --komac target/debug/komac
```

It considers every NSIS reference, including historical versions and nested NSIS
installers, and deduplicates by SHA256. Downloads must match the manifest hash.
It resumes from existing results for the same analyzer hash. `--reuse-previous`
also skips older completed attempts to advance corpus breadth; each result keeps
its analyzer hash. Add `--recheck-id Package.Identifier` to rerun an affected
package family after a parser change. Older outputs remain unverified and are
not described as analyzed with the new binary.
Failed downloads remain recorded, not silently counted as tested installers.
Manifest differences are triage hints only. Matching manifests are not considered
proof of correctness; each result explicitly records `arp_verified: false`.
Runtime ARP equivalence needs an independent registry capture on Windows, including
installation mode, selected components, environment, and prerequisites.
Four additional `termination.nsi` cases check Abort/Quit in initialization and
sections, suppression of unreachable ARP writes, and the failure callback.

Resource limits for the full audit
----------------------------------

On this 8-core, 32 GiB environment, reserve cores 6 and 7, use sixteen download
workers and up to four analysis processes, and wait before starting new work
when available RAM falls below 4 GiB. Each analyzer has a 6 GiB virtual-address
limit. Compiler jobs run one at a time with a 10 GiB address-space cap.
CPU nice priority is lowered and disk I/O uses the idle class. These are ceilings,
not target allocations; monitor available memory and responsiveness during runs.

```sh
nice -n 10 ionice -c 3 taskset -c 0-5 prlimit --as=2147483648:8589934592 -- \
  python3 scripts/audit_nsis.py --index target/nsis-audit/index.jsonl \
    --results target/nsis-audit/results.jsonl --work target/nsis-audit/downloads \
    --logs target/nsis-audit/logs --komac target/release/komac --jobs 16 --analysis-jobs 4 \
    --cpu-count 6 --memory-mib 6144 --headroom-mib 4096 \
    --download-mibps 128 --download-timeout 600 --reuse-previous
```

Traces stream to disk and are gzip-compressed, so verbose interpreter output is
not accumulated in RAM. Each run copies the analyzer to a hash-addressed path;
a rebuild cannot change an analyzer midway through a run. SIGTERM/SIGINT stops
new work and checkpoints completed results. Interrupted downloads are retryable.
Keep journals in the workspace: `/tmp` was cleared between session continuations.
Resolver failures stop the run and do not count as artifact download failures.
Unicode URL paths are encoded before requesting them. Compared fields use a
string-preserving YAML loader to avoid YAML 1.1 numeric/boolean coercion.
For ZIPs it analyzes the manifest-selected nested executable and retains its
hash, rather than relying on automatic archive member selection. Runner hashes
also distinguish journal records and trace paths after harness changes.

Read current distinct-artifact counts with:

```sh
python3 scripts/summarize_nsis_audit.py target/nsis-audit/results.jsonl
```

The separate `scripts/independent_nsis.py` reader checks literal uninstall registry
writes in supported headers without using Komac or manifests as an oracle. Four
zlib/LZMA fixture builds also check that corrupted output is flagged. Literal
agreement is not proof of reachability or runtime registry equivalence. Reader
hashes and source snapshots are retained with each audit run. Nonrecursive RMDir,
wildcard Delete, active-directory protection, and exclusion of HKCR lookalike
uninstall paths are also covered by the source fixture.

An eleventh case inserts a sector before the NSIS header and updates the trailing
CRC. It checks detection after PE section padding and preserves the source ARP
expectations. Header discovery follows NSIS's 512-byte file boundaries, within a
first 1 MiB of the file using upstream FirstHeaderFinder.

The full scan retains prior analyses and schedules unseen artifacts first.
Broad `--recheck-static` passes are not part of normal continuation. Use two
analysis slots while compiling, then four when the optimized build is ready.
See the live dashboard's Analysis results browser for full metadata, ARP evidence,
manifest comparisons, diagnostics, and per-artifact run history.

`system.nsi` exercises the System plugin through compiled instructions, including
the stock WinVer and x64 macros, packed structures, heap copies, 64-bit arithmetic,
saved procedures, environment variables, known-folder strings, and native registry
writes. Run its ANSI x86, Unicode x86, and Unicode AMD64 cases with:

```sh
python3 scripts/check_system_fixture.py --makensis /path/to/makensis --komac target/release/komac
```

The toolchain needs the corresponding stubs and System DLLs. The check selects
the explicit Windows 11 26H2 build 26300.9818 / native x64 simulation profile.
Like the ARP fixture above, these executables are analyzed without running them
on Windows.
