# Export benchmark samples

Measured on November 12, 2026 with Go 1.27.3, macOS/arm64, and an Apple M3 Max.
The export implementation and comparison harness are from commit `d5dd107`.
The core baseline is `2007a24b76d20baa65444e1e4aa441aeac7d6846` (before exports).

The text files preserve each timing and allocation sample. Repeated headers and
command completion messages have been removed. Each case has six samples:

- `comparison.txt`: headers and exports from the same PE32+ fixtures; 1 second
  per sample. Dependency versions are pinned in the comparison module's `go.mod`.
- `exports.txt`: export parsing from an existing header snapshot; 500 milliseconds
  per sample. The two rejection cases measure an absent directory and an address
  count above `MaxExportSymbols`.
- `core-baseline.txt` and `core-candidate.txt`: header parsing, non-PE rejection,
  and standard imports; 1 second per sample. Baseline and candidate binaries
  alternated, reversing their order for each pair. No concurrent fuzzing ran.

The median headers-plus-exports measurements were:

| Symbols | Parser | Time per operation | Allocations per operation |
| --- | --- | --- | --- |
| 16 | go-pe | 0.724 µs | 24 |
| 16 | Binject/debug | 3.072 µs | 45 |
| 16 | saferwall/pe | 6.320 µs | 101 |
| 256 | go-pe | 8.319 µs | 264 |
| 256 | Binject/debug | 23.64 µs | 297 |
| 256 | saferwall/pe | 67.70 µs | 843 |

The measured core cases had no statistically significant timing change under
`benchstat`; bytes and allocation counts were unchanged. In particular, parsing
256 standard imports took 5.831 µs at both revisions (p = 0.818, n = 6).

These are small synthetic workloads with different output representations and
validation policies. See the [comparison scope](../README.md#comparison-scope)
before interpreting the results. They don't predict every file's scan cost.

To summarize the stored samples, run these commands from this directory:

```sh
benchstat comparison.txt
benchstat exports.txt
benchstat core-baseline.txt core-candidate.txt
```

To reproduce the core check, compile the root package's test binary at each
revision with `go test -c -o PATH`. Run each binary with `-test.run='^$'`,
`-test.benchmem`, `-test.benchtime=1s`, and each of these benchmark filters:

```text
^BenchmarkNew$/(Sections8|NonPE)$
^BenchmarkImports$/PE64=true$/Symbols256$
```

Collect six alternating pairs. The parent comparison guide provides the
commands for reproducing the export measurements.

## Alias bookkeeping check

`review-baseline.txt` and `review-candidate.txt` use the same environment as the
samples above. The baseline is `69ffba6` with the ordinal-only benchmark cases
added. The candidate's `exports.go` blob is
`6be2cf76a9666d398fc8f1d2784a3c6b6f245025`. Six pairs alternated baseline and
candidate binaries, reversing their order for each pair, with no concurrent
fuzzing. Each sample ran for 1 second using this filter:

```text
^BenchmarkExports$/PE64=true$/Symbols(256|65536)$
```

Named exports retained 261 allocations and showed no significant timing change
(7.848 µs to 7.801 µs; p = 0.310). Ordinal-only parsing dropped from four to three
allocations: 256 slots saved 1 KiB and measured 1.508 µs to 1.385 µs (p = 0.002).
At 65,536 slots, it saved 256 KiB with no significant timing change (p = 0.065).
The fixtures retain their unused name table bytes but declare zero names.

```sh
benchstat review-baseline.txt review-candidate.txt
```
