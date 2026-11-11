# Contributing to go-pe

Keep changes focused on the standalone PE parser. Include regression tests for
behavior changes and benchmarks for changes to parsing or address lookup.

## Scope a change

Before adding an analysis feature, assess existing Go libraries for suitable
implementations. Consider their APIs, dependencies, licenses, input validation,
resource use, and performance on comparable workloads. Use standard-library
primitives where they meet the requirements.

Keep scanner schemas, rule semantics, and scan lifecycle management in consuming
projects. If a feature adds expensive parsing, define its work limits and
cancellation behavior for general library callers.

## Write documentation

Follow the [Google developer documentation style guide](https://developers.google.com/style/)
for the README, repository documentation, and prose in code comments. Follow
[Go doc comment conventions](https://go.dev/doc/comment) for API comments and
`gofmt` for Go code, including code samples.

- Write direct sentences in active voice. Address the reader as “you” in instructions.
- Use familiar words, sentence-case headings, and consistent technical terms.
- Define abbreviations on first use when readers might not know them.
- Put conditions before instructions. Use numbered lists for ordered steps.
- Introduce code samples and commands. Provide runnable examples or identify
  omitted context, and verify the examples you change.
- Describe implemented behavior and relevant limits. Avoid promotional claims,
  unsupported guarantees, and promises about future features.
- Start exported API comments with the identifier's name. Link related symbols
  with Go doc links, such as `[New]`.

## Validate a change

From the repository root, format the Go files and run the tests and static checks:

```sh
gofmt -w *.go
go test -race -cover ./...
go vet ./...
```

For parser or reader changes, run the applicable fuzz target:

```sh
go test -run '^$' -fuzz '^FuzzNew$' -fuzztime=30s -parallel=2
go test -run '^$' -fuzz '^FuzzSafeReader$' -fuzztime=30s -parallel=2
```

The tests compare PE32 and PE32+ header fields and sections with `debug/pe`. They
also cover truncation, directory bounds, COFF strings, arithmetic overflow,
address mapping, and concurrent reads. These comparisons and bounded fuzz runs
don't establish full format compatibility or prove that all inputs are safe.

## Measure performance

To collect timing and allocation samples, run the benchmarks:

```sh
go test -run '^$' -bench . -benchmem -count=5
```

Record the Go version, CPU, workload, and raw results. Benchmarks cover parsing
1, 8, 96, and 256 sections, rejecting non-PE input, and translating addresses.
The `debug/pe` comparison measures header parsing; the libraries perform different
amounts of work, so it doesn't establish overall performance superiority.
