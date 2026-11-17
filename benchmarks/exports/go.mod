module github.com/cawalch/go-pe/benchmarks/exports

go 1.26.0

require (
	github.com/Binject/debug v0.0.0-20260128230015-4e22595eaac6
	github.com/Velocidex/go-pe v0.1.0
	github.com/cawalch/go-pe v0.0.0
	github.com/foxboron/go-uefi v0.0.0-20261004203234-c7f1f57bdc6e
	github.com/saferwall/pe v1.6.5
)

require (
	github.com/ayoubfaouzi/pkcs7 v0.2.3 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)

replace github.com/cawalch/go-pe => ../..
