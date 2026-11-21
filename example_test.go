package pe_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func ExampleNew() {
	data := testfixture.Minimal(true, 2)
	f, err := pe.New(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("64-bit=%t sections=%d\n", f.Is64Bit(), f.NumberOfSections())
	// Output:
	// 64-bit=true sections=2
}

func ExampleNewFromReaderAt() {
	data := testfixture.Minimal(true, 2)
	r := bytes.NewReader(data)
	f, err := pe.NewFromReaderAt(r, int64(len(data)))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("size=%d sections=%d\n", f.FileSize(), f.NumberOfSections())
	// Output:
	// size=1536 sections=2
}

func ExampleFile_Imports() {
	data := testfixture.Imports(true, 1, 2)
	f, err := pe.New(data)
	if err != nil {
		log.Fatal(err)
	}
	libs, err := f.Imports(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("dll=%s symbols=%d\n", libs[0].DLL, len(libs[0].Symbols))
	// Output:
	// dll=lib0.dll symbols=2
}

func ExampleFile_ComputeCheckSum() {
	data := testfixture.Minimal(true, 1)
	f, err := pe.New(data)
	if err != nil {
		log.Fatal(err)
	}
	sum, err := f.ComputeCheckSum(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("nonzero=%t\n", sum != 0)
	// Output:
	// nonzero=true
}

func ExampleFile_LayoutAnomalies() {
	data := testfixture.Minimal(true, 2)
	f, err := pe.New(data)
	if err != nil {
		log.Fatal(err)
	}
	anomalies := f.LayoutAnomalies()
	fmt.Printf("any=%t\n", anomalies.Any())
	// Output:
	// any=false
}
