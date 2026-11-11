// Package pe reads PE32 and PE32+ image headers and sections using bounded
// in-memory parsing. It is a standalone library with no scanner dependencies.
//
// New requires complete headers but does not validate the Windows loader's
// requirements, section bodies, or directory contents. It returns owned header
// metadata without retaining the input. Address helpers map only existing file
// bytes according to the policy documented on File.RVAToOffset.
package pe
