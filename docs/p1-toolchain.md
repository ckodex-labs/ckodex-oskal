# Go security patch for the final candidate

The final candidate requires Go 1.27.4, the current Go 1.27 security patch checked
on 2026-11-13 against the [official release history](https://go.dev/doc/devel/release#go1.27.4)
and [download API](https://go.dev/dl/?mode=json).

Go 1.27.4 was released on 2026-11-10 with security fixes including the Go command,
compiler, linker and net/http. The repository minimum, Docker builder and Dagger
build/test compiler now select 1.27.4. GitHub setup-go reads that root go.mod for
both CI and release builds. The nested Dagger SDK module retains its SDK-managed
minimum; the application's compilation and tests use the explicit patched image.

The installed default remained Go 1.27.3 during earlier component proofs. An
explicit automatic toolchain request fetched Go 1.27.4 with Go's checksum database
enabled. No global PATH or persistent Go environment setting was changed.

Actual commands and results:

```text
go env GOTOOLCHAIN GOSUMDB GOPROXY
auto
sum.golang.org
https://proxy.golang.org,direct

GOTOOLCHAIN=go1.27.4 go version
go: downloading go1.27.4 (darwin/arm64)
go version go1.27.4 darwin/arm64
exit 0

go version
go version go1.27.4 darwin/arm64
exit 0

go build ./...
exit 0

docker manifest inspect golang:1.27.4
exit 0
```

The registry response was retained at
`/private/tmp/oskal-go-1.27.4-manifest.json`. This verifies availability of the
official versioned image tag; it does not claim that a mutable tag is an immutable
identity. Final source testing, runtime image-byte verification and release
checksums/provenance are recorded separately. Earlier component results remain
labelled with their actual compiler version.
