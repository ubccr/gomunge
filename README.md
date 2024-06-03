# gomunge - Go bindings for MUNGE

[![GoDoc](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/ubccr/gomunge)

Go bindings for [MUNGE](https://github.com/dun/munge) (MUNGE Uid 'N' Gid
Emporium) an authentication service for creating and validating user
credentials.

Requires CGO and libmunge to be installed.

## Usage

Install using go tools:

```
$ go get github.com/ubccr/gomunge
```

Example:

```go
package main

import (
    "fmt"

    "github.com/ubccr/gomunge"
)

func main() {
    // Encode default cred
    b64, err := munge.Encode()

    // Encode cred with options
    b64, err := munge.NewCredential(munge.WithPayload(payload), munge.WithTTL(800))
	
    // Use b64 in some transport

    // Decode cred
    cred, err := munge.Decode(b64)

    fmt.printf("%s\n", cred.UidString())
}
```

## License

gomunge is released under the GPLv3 license. See the LICENSE file.
