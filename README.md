# softblake3

A pure Go software implementation of the BLAKE3 hash function.

## Instalation

```bash
go get -u github.com/lemon-mint/softblake3
```

## Usage

```go
package main

import (
  "encoding/hex"
  "fmt"

  "github.com/lemon-mint/softblake3"
)

func main() {
  // Create a new Hasher.
  h := softblake3.New()
  text := "Hello, World!"
  h.WriteString(text)

  // Get the hash as a byte slice.
  hash := h.Sum(nil)

  fmt.Println(hex.EncodeToString(hash))
}
```

## License

This project is licensed under the CC0 1.0 Universal license. (Public Domain)
