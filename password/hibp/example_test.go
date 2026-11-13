package hibp_test

import (
	"context"
	"fmt"

	"github.com/mtnaskari/goraz/password/hibp"
)

// Only the first five hexadecimal characters of the password's SHA-1 hash are sent.
// This example has no output check, because it makes a real network request.
func ExampleClient_Count() {
	n, err := hibp.New().Count(context.Background(), []byte("password"))
	if err != nil {
		fmt.Println("check failed:", err)
		return
	}
	fmt.Println(n > 0)
}
