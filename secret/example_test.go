package secret_test

import (
	"encoding/json"
	"fmt"

	"github.com/mtnaskari/goraz/secret"
)

// A Secret never reveals its bytes through formatting or JSON, so logging a struct
// that holds one is safe.
func Example() {
	type config struct {
		User     string
		Password secret.Secret
	}
	c := config{User: "app", Password: secret.New([]byte("hunter2"))}
	defer c.Password.Wipe()

	fmt.Printf("%v\n", c)
	b, _ := json.Marshal(c)
	fmt.Println(string(b))
	fmt.Println(string(c.Password.Bytes()))
	// Output:
	// {app [REDACTED]}
	// {"User":"app","Password":"[REDACTED]"}
	// hunter2
}
