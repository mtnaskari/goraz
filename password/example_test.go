package password_test

import (
	"fmt"
	"time"

	"github.com/mtnaskari/goraz/password"
)

func ExampleGenerate() {
	s, err := password.Generate(password.DefaultLength, password.DefaultAlphabet)
	if err != nil {
		panic(err)
	}
	defer s.Wipe()
	fmt.Println(s.Len())
	// Output: 24
}

func ExampleTOTP() {
	// RFC 6238 test key and time, with 8 digits.
	code, err := password.TOTP([]byte("12345678901234567890"), time.Unix(59, 0), 30, 8, password.SHA1)
	fmt.Println(code, err)
	// Output: 94287082 <nil>
}

func ExampleCheckMaster() {
	fmt.Println(password.CheckMaster([]byte("short")))
	fmt.Println(password.CheckMaster([]byte("violet granite ocean drift lantern")))
	// Output:
	// password: use at least 15 characters; a generated passphrase is recommended
	// <nil>
}
