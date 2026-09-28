package compositemldsa_test

import (
	"fmt"
	"log"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
)

// Signs a message with a new composite key and verifies the signature.
func Example() {
	key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA65ECDSAP256SHA512)
	if err != nil {
		log.Fatal(err)
	}
	message := []byte("hello, post-quantum world")
	signature, err := key.Sign(nil, message, nil)
	if err != nil {
		log.Fatal(err)
	}
	err = compositemldsa.Verify(key.PublicKey(), message, signature, nil)
	fmt.Println(key.Algorithm(), key.Algorithm().OID(), err == nil)
	// Output: MLDSA65-ECDSA-P256-SHA512 1.3.6.1.5.5.7.6.45 true
}

// Stores a key as PKCS #8 and loads it again.
func ExampleParsePKCS8PrivateKey() {
	key, err := compositemldsa.GenerateKey(compositemldsa.MLDSA44Ed25519SHA512)
	if err != nil {
		log.Fatal(err)
	}
	der, err := compositemldsa.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	loaded, err := compositemldsa.ParsePKCS8PrivateKey(der)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(loaded.Equal(key))
	// Output: true
}
