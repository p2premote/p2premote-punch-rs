//go:build ignore

// Standalone vector generator for p2premote-punch-rs tests. Uses only the
// standard library so it runs with any Go toolchain. Run:
//   go run tests/go-vector/main.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func deriveKeyForTopic(salt, uid string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(md5hex(uid)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func deriveKeyForPayload(uid string, ascii bool) string {
	h := sha256.New()
	h.Write([]byte("gonc-p2p-payload"))
	h.Write([]byte(md5hex(uid)))
	if ascii {
		return hex.EncodeToString(h.Sum(nil))[:8]
	}
	return string(h.Sum(nil)[:8])
}

func deriveKey(salt, uid string) [32]byte {
	h := sha256.New()
	h.Write([]byte("nc-p2p-tool"))
	h.Write([]byte(salt))
	h.Write([]byte(uid))
	return sha256.Sum256(h.Sum(nil))
}

func encryptAESGCM(key [32]byte, plaintext []byte) (nonceB64, dataB64 string) {
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ct)
}

func fixedECDH(d1, d2 *big.Int) (pub1B64 string, sharedHex string) {
	curve := elliptic.P256()
	priv1 := &ecdsa.PrivateKey{D: d1, PublicKey: ecdsa.PublicKey{Curve: curve}}
	priv1.PublicKey.X, priv1.PublicKey.Y = curve.ScalarBaseMult(d1.Bytes())
	pub1 := elliptic.Marshal(curve, priv1.PublicKey.X, priv1.PublicKey.Y)

	priv2 := &ecdsa.PrivateKey{D: d2, PublicKey: ecdsa.PublicKey{Curve: curve}}
	priv2.PublicKey.X, priv2.PublicKey.Y = curve.ScalarBaseMult(d2.Bytes())

	x, _ := curve.ScalarMult(priv2.PublicKey.X, priv2.PublicKey.Y, priv1.D.Bytes())
	shared := sha256.Sum256(x.Bytes())
	return base64.StdEncoding.EncodeToString(pub1), hex.EncodeToString(shared[:])
}

func main() {
	fmt.Println("md5_empty=" + md5hex(""))
	fmt.Println("md5_hello=" + md5hex("hello"))
	fmt.Println("md5_demo=" + md5hex("demo-token-kx"))

	fmt.Println("topic_wgvpn=" + deriveKeyForTopic("wgvpn-kx/", "demo-token-kx"))
	fmt.Println("topic_gonc_addr=" + deriveKeyForTopic("gonc-exchange-address", "p2p-token"))
	fmt.Println("topic_cid=" + deriveKeyForTopic("mqtt-topic-gonc-cid", "p2p-token")[:8])

	fmt.Println("payload_ascii=" + deriveKeyForPayload("p2p-token", true))
	fmt.Println("payload_bin=" + hex.EncodeToString([]byte(deriveKeyForPayload("p2p-token", false))))

	key := deriveKey("mqtt-exchange-gonc-v2.2.0", "uid-123")
	fmt.Println("derive_key=" + hex.EncodeToString(key[:]))

	nonce, data := encryptAESGCM(key, []byte(`{"addrs":[],"pk":""}`))
	fmt.Println("aes_nonce=" + nonce)
	fmt.Println("aes_data=" + data)

	// ECDH with fixed scalars d1=0x0123...2f, d2=0x0456...c1
	d1 := new(big.Int).SetBytes([]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
		0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x2f,
	})
	d2 := new(big.Int).SetBytes([]byte{
		0x04, 0x56, 0x89, 0xac, 0xdf, 0x11, 0x24, 0x57,
		0x8a, 0xce, 0x01, 0x34, 0x67, 0x9a, 0xcd, 0xf0,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f, 0x1e, 0xc1,
	})
	pub1B64, sharedHex := fixedECDH(d1, d2)
	fmt.Println("ecdh_pub1=" + pub1B64)
	fmt.Println("ecdh_shared=" + sharedHex)
}
