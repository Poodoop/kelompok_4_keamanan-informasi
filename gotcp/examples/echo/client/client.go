package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"encoding/pem"
	"errors"
	"os"

	"github.com/gansidui/gotcp/examples/echo"
)

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func LoadPrivateKey(private_key_file string) (*rsa.PrivateKey, error) {
	privIn := make([]byte, 5000)

	f, err := os.Open(private_key_file)
	checkError(err)
	_, err = f.Read(privIn)
	checkError(err)

	// Import the keys from pem string
	priv_parsed, err := ParseRsaPrivateKeyFromPemStr(string(privIn))

	return priv_parsed, err
}

func LoadPublicKey(public_key_file string) (*rsa.PublicKey, error) {
	pubIn := make([]byte, 5000)

	f, err := os.Open(public_key_file)
	checkError(err)
	_, err = f.Read(pubIn)
	checkError(err)

	// Import the keys from pem string
	pub_parsed, err := ParseRsaPublicKeyFromPemStr(string(pubIn))

	return pub_parsed, err
}

func encrypt(key []byte, data []byte) (cipherText []byte) {
	// Buat AES cipher
	block, err := aes.NewCipher(key)
	checkError(err)

	// Hitung jumlah bytes untuk plain text dan cipher text
	byteCount := ((len(data) + aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize

	plainText := make([]byte, byteCount)
	cipherText = make([]byte, byteCount)

	// Copy data ke plainText
	for i := 0; i < len(data); i++ {
		plainText[i] = data[i]
	}

	// Enkripsi data menggunakan AES
	block.Encrypt(cipherText, plainText)

	return cipherText
}

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	checkError(err)

	echoProtocol := &echo.EchoProtocol{}

	// Load private key dari client
	clientPrivateKey, err := LoadPrivateKey("client_private.key")
	checkError(err)

	// Load public key dari server
	serverPublicKey, err := LoadPublicKey("server_public.key")
	_, err = LoadPublicKey("server_public.key")
	checkError(err)

	// Session key dari client
	sessionKey := []byte("1234567812345678")

	/*

		Step 1:	Kirim hash dari username dan password yang sudah dienkripsi
				menggunakan private key dari client (pakai RSA)

		Step 2:	Kirim session key yang sudah dienkripsi menggunakan
				public key dari server (pakai RSA juga)

		Step 3:	Kirim data yang sudah dienkripsi menggunakan session key
				dari client (pakai AES)

	*/
	for i := 0; i < 3; i++ {
		switch i {

		// Step 1
		case 0:
			fmt.Println("Mengirim message yang disign menggunakan private key dari client.")

			message := []byte("clientmessage")
			messageHash := sha256.New()
			_, err := messageHash.Write(message)
			checkError(err)

			messageHashSum := messageHash.Sum(nil)

			signature, err := rsa.SignPSS(rand.Reader, clientPrivateKey, crypto.SHA256, messageHashSum, nil)
			checkError(err)

			// Kirim data ke server
			conn.Write(echo.NewEchoPacket(signature, false).Serialize())

		// Step 2
		case 1:
			// Enkripsi session key menggunakan public key dari server
			encryptedData, err := rsa.EncryptOAEP(
				sha256.New(),
				rand.Reader,
				serverPublicKey,
				sessionKey,
				[]byte(""),
			)
			checkError(err)

			fmt.Println("Mengirim session key dari client yang sudah dienkripsi menggunakan public key dari server.")

			conn.Write(echo.NewEchoPacket(encryptedData, false).Serialize())

		// Step 3
		case 2:
			fmt.Println("Mengirim data yang sudah dienkripsi menggunakan session key dari client.")

			data := encrypt(sessionKey, []byte("secret message.."))

			conn.Write(echo.NewEchoPacket(data, false).Serialize())

		default:
			break
		}

		// Baca dan proses reply dari server
		p, err := echoProtocol.ReadPacket(conn)
		if err == nil {
			echoPacket := p.(*echo.EchoPacket)

			packetLen := echoPacket.GetLength()
			packetBody := string(echoPacket.GetBody())

			fmt.Printf("Server reply:[%v] [%v]\n", packetLen, packetBody)

			if packetBody == "failed" {
				break
			}
		}

		time.Sleep(2 * time.Second)
	}

	conn.Close()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
