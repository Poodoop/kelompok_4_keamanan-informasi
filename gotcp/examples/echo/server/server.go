package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

type Callback struct{}

/*
REPLY_STEP untuk menentukan reply yang dikirim ke client

SESSION_KEY adalah session key dari client yang akan digunakan
untuk mendekripsi data yang dikirim oleh client
*/

var REPLY_STEP = 0
var SESSION_KEY = []byte("")

func decrypt(key []byte, cipherText []byte) (plainText []byte) {
	// Buat AES cipher
	block, err := aes.NewCipher(key)
	checkError(err)

	// Untuk output plain text
	plainText = make([]byte, len(cipherText))

	// Enkripsi data menggunakan AES
	block.Decrypt(plainText, cipherText)

	return plainText
}

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

func (this *Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}

func (this *Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
	echoPacket := p.(*echo.EchoPacket)

	// packetLen := echoPacket.GetLength()
	packetBody := echoPacket.GetBody()
	// packetStr := string(packetBody)

	var reply = []byte("")

	switch REPLY_STEP {
	case 0:
		// Load public key dari client
		clientPublicKey, err := LoadPublicKey("client_public.key")
		checkError(err)

		// Buat message hash sum
		message := []byte("clientmessage")
		messageHash := sha256.New()
		_, err = messageHash.Write(message)
		checkError(err)

		messageHashSum := messageHash.Sum(nil)

		// Verify message hash sum menggunakan client public key dan signature yang dikirim client
		err = rsa.VerifyPSS(clientPublicKey, crypto.SHA256, messageHashSum, packetBody, nil)

		fmt.Println("Received client's message signature, verifying using client public key...")

		if err == nil {
			reply = []byte("verified")

			fmt.Println("Client is verified!")

			// Lanjut ke step 2
			REPLY_STEP = 1
		} else {
			reply = []byte("failed")

			fmt.Println("Client could not be verified!")

			// Balik ke step 1
			REPLY_STEP = 0
		}

	case 1:
		fmt.Println("Received client session key, decrypting using server private key...")

		// Load private key dari server
		serverPrivateKey, err := LoadPrivateKey("server_private.key")
		checkError(err)

		// Dekripsi session key dari client menggunakan private key dari server
		decrypted, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			serverPrivateKey,
			packetBody,
			[]byte(""),
		)

		if err == nil {
			reply = []byte("ok1")
		} else {
			reply = []byte("failed")
		}

		fmt.Printf("Session key : [%v]\n", string(decrypted))

		// Simpan session key
		SESSION_KEY = decrypted

		// Lanjut ke step 3
		REPLY_STEP = 2

	case 2:
		fmt.Println("Received data from client, decrypting using session key...")

		decrypted := decrypt(SESSION_KEY, packetBody)

		fmt.Printf("Decrypted message : [%v]\n", string(decrypted))

		reply = []byte("ok2")

		// Balik ke step 1
		REPLY_STEP = 0

	default:
		// Balik ke step 1
		REPLY_STEP = 0
	}

	// fmt.Printf("OnMessage:[%v] [%v]\n", packetLen, packetBody)
	c.AsyncWritePacket(echo.NewEchoPacket(reply, false), time.Second)

	return true
}

func (this *Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// creates a tcp listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8989")
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	// creates a server
	config := &gotcp.Config{
		PacketSendChanLimit:    20,
		PacketReceiveChanLimit: 20,
	}
	srv := gotcp.NewServer(config, &Callback{}, &echo.EchoProtocol{})

	// starts service
	go srv.Start(listener, time.Second)
	fmt.Println("listening:", listener.Addr())

	// catchs system signal
	chSig := make(chan os.Signal)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Signal: ", <-chSig)

	// stops service
	srv.Stop()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
