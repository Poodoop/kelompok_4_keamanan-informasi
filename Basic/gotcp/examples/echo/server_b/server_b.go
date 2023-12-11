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

	"crypto/aes"

	"github.com/LarryBattle/nonce-golang"
	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

/*
REPLY_STEP untuk menentukan reply yang dikirim ke client
SESSION_KEY adalah session key yang akan diterima dari A
NONCE_ORIGINAL untuk membandingkan nonce yang diterima dari A
*/

var REPLY_STEP = 0
var SESSION_KEY []byte
var NONCE_ORIGINAL []byte

func encrypt(key []byte, data []byte) (encrypted []byte) {
	// Buat AES cipher
	block, err := aes.NewCipher(key)
	checkError(err)

	// Hitung jumlah blok
	blockCount := (aes.BlockSize - 1 + len(data)) / aes.BlockSize

	// Enkripsi data
	encrypted = make([]byte, blockCount*aes.BlockSize)

	idx := 1
	end := 0
	for blockCount > 0 {
		start := aes.BlockSize * (idx - 1)
		end = aes.BlockSize * idx

		block.Encrypt(encrypted[start:end], data[start:end])

		idx++
		blockCount--
	}

	return encrypted
}

func decrypt(key []byte, data []byte) (decrypted []byte) {
	// Buat AES cipher
	block, err := aes.NewCipher(key)
	checkError(err)

	// Hitung jumlah block
	blockCount := (aes.BlockSize - 1 + len(data)) / aes.BlockSize

	// Dekripsi data
	decrypted = make([]byte, blockCount*aes.BlockSize)

	idx := 1
	end := 0
	for blockCount > 0 {
		start := (idx - 1) * aes.BlockSize
		end = idx * aes.BlockSize

		block.Decrypt(decrypted[start:end], data[start:end])

		idx++
		blockCount--
	}

	return decrypted
}

type Callback struct{}

func (this *Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}

func (this *Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
	echoPacket := p.(*echo.EchoPacket)

	packetLen := echoPacket.GetLength()
	packetBody := echoPacket.GetBody()

	// Master key milik B
	masterKey := []byte("masterKeyB123456")

	var reply = []byte("")

	/*
		Panjang session key dan master key = 16 bytes
		Panjang idA, idB, nonce1, dan nonce2 = 32 bytes

		Step 1:	Menerima data yang berisi session key dan ID A yang dienkripsi menggunakan
				master key B.

				Mengirimkan nonce 2 yang dienkripsi menggunakan session key ke A

		Step 2: Menerima data yang berisi nonce 2 yang sudah ditransformasikan yang dienkripsi
				menggunakan session key

	*/

	switch REPLY_STEP {
	// Step 1
	case 0:
		fmt.Println("===== Step 1 =====")
		fmt.Println("Menerima data yang berisi session key dan ID A yang dienkripsi menggunakan")
		fmt.Println("master key B.")
		fmt.Println()
		fmt.Println("Mengirimkan nonce 2 yang dienkripsi menggunakan session key ke A")
		fmt.Println()

		// Dekripsi data menggunakan master key B
		decrypted := decrypt(masterKey, packetBody)

		// Ambil session key
		SESSION_KEY = decrypted[:16]

		// Buat nonce 2
		nonce2 := []byte(nonce.NewToken())
		NONCE_ORIGINAL = nonce2

		fmt.Println("Nonce 2 = " + string(nonce2))

		// Buat reply yang akan dikirimkan ke A
		reply = encrypt(SESSION_KEY, nonce2)

		// Lanjut ke step 2
		REPLY_STEP = 1

		fmt.Println()

	// Step 2
	case 1:
		fmt.Println("===== Step 2 =====")
		fmt.Println("Menerima data yang berisi nonce 2 yang sudah ditransformasikan yang dienkripsi")
		fmt.Println("menggunakan session key.")
		fmt.Println()

		// Dekripsi data yang diterima
		nonce2 := decrypt(SESSION_KEY, packetBody)

		// Nonce 2 original yang ditransformasikan untuk dicocokkan dengan
		// nonce 2 yang diterima dari A
		for i := 0; i < len(NONCE_ORIGINAL); i++ {
			NONCE_ORIGINAL[i] = NONCE_ORIGINAL[i] ^ 0xFF
		}

		fmt.Println(string(nonce2) + " = " + string(NONCE_ORIGINAL))

		// Bandingkan
		if string(nonce2) != string(NONCE_ORIGINAL) {
			fmt.Println("Nonce yang diterima salah!")
			reply = []byte("failed")
		} else {
			fmt.Println("Nonce yang diterima benar!")
			reply = []byte("ok")
		}

		fmt.Println()

		REPLY_STEP = 0

	default:
		// Balik ke step 1
		REPLY_STEP = 0
	}

	fmt.Printf("OnMessage:[%v] [%v]\n\n", packetLen, string(packetBody))
	c.AsyncWritePacket(echo.NewEchoPacket(reply, false), time.Second)

	return true
}

func (this *Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// creates a tcp listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8990")
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	// creates a server
	config := &gotcp.Config{
		PacketSendChanLimit:    2048,
		PacketReceiveChanLimit: 2048,
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
