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
NONCE_ORIGINAL untuk membandingkan nonce yang diterima dari A
*/

var REPLY_STEP = 0
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

	// Shared master key
	masterKey := []byte("masterKey1234567")

	// Session key
	sessionKey := []byte("sessionKey123456")

	var reply = []byte("")

	/*
		Panjang session key dan master key = 16 bytes
		Panjang idA, idB, nonce1, dan nonce2 = 32 bytes

		Step 1:	Menerima data yang berisi ID A dan nonce 1.

				Mengirimkan session key, ID A, ID B, nonce 1 yang ditransformasikan, dan nonce 2
				yang dienkripsi menggunakan shared master key.

		Step 2: Menerima data yang berisi nonce 2 yang sudah ditransformasikan yang dienkripsi
				menggunakan session key

	*/

	switch REPLY_STEP {
	// Step 1
	case 0:
		fmt.Println("===== Step 1 =====")
		fmt.Println("Menerima data yang berisi ID A dan nonce 1.")
		fmt.Println()

		// Ambil ID A dan nonce 1
		idA := packetBody[:32]
		nonce1 := packetBody[32:]

		fmt.Println("ID A = " + string(idA))
		fmt.Println("Nonce 1 = " + string(nonce1))

		// Buat data yang akan dikirimkan ke A
		idB := []byte(nonce.NewToken())
		nonce2 := []byte(nonce.NewToken())
		NONCE_ORIGINAL = nonce2

		// Transformasikan nonce 1
		for i := 0; i < len(nonce1); i++ {
			nonce1[i] = nonce1[i] ^ 0xFF
		}

		fmt.Println("Mengirimkan session key, ID A, ID B, nonce 1 yang ditransformasikan, dan nonce 2")
		fmt.Println("yang dienkripsi menggunakan shared master key.")
		fmt.Println()

		fmt.Println("Session key = " + string(sessionKey))
		fmt.Println("ID A = " + string(idA))
		fmt.Println("ID B = " + string(idB))
		fmt.Println("Nonce 1 (transformed) = " + string(nonce1))
		fmt.Println("Nonce 2 = " + string(nonce2))
		fmt.Println()

		reply = sessionKey
		reply = append(reply, idA...)
		reply = append(reply, idB...)
		reply = append(reply, nonce1...)
		reply = append(reply, nonce2...)
		reply = encrypt(masterKey, reply)

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
		nonce2 := decrypt(sessionKey, packetBody)

		// Transformasikan kembali nonce 2 yang diterima untuk
		// dicocokkan dengan nonce 2 yang dikirimkan
		for i := 0; i < len(nonce2); i++ {
			nonce2[i] = nonce2[i] ^ 0xFF
		}

		fmt.Println("Nonce 2 = " + string(nonce2) + " = " + string(NONCE_ORIGINAL))

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
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8989")
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
