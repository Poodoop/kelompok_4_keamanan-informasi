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

	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

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

	// Buat session key
	sessionKey := []byte("sessionKey123456")

	// Master key milik A dan B
	masterKeyA := []byte("masterKeyA123456")
	masterKeyB := []byte("masterKeyB123456")

	fmt.Println()
	fmt.Println("Menerima data yang berisi ID A, ID B, dan nonce 1")

	// Ambil data
	idA := packetBody[:32]
	idB := packetBody[32:64]
	nonce1 := packetBody[64:96]

	fmt.Println("ID A = " + string(idA))
	fmt.Println("ID B = " + string(idB))
	fmt.Println("Nonce 1 = " + string(nonce1))
	fmt.Println()

	// Buat data yang akan dikirimkan ke A
	dataA := sessionKey
	dataA = append(dataA, packetBody...)
	dataA = encrypt(masterKeyA, dataA)

	// Buat data yang akan dikirimkan ke B
	dataB := sessionKey
	dataB = append(dataB, idA...)
	dataB = encrypt(masterKeyB, dataB)

	// Gabungkan data untuk A dan data untuk B
	data := append(dataA, dataB...)

	fmt.Println("Mengirimkandata yang berisi session key, ID A, ID B, dan nonce 1 yang dienkripsi")
	fmt.Println("menggunakan master key A dan data yang berisi session key dan ID A yang")
	fmt.Println("dienkripsi menggunakan master key B.")
	fmt.Println()

	fmt.Printf("OnMessage:[%v] [%v]\n\n", packetLen, string(packetBody))
	c.AsyncWritePacket(echo.NewEchoPacket(data, false), time.Second)

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
