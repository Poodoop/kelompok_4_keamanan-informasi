package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"crypto/aes"

	// "errors"
	// "os"

	"github.com/LarryBattle/nonce-golang"
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

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	checkError(err)

	echoProtocol := &echo.EchoProtocol{}

	// Untuk menyimpan data bytes dari server
	packetBytes := []byte("")

	// Untuk menyimpan session key
	sessionKey := []byte("")

	// Master key dari A
	masterKey := []byte("masterKey1234567")

	// ID A, ID B, dan nonce 1
	idA := []byte(nonce.NewToken())    // 32 bytes
	nonce1 := []byte(nonce.NewToken()) // 32 bytes

	/*
		Panjang session key dan master key = 16 bytes
		Panjang idA, idB, nonce1, dan nonce2 = 32 bytes

		Step 1:	Kirim ID A, dan nonce 1 ke B.

		Step 2: Menerima dan mendekripsi data yang berisi session key, ID A, ID B, nonce 1
				yang ditransformasikan, dan nonce 2 yang dienkripsi menggunakan shared master key.

				Mengirim data yang berisi nonce 2 yang ditransformasikan yang dienkripsi
				menggunakan session key.

	*/

	hasError := false

	for i := 0; i < 2; i++ {
		switch i {

		// Step 1
		case 0:
			fmt.Println("===== Step 1 =====")

			fmt.Println("Mengirim ID A dan nonce 1 ke B.")
			fmt.Println()

			fmt.Println("ID A = " + string(idA))
			fmt.Println("Nonce 1 = " + string(nonce1))

			// Buat data yang berisi ID A, ID B, dan nonce 1
			data := []byte("")

			data = append(data, idA...)    // 32 bytes
			data = append(data, nonce1...) // 32 bytes

			// Kirim data ke B
			conn.Write(echo.NewEchoPacket(data, false).Serialize())

			fmt.Println()

		// Step 2
		case 1:
			fmt.Println("===== Step 2 =====")

			fmt.Println("Menerima dan mendekripsi data yang berisi session key, ID A, ID B, nonce 1")
			fmt.Println("yang ditransformasikan, dan nonce 2 yang dienkripsi menggunakan shared master key.")
			fmt.Println()

			// Dekripsi data
			decrypted := decrypt(masterKey, packetBytes)

			sessionKey = decrypted[:16]
			checkIDA := decrypted[16:48]
			checkIDB := decrypted[48:80]
			checkNonce1 := decrypted[80:112]
			nonce2 := decrypted[112:]

			// Transformasikan kembali nonce 1 yang diterima dari B
			for i := 0; i < len(checkNonce1); i++ {
				checkNonce1[i] = checkNonce1[i] ^ 0xFF
			}

			// Pastikan ID A dan nonce 1 yang diterima benar
			if string(checkIDA) != string(idA) || string(checkNonce1) != string(nonce1) {
				fmt.Println("Nonce 1 yang diterima salah!")

				hasError = true
				break
			}

			fmt.Println("Session key = " + string(sessionKey))
			fmt.Println("ID A = " + string(idA) + " = " + string(checkIDA))
			fmt.Println("ID B = " + string(checkIDB))
			fmt.Println("Nonce 1 = " + string(nonce1) + " = " + string(checkNonce1))
			fmt.Println("Nonce 2 = " + string(nonce2))
			fmt.Println()

			fmt.Println("Mengirim data yang berisi nonce 2 yang ditransformasikan yang dienkripsi")
			fmt.Println("menggunakan session key.")
			fmt.Println()

			// Transformasikan nonce 2
			for i := 0; i < len(nonce2); i++ {
				nonce2[i] = nonce2[i] ^ 0xFF
			}

			// Enkripsi nonce 2
			nonce2 = encrypt(sessionKey, nonce2)

			// Kirim nonce 2
			conn.Write(echo.NewEchoPacket(nonce2, false).Serialize())

			fmt.Println()

		default:
			break
		}

		// Cek error
		if hasError {
			break
		}

		// Baca dan proses reply dari server
		p, err := echoProtocol.ReadPacket(conn)
		if err == nil {
			echoPacket := p.(*echo.EchoPacket)

			// Simpan data yang diterima dari server
			packetBytes = echoPacket.GetBody()

			packetLen := echoPacket.GetLength()
			packetBody := string(packetBytes)

			fmt.Printf("Server reply:[%v] [%v]\n\n", packetLen, packetBody)

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
