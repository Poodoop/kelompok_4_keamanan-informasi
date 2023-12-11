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
	// Connect ke KDC
	tcpAddrKDC, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	checkError(err)
	connKDC, err := net.DialTCP("tcp", nil, tcpAddrKDC)
	checkError(err)

	// Connect ke B
	tcpAddrB, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8990")
	checkError(err)
	connB, err := net.DialTCP("tcp", nil, tcpAddrB)
	checkError(err)

	echoProtocol := &echo.EchoProtocol{}

	// Untuk menyimpan data bytes dari server
	packetBytes := []byte("")

	// Untuk menyimpan session key
	sessionKey := []byte("")

	// Master key dari A
	masterKey := []byte("masterKeyA123456")

	// ID A, ID B, dan nonce 1
	idA := []byte(nonce.NewToken())    // 32 bytes
	idB := []byte(nonce.NewToken())    // 32 bytes
	nonce1 := []byte(nonce.NewToken()) // 32 bytes

	/*
		Panjang session key dan master key = 16 bytes
		Panjang idA, idB, nonce1, dan nonce2 = 32 bytes

		Step 1:	Kirim ID A, ID B, dan nonce 1 ke KDC.

		Step 2: Menerima data yang berisi session key, ID A, ID B, dan nonce 1 yang dienkripsi menggunakan
				master key A dan data yang berisi session key dan ID A yang dienkripsi menggunakan
				master key B.

				Mendekripsi data yang berisi session key, ID A, ID B, dan nonce 1 menggunakan
				master key A, kemudian mencocokkan nonce yang diterima dengan nonce yang
				dikirimkan oleh A.

				Mengirim data yang berisi session key dan ID A yang dienkripsi menggunakan
				master key B ke B.

		Step 3: Menerima data yang berisi nonce 2 yang dienkripsi menggunakan session key.
				Mendekripsi data menggunakan session key, kemudian mentransformasikan
				nonce 2 yang diterima.

				Mengirimkan data yang berisi nonce 2 yang sudah ditransformasikan yang dienkripsi
				menggunakan session key ke B.

	*/

	hasError := false

	// Current connection
	conn := connKDC

	for i := 0; i < 3; i++ {
		switch i {

		// Step 1
		case 0:
			fmt.Println("===== Step 1 =====")

			fmt.Println("Mengirim ID A, ID B, dan nonce 1 ke KDC.")
			fmt.Println()

			// Buat data yang berisi ID A, ID B, dan nonce 1
			data := []byte("")

			data = append(data, idA...)
			data = append(data, idB...)
			data = append(data, nonce1...) // 96 bytes

			fmt.Printf("Data len = %v\n", len(data))

			// Kirim data ke KDC
			conn = connKDC
			conn.Write(echo.NewEchoPacket(data, false).Serialize())

			fmt.Println()

		// Step 2
		case 1:
			fmt.Println("===== Step 2 =====")

			fmt.Println("Mendekripsi data yang berisi session key, ID A, ID B, dan nonce 1 menggunakan")
			fmt.Println("master key A, kemudian mencocokkan nonce yang diterima dengan nonce yang")
			fmt.Println("oleh A.")
			fmt.Println()

			dataA := packetBytes[:112]
			dataB := packetBytes[112:]

			decrypted := decrypt(masterKey, dataA)

			sessionKey = decrypted[:16]
			checkIDA := decrypted[16:48]
			checkIDB := decrypted[48:80]
			checkNonce1 := decrypted[80:]

			fmt.Println("Session key = " + string(sessionKey))
			fmt.Println(string(idA) + " = " + string(checkIDA))
			fmt.Println(string(idB) + " = " + string(checkIDB))
			fmt.Println(string(nonce1) + " = " + string(checkNonce1))

			// Cocokkan data
			if string(checkIDA) != string(idA) || string(checkIDB) != string(idB) || string(checkNonce1) != string(nonce1) {
				fmt.Println("Data yang diterima salah!")

				hasError = true
				break
			}

			// Kirim data B ke B
			conn = connB
			conn.Write(echo.NewEchoPacket(dataB, false).Serialize())

			fmt.Println()

		// Step 3
		case 2:
			fmt.Println("===== Step 3 =====")

			fmt.Println("Menerima data yang berisi nonce 2 yang dienkripsi menggunakan session key.")
			fmt.Println("Mendekripsi data menggunakan session key, kemudian mentransformasikan")
			fmt.Println("nonce 2 yang diterima.")
			fmt.Println()
			fmt.Println("Mengirimkan data yang berisi nonce 2 yang sudah ditransformasikan yang dienkripsi")
			fmt.Println("menggunakan session key ke B.")
			fmt.Println()

			// Dekripsi nonce 2
			nonce2 := decrypt(sessionKey, packetBytes)

			fmt.Println("Nonce 2 = " + string(nonce2))

			// Transformasikan nonce2
			for i := 0; i < len(nonce2); i++ {
				nonce2[i] = nonce2[i] ^ 0xFF
			}

			fmt.Println("Nonce 2 (transformed) = " + string(nonce2))

			// Enkripsi menggunakan session key
			nonce2 = encrypt(sessionKey, nonce2)

			// Mengirim data ke B
			conn = connB
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
