package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type HexHash [32]byte

func NewHexHash(data []byte) HexHash {
	return HexHash(sha256.Sum256(data))
}

func (h HexHash) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}

func (h *HexHash) UnmarshalText(data []byte) error {
	if hex.DecodedLen(len(data)) != 32 {
		return fmt.Errorf("Hash has incorrect number of bytes to decode: %v != 32", hex.DecodedLen(len(data)))
	}
	_, err := hex.Decode(h[:], data)
	if err != nil {
		return err
	}
	return nil
}

func (h HexHash) String() string {
	return hex.EncodeToString(h[:])
}

type BlockHeader struct {
	ParentId   HexHash   `json:"parentid"`
	Root       HexHash   `json:"root"`
	Difficulty uint64    `json:"difficulty"`
	Timestamp  uint64    `json:"timestamp"`
	Nonces     [3]uint64 `json:"nonces"`
	Version    byte      `json:"version"`
}

type Block struct {
	Header   BlockHeader `json:"header"`
	Contents string      `json:"block"`

	Id            HexHash `json:"id,omitempty"`
	BlockHeight   int     `json:"blockheight,omitempty"`
	IsMainChain   bool    `json:"ismainchian,omitempty"`
	EverMainChain bool    `json:"evermainchain,omitempty"`
	TotalDiff     int     `json:"totaldiff,omitempty"`
	Timestamp     string  `json:"timestamp,omitempty"`
}

var ServerURL = "http://6857coin.csail.mit.edu"

func GetNext() (*BlockHeader, error) {
	resp, err := http.Get(ServerURL + "/next")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Bad response: %v; Body could not be read: %v", resp.Status, err)
		}
		return nil, fmt.Errorf("Bad response: %v; Body: %v", resp.Status, string(body))
	}

	next := &BlockHeader{}
	err = json.NewDecoder(resp.Body).Decode(next)
	if err != nil {
		return nil, err
	}

	return next, nil
}

func SendBlock(b *Block) error {
	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(b)
	if err != nil {
		return err
	}

	resp, err := http.Post(ServerURL+"/add", "application/json", buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Bad response: %v; Body could not be read: %v", resp.Status, err)
		}
		return fmt.Errorf("Bad response: %v; Body: %v", resp.Status, string(body))
	}

	return nil
}

func (h *BlockHeader) SetContents(contents string) {
	h.Root = NewHexHash([]byte(contents))
}

func (h *BlockHeader) SetTimestamp(t time.Time) {
	h.Timestamp = uint64(t.UnixNano())
}

func (h *BlockHeader) SetNonce0(n0 uint64) {
	h.Nonces[0] = n0
}

func (h *BlockHeader) SetNonce12(n1, n2 uint64) {
	h.Nonces[1] = n1
	h.Nonces[2] = n2
}

func (h *BlockHeader) Seeds() (HexHash, HexHash) {
	buf := &bytes.Buffer{}
	buf.Write(h.ParentId[:])
	buf.Write(h.Root[:])
	binary.Write(buf, binary.BigEndian, h.Difficulty)
	binary.Write(buf, binary.BigEndian, h.Timestamp)
	binary.Write(buf, binary.BigEndian, h.Nonces[0])
	binary.Write(buf, binary.BigEndian, h.Version)

	data := buf.Bytes()
	if len(data) != 89 {
		panic("Invalid buffer length")
	}

	seed1 := NewHexHash(data)
	seed2 := NewHexHash(seed1[:])

	return seed1, seed2
}

func (h *BlockHeader) Verify() bool {
	// TODO
	return true
}

func (h *BlockHeader) SolveNonces(ctx context.Context) error {
	c := exec.CommandContext(ctx, "./aesham2")

	stdin := &bytes.Buffer{}
	seed1, seed2 := h.Seeds()
	fmt.Fprintf(stdin, "%x\n", seed1[:])
	fmt.Fprintf(stdin, "%x\n", seed2[:])
	difficulty := h.Difficulty
	fmt.Fprintf(stdin, "%d\n", difficulty)
	c.Stdin = stdin

	c.Stderr = os.Stdout

	output, err := c.Output()
	if err != nil {
		return err
	}

	var n1, n2 uint64

	_, err = fmt.Sscan(string(output), &n1, &n2)
	if err != nil {
		return err
	}

	h.SetNonce12(n1, n2)

	return nil
}

var contents = "andrewhe,baula,werryju"
var timeout = 60 * time.Second

func main() {
	var next *BlockHeader
	for {
		var err error

		// TODO: Poll maybe?
		next, err = GetNext()
		if err != nil {
			fmt.Println(err)
			continue
		}

		if next.Version != 0 {
			panic("Unknown version!")
		}

		header := *next

		header.SetContents(contents)
		header.SetNonce0(rand.Uint64())
		header.SetTimestamp(time.Now())

		fmt.Printf("Solving block...\n")
		fmt.Printf("%+v\n", header)

		seed1, seed2 := header.Seeds()
		fmt.Printf("Seeds:\n")
		fmt.Printf("%v\n", seed1)
		fmt.Printf("%v\n", seed2)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err = header.SolveNonces(ctx)
		cancel()
		if err != nil {
			fmt.Println(err)
			continue
		}

		fmt.Printf("Sending block...\n")
		block := &Block{Header: header, Contents: contents}
		fmt.Printf("%+v\n", block)

		err = SendBlock(block)
		if err != nil {
			fmt.Println(err)
			continue
		}

		fmt.Printf("Success!\n")
	}
}
