package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
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
		return nil, fmt.Errorf("Bad response: %v; Body: %v", resp.Status, strings.TrimSpace(string(body)))
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

	fmt.Println("POST", "/add", strings.TrimSpace(string(buf.Bytes())))

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
		return fmt.Errorf("Bad response: %v; Body: %v", resp.Status, strings.TrimSpace(string(body)))
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

func (h *BlockHeader) Id() HexHash {
	buf := &bytes.Buffer{}
	buf.Write(h.ParentId[:])
	buf.Write(h.Root[:])
	binary.Write(buf, binary.BigEndian, h.Difficulty)
	binary.Write(buf, binary.BigEndian, h.Timestamp)
	binary.Write(buf, binary.BigEndian, h.Nonces[0])
	binary.Write(buf, binary.BigEndian, h.Nonces[1])
	binary.Write(buf, binary.BigEndian, h.Nonces[2])
	binary.Write(buf, binary.BigEndian, h.Version)

	data := buf.Bytes()
	if len(data) != 105 {
		panic("Invalid buffer length")
	}

	return NewHexHash(data)
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

func (h *BlockHeader) Verify() error {
	seed1, seed2 := h.Seeds()
	A, err := aes.NewCipher(seed1[:])
	if err != nil {
		return err
	}
	B, err := aes.NewCipher(seed2[:])
	if err != nil {
		return err
	}

	ibuf := &bytes.Buffer{}
	binary.Write(ibuf, binary.BigEndian, uint64(0))
	binary.Write(ibuf, binary.BigEndian, h.Nonces[1])
	jbuf := &bytes.Buffer{}
	binary.Write(jbuf, binary.BigEndian, uint64(0))
	binary.Write(jbuf, binary.BigEndian, h.Nonces[2])

	i := ibuf.Bytes()
	j := jbuf.Bytes()

	encryptToInt := func(cipher cipher.Block, block []byte) *big.Int {
		ciph := make([]byte, len(block))
		cipher.Encrypt(ciph, block)
		return (&big.Int{}).SetBytes(ciph)
	}

	Ai := encryptToInt(A, i)
	Aj := encryptToInt(A, j)
	Bi := encryptToInt(B, i)
	Bj := encryptToInt(B, j)

	Ai.Add(Ai, Bj)
	Aj.Add(Aj, Bi)

	dist := uint64(0)
	for p := 0; p < 128; p++ {
		if Ai.Bit(p) != Aj.Bit(p) {
			dist++
		}
	}

	if !(dist <= 128-h.Difficulty) {
		return fmt.Errorf("Distance was too large: %v > %v", dist, 128-h.Difficulty)
	}

	return nil
}

func (h *BlockHeader) RunSolver(ctx context.Context) error {
	seed1, seed2 := h.Seeds()
	difficulty := h.Difficulty
	args := []string{
		fmt.Sprintf("%x", seed1[:]),
		fmt.Sprintf("%x", seed2[:]),
		fmt.Sprintf("%d", difficulty),
	}
	c := exec.CommandContext(ctx, "./aesham2", args...)

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
var timeout = 90 * time.Second
var pollTime = 30 * time.Second
var numProcs = 1

func TryMine(ctx context.Context, template *BlockHeader) (*BlockHeader, error) {
	var err error

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if template.Version != 0 {
		panic("Unknown version!")
	}

	// Spin up numProcs different processes trying different headers
	ch := make(chan *BlockHeader)
	waitGroup := sync.WaitGroup{}
	for proc := 0; proc < numProcs; proc++ {
		header := *template

		header.SetContents(contents)
		header.SetNonce0(rand.Uint64())
		header.SetTimestamp(time.Now())

		fmt.Printf("Solving block...\n")
		fmt.Printf("%+v\n", header)

		seed1, seed2 := header.Seeds()
		fmt.Printf("Seeds:\n")
		fmt.Printf("%v\n", seed1)
		fmt.Printf("%v\n", seed2)

		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			err := header.RunSolver(ctx)
			if err != nil {
				fmt.Println("Solve failed:", err)
				return
			}

			select {
			case <-ctx.Done():
			case ch <- &header:
			}
		}()
	}

	allDone := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(allDone)
	}()

	var header *BlockHeader
	select {
	case <-allDone:
		fmt.Println("All processes failed")
		return nil, fmt.Errorf("Try again")
	case <-ctx.Done():
		fmt.Println("Timed out, starting over")
		return nil, fmt.Errorf("Try again")
	case header = <-ch:
	}

	fmt.Println("Solved block:")
	fmt.Printf("%+v\n", header)

	err = header.Verify()
	if err != nil {
		fmt.Println("Verification failed:", err)
		fmt.Println("Sending anyways")
	} else {
		fmt.Println("Verification passed")
	}

	fmt.Printf("Sending block...\n")
	block := &Block{Header: *header, Contents: contents}
	fmt.Printf("%+v\n", block)

	err = SendBlock(block)
	if err != nil {
		fmt.Println("SendBlock failed:", err)
		return nil, fmt.Errorf("SendBlock failed: %v", err)
	}

	fmt.Println("Success!")
	fmt.Println("New block ID:", header.Id())

	// Linux notification
	notification := exec.Command(
		"notify-send",
		"--urgency=low",
		"--app-name=gminer",
		fmt.Sprintf("Mined a block w/ d = %d", header.Difficulty),
	)
	go notification.Run()

	return header, nil
}

func TryMineNext() (*BlockHeader, error) {
	var next *BlockHeader
	var err error

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	next, err = GetNext()
	if err != nil {
		fmt.Println("GetNext failed:", err)
		return nil, err
	}

	// Poll for new versions of next as we're running
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollTime):
			}
			newNext, err := GetNext()
			if err != nil {
				continue
			}
			if *newNext != *next {
				fmt.Println("Found newer head", newNext)
				cancel()
				return
			}
		}
	}()

	return TryMine(ctx, next)
}

func MustDecodeHex(s string) *HexHash {
	res := &HexHash{}
	if err := res.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return res
}

func MineNext(maxBlocks int) {
	for maxBlocks != 0 {
		_, err := TryMineNext()
		if err != nil {
			continue
		}
		maxBlocks--
	}
}

func MineOn(start HexHash, difficulty uint64, maxBlocks int) {
	template := &BlockHeader{
		ParentId:   start,
		Difficulty: difficulty,
	}
	for maxBlocks != 0 {
		next, err := TryMine(context.Background(), template)
		if err != nil {
			if strings.Contains(err.Error(), "invalid difficulty") {
				template.Difficulty += 2
			}
			continue
		}
		template = &BlockHeader{
			ParentId:   next.Id(),
			Difficulty: template.Difficulty,
		}
		maxBlocks--
	}
}

func main() {
	base := flag.String("base", "", "Previous block ID to build a chain on")
	difficulty := flag.Uint64("difficulty", 86, "Difficulty to mine at")
	maxBlocks := flag.Int("maxBlocks", -1, "Maximum nubmer of blocks to mine (< 0 for infinity)")
	flag.Parse()

	if *base != "" {
		MineOn(
			*MustDecodeHex(*base),
			*difficulty,
			*maxBlocks,
		)
	} else {
		MineNext(*maxBlocks)
	}
}
