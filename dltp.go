// MIT License
//
// Copyright (c) 2017 Roman Kindruk
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


package main

import (
	"fmt"
	"os"
	"log"
	"bufio"
	"encoding/binary"
	"bytes"
	"strings"
	"strconv"
	"time"
	"flag"
	"path/filepath"
)


const (
	UEH  = 1 << 0
	MSBF = 1 << 1
	WEID = 1 << 2
	WSID = 1 << 3
	WTMS = 1 << 4
)

const (
	VERB = 1 << 0
)

const (
	BOOL = 1 << 4
	SINT = 1 << 5
	UINT = 1 << 6
	STRG = 1 << 9
	VARI = 1 << 11
	FIXP = 1 << 12
	SCOD = 1 << 15
)


type stringList []string

func (s *stringList) String() string {
    return fmt.Sprint(*s)
}

func (s *stringList) Set(value string) error {
    *s = strings.Split(value, ",")
    return nil
}


type StorageHeader struct {
	timestamp time.Time
}

type StandardHeader struct {
	htyp byte
	msbf bool
	weid bool
	wsid bool
	wtms bool
	ueh  bool

	mcnt byte
	len  uint16
	tmsp float32

	size int
}

type ExtendedHeader struct {
	msin byte
	verb bool
	mstp int
	mtin int
	noar int
	apid string
	ctid string
}

type Payload struct {
	args []interface{}
}

type Message struct {
	st StorageHeader
	sh StandardHeader
	eh ExtendedHeader
	pl Payload

	verbose bool
}


func (h *StorageHeader) Parse(data []byte) {
	sec := int64(binary.LittleEndian.Uint32(data[4:8]))
	mic := int64(binary.LittleEndian.Uint32(data[8:12]))
	h.timestamp = time.Unix(sec, mic*1000)
}


func (h *StandardHeader) Parse(data []byte) {
	h.htyp = data[0]
	h.msbf = h.htyp & MSBF != 0
	h.weid = h.htyp & WEID != 0
	h.wsid = h.htyp & WSID != 0
	h.wtms = h.htyp & WTMS != 0	
	h.ueh  = h.htyp & UEH != 0

	h.mcnt = data[1]
	h.len  = binary.BigEndian.Uint16(data[2:4])

	h.size = 4
	if h.weid {
		h.size += 4
	}
	if h.wsid {
		h.size += 4
	}
	if h.wtms {
		h.tmsp = 1E-4 * float32(binary.BigEndian.Uint32(data[h.size:h.size+4]))
		h.size += 4
	}
}


func (h *ExtendedHeader) Parse(data []byte) {
	h.msin = data[0]
	h.verb = h.msin & VERB != 0
	h.mstp = int(h.msin >> 1) & 0x03
	h.mtin = int(h.msin >> 4) & 0x0F

	h.noar = int(data[1])

	h.apid = string(bytes.TrimRight(data[2:6], "\x00"))
	h.ctid = string(bytes.TrimRight(data[6:10], "\x00"))
}


func parseBool(tinfo uint32, data []byte) (v interface{}, rest []byte) {
	val := true
	if data[0] == 0 {
		val = false
	}
	return val, data[1:]
}


func parseSint(tinfo uint32, data []byte) (v interface{}, rest []byte) {
	length := 1 << (tinfo & 0x0F - 1)
	return int32(0), data[length:]
}


func parseUint(tinfo uint32, data []byte) (v interface{}, rest []byte) {
	length := 1 << (tinfo & 0x0F - 1)
	return uint32(0), data[length:]
}


func parseString(tinfo uint32, data []byte) (v interface{}, rest []byte) {
	length := binary.LittleEndian.Uint16(data[:2])
	s := strconv.QuoteToGraphic(string(bytes.TrimRight(data[2:2+length], "\x00")))
	return s[1:len(s)-1], data[2+length:] // return without quotes
}


func parseArg(data []byte) (arg interface{}, rest []byte) {
	pf := map[uint32] func (ti uint32, data []byte) (interface{}, []byte) {
		BOOL : parseBool,
		SINT : parseSint,
		UINT : parseUint,
		STRG : parseString,
	}

	typeInfo := binary.LittleEndian.Uint32(data[:4])
	if typeInfo & VARI == VARI {
		log.Fatal("parseArg: VARI parsing isn't implemented")
	}
	if typeInfo & FIXP == FIXP {
		log.Fatal("parseArg: FIXP parsing isn't implemented")
	}

	key := typeInfo & (BOOL | SINT | UINT | STRG)
	if key != 0 {
		return pf[key](typeInfo, data[4:])
	}
	return data, data
}


func (p *Payload) Parse(verbose bool, noar int, data []byte) {
	if !verbose {
		messageID := binary.LittleEndian.Uint32(data[:4])
		p.args = []interface{} {fmt.Sprintf("<%d (%d) %q>", messageID, len(data[4:]), data[4:])}
		return
	}

	p.args = make([]interface{}, noar)
	for i:=0; i<noar; i++ {
		p.args[i], data = parseArg(data)
	}
}


func parse_message(data []byte) Message {
	var msg Message
	msg.st.Parse(data[:16])
	data = data[16:]
	msg.sh.Parse(data)
	payloadOffset := msg.sh.size
	noar := 0
	if msg.sh.ueh {
		msg.eh.Parse(data[msg.sh.size:msg.sh.size+10])
		noar = msg.eh.noar
		payloadOffset += 10
	}
	msg.verbose = msg.sh.ueh && msg.eh.verb
	msg.pl.Parse(msg.verbose, noar, data[payloadOffset:])
	return msg
}


func printMessage(msg Message, index int) {
	fmt.Printf("%d\t%X %X\t%-32s\t%.4f", index, msg.sh.htyp, msg.sh.mcnt, msg.st.timestamp.Format(time.RFC3339Nano), msg.sh.tmsp)
	verb := "n"
	if msg.verbose {
		verb = "v"
	}
	fmt.Printf("\t%s", verb)
	if msg.sh.ueh {
		fmt.Printf("\t%X %X\t%-4s %-4s\t(%d)", msg.eh.mstp, msg.eh.mtin,
			strings.Trim(msg.eh.apid, "\x00"), strings.Trim(msg.eh.ctid, "\x00"), msg.eh.noar)
	}
	for i, v := range(msg.pl.args) {
		if i==0 {
			fmt.Printf("\t")
		} else {
			fmt.Printf(" ")
		}
		fmt.Printf("%v",  v)
	}
	fmt.Printf("\n")
}


func splitMessage(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 16 + 4 {
		return 0, nil, nil
	}

	mlen := binary.BigEndian.Uint16(data[18:20])

	advance = 16 + int(mlen)
	if len(data) < advance {
		return 0, nil, nil
	}

	err = nil
	if atEOF {
		err = bufio.ErrFinalToken
	}
	return advance, data[:advance], err
}


func readMessages(f *os.File) <-chan []byte {
	out := make(chan []byte)
	go func () {
		scn := bufio.NewScanner(f)
		scn.Split(splitMessage)

		for scn.Scan() {
			out <- append([]byte{}, scn.Bytes()...)
		}

		if err := scn.Err(); err != nil {
			log.Fatal(err)
		}
		close(out)
	}()
	return out
}


func parseMessages(buf <-chan []byte) (<-chan Message) {
	out := make(chan Message)
	go func () {
		for m := range buf {
			out <- parse_message(m)
		}
		close(out)
	}()
	return out
}


func match_appid(m Message, apps map[string]bool) bool {
	if m.sh.ueh {
		_, ok := apps[m.eh.apid]
		return ok
	}
	return false
}


func filterMessages(msg <-chan Message, appidList stringList) (<-chan Message) {
	out := make(chan Message)
	apps := make(map[string]bool)
	for _, app := range(appidList) {
		apps[app] = true
	}
	go func () {
		for m := range msg {
			if len(apps)==0 || match_appid(m, apps) {
				out <- m
			}
		}
		close(out)
	}()
	return out
}


func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] FILE [...]\n", filepath.Base(os.Args[0]))
	flag.PrintDefaults()
}


func main() {
	var appidList stringList
	flag.Var(&appidList, "a", "comma-separated list of the APPID to show")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
		os.Exit(-1)
	}

	for _, fn := range flag.Args() {
		f, err := os.Open(fn)
		if err != nil {
			log.Fatalln(err)
		}
		defer f.Close()

		c := readMessages(f)
		m := parseMessages(c)
		fm := filterMessages(m, appidList)
		index := 0
		for msg := range fm {
			printMessage(msg, index)
			index++
		}
	}
}
