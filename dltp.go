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
	"errors"
	"bytes"
)

var (
        ErrBadHeader = errors.New("dlt.Scanner: Bad header")
)

const (
	UEH  = 1 << 0
	WEID = 1 << 2
	WSID = 1 << 3
	WTMS = 1 << 4
)

const (
	VERB = 1 << 0
)

const (
	STRG = 1 << 9
	VARI = 1 << 11
	SCOD = 1 << 15
)


type MessageHeader struct {
	
}

type Message struct {
	standardHeader []byte
	extendedHeader []byte
	payload []byte
}

func (msg *Message) Read(data []byte) {
	htyp := data[0]
	sz := 4
	if htyp & WEID != 0 {
		sz += 4
	}
	if htyp & WSID != 0 {
		sz += 4
	}
	if htyp & WTMS != 0 {
		sz += 4
	}
	msg.standardHeader = data[:sz]
	
	if htyp & UEH != 0 {
		msg.extendedHeader = data[sz:sz+10]
		sz += 10
	}

	msg.payload = data[sz:]
}

func decodePayload(buf []byte, verbose bool, noar int) string {
	if buf != nil {
		if verbose {
			offset := 0
			for i:=0; i<noar; i++ {
				typeInfo := binary.LittleEndian.Uint32(buf[offset:offset+4])
				if typeInfo & STRG == STRG {
					if typeInfo & VARI == VARI {
						fmt.Println("*****   VARI   *****\n")
					}
					length := int(binary.LittleEndian.Uint16(buf[offset+4:offset+6]))
					return fmt.Sprintf("\t%#x\t%s", typeInfo, string(buf[offset+6:offset+6+length]))
					offset += 6+length
				} else {
					return fmt.Sprintf("\t%#x\t%d", typeInfo, len(buf))
				}
			}
		} else {
			messageID := binary.LittleEndian.Uint32(buf[:4])
			return fmt.Sprintf("\t<%d (%d) %q>", messageID, len(buf[4:]), buf[4:])
		}
	}
	return ""
}


func printMessage(msg Message, index int) {
	htyp := msg.standardHeader[0]
	mcnt := msg.standardHeader[1]

	fmt.Printf("%d\t%X %X", index, htyp, mcnt)

	verbose := false
	noar := 0
	if msg.extendedHeader != nil {
		msin := msg.extendedHeader[0]
		noar = int(msg.extendedHeader[1])
		apid := string(msg.extendedHeader[2:6])
		ctid := string(msg.extendedHeader[6:10])
		if msin & VERB == VERB {
			verbose = true
		}
		mstp := (msin >> 1) & 0x03
		msli := (msin >> 4) & 0x0F
		fmt.Printf("\t%t\t%X %X\t%s %s\t(%d)", verbose, mstp, msli, string(apid), string(ctid), noar)
	}

	fmt.Printf("\t%s\n", decodePayload(msg.payload, verbose, noar));
}


func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if len(data) < 16 + 4 {
			log.Fatal(ErrBadHeader)
		}

		var mlen uint16
		buf := bytes.NewReader(data[18:20])
		err = binary.Read(buf, binary.BigEndian, &mlen)
		if err != nil {
			log.Fatal(err)
		}

		advance = 16 + int(mlen)
		token = data[:advance]
		err = nil
		if len(data) <= advance {
			if atEOF {
				err = bufio.ErrFinalToken
			} else {
				return 0, nil, nil
			}
		}
		return
	}

	scn := bufio.NewScanner(f)
	scn.Split(split)
	index := 0
	for scn.Scan() {
		var msg Message
		msg.Read(scn.Bytes()[16:]) // skip storage prefix
		printMessage(msg, index)
		index++
	}

	if err = scn.Err(); err != nil {
		log.Fatal(err)
	}
}
