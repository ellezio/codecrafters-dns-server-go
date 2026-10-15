package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	HeaderSectionBytes = 12
)

type Header struct {
	// Packet Identifier - A random ID assigned to query packets. Response packets must reply with the same ID.
	id uint16

	// Query/Response Indicato - 1 for a reply packet, 0 for a question packet.
	qr uint8

	// Operation Code - Specifies the kind of query in a message.
	opcode uint8

	// Authoritative Answer - 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
	aa uint8

	// Truncation - 1 if the message is larger than 512 bytes.
	tc uint8

	// Recursion Desired - Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
	rd uint8

	// Recursion Available - Server sets this to 1 to indicate that recursion is available.
	ra uint8

	// Reserved - Used by DNSSEC queries. At inception, it was reserved for future use.
	z uint8

	// Response Code - Response code indicating the status of the response.
	rcode uint8

	// Question Count - Number of questions in the Question section.
	qdcount uint16

	// Answer Record Count - Number of records in the Answer section.
	ancount uint16

	// Authority Record Count - Number of records in the Authority section.
	nscount uint16

	// Additional Record Count - Number of records in the Additional section.
	arcount uint16
}

func (h *Header) Serialize() [HeaderSectionBytes]byte {
	var out [HeaderSectionBytes]byte

	binary.BigEndian.PutUint16(out[0:2], h.id)
	binary.BigEndian.PutUint16(out[4:6], h.qdcount)
	binary.BigEndian.PutUint16(out[6:8], h.ancount)
	binary.BigEndian.PutUint16(out[8:10], h.nscount)
	binary.BigEndian.PutUint16(out[10:12], h.arcount)

	var field uint16
	field |= uint16(h.qr) << 15
	field |= uint16(h.opcode) << 11
	field |= uint16(h.aa) << 10
	field |= uint16(h.tc) << 9
	field |= uint16(h.rd) << 8
	field |= uint16(h.ra) << 7
	field |= uint16(h.z) << 4
	field |= uint16(h.rcode)
	binary.BigEndian.PutUint16(out[2:4], field)

	return out
}

type Question struct {
	name  []byte
	typ   uint16
	class uint16
}

func (q *Question) Serialize() []byte {
	name := encodeLabelSequence(q.name)
	out := make([]byte, len(name)+4)
	n := copy(out, name)
	binary.BigEndian.PutUint16(out[n:n+2], q.typ)
	binary.BigEndian.PutUint16(out[n+2:n+4], q.class)
	return out
}

type Answer struct {
	name   []byte
	typ    uint16
	class  uint16
	ttl    uint32
	length uint16
	data   []byte
}

func (a *Answer) Serialize() []byte {
	name := encodeLabelSequence(a.name)

	out := make([]byte, 0, len(name)+10+int(uint(a.length)))
	buf := bytes.NewBuffer(out)
	buf.Write(name)
	_ = binary.Write(buf, binary.BigEndian, a.typ)
	_ = binary.Write(buf, binary.BigEndian, a.class)
	_ = binary.Write(buf, binary.BigEndian, a.ttl)
	_ = binary.Write(buf, binary.BigEndian, a.length)
	_ = binary.Write(buf, binary.BigEndian, a.data)

	return buf.Bytes()
}

type Message struct {
	header   Header
	question Question
	answer   Answer
}

func (m *Message) Serialize() []byte {
	h := m.header.Serialize()
	q := m.question.Serialize()
	a := m.answer.Serialize()

	out := make([]byte, len(h)+len(q)+len(a))
	n := copy(out, h[:])
	n += copy(out[n:], q)
	copy(out[n:], a)

	return out
}

func encodeLabelSequence(v []byte) []byte {
	labelSeq := make([]byte, len(v)+2)
	off := 0

	for {
		idx := bytes.IndexByte(v, '.')
		if idx == -1 {
			labelSeq[off] = byte(len(v))
			copy(labelSeq[off+1:], v)
			break
		}

		labelSeq[off] = byte(idx)
		off++
		off += copy(labelSeq[off:off+idx], v)

		if idx+1 > len(v) {
			break
		}

		v = v[idx+1:]
	}

	labelSeq[len(labelSeq)-1] = 0
	return labelSeq
}

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		message := Message{
			header: Header{
				id:      1234,
				qr:      1,
				qdcount: 1,
				ancount: 1,
			},

			question: Question{
				name:  []byte("codecrafters.io"),
				typ:   1,
				class: 1,
			},

			answer: Answer{
				name:   []byte("codecrafters.io"),
				typ:    1,
				class:  1,
				ttl:    60,
				length: 4,
				data:   []byte{8, 8, 8, 8},
			},
		}

		response := message.Serialize()

		_, err = udpConn.WriteToUDP(response[:], source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
