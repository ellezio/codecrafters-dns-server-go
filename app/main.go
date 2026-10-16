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
	// name := encodeLabelSequence(q.name)
	out := make([]byte, len(q.name)+4)
	n := copy(out, q.name)
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
	// name := encodeLabelSequence(a.name)

	out := make([]byte, 0, len(a.name)+10+int(uint(a.length)))
	buf := bytes.NewBuffer(out)
	buf.Write(a.name)
	_ = binary.Write(buf, binary.BigEndian, a.typ)
	_ = binary.Write(buf, binary.BigEndian, a.class)
	_ = binary.Write(buf, binary.BigEndian, a.ttl)
	_ = binary.Write(buf, binary.BigEndian, a.length)
	_ = binary.Write(buf, binary.BigEndian, a.data)

	return buf.Bytes()
}

type Message struct {
	header    Header
	questions []Question
	answers   []Answer
}

func (m *Message) Serialize() []byte {
	var buf [512]byte
	h := m.header.Serialize()

	out := buf[0:0:512]
	out = append(out, h[:]...)

	for _, question := range m.questions {
		q := question.Serialize()
		out = append(out, q...)
	}

	for _, answer := range m.answers {
		a := answer.Serialize()
		out = append(out, a...)
	}

	return out
}

func (m *Message) AddAnswer() {
	m.header.ancount = m.header.qdcount
	m.answers = make([]Answer, 0, m.header.ancount)
	for _, q := range m.questions {
		a := Answer{
			name:   q.name,
			typ:    1,
			class:  1,
			ttl:    60,
			length: 4,
			data:   []byte{8, 8, 8, 8},
		}
		m.answers = append(m.answers, a)
	}
}

func parseHeader(v []byte) Header {
	h := Header{qr: 1}

	h.id = binary.BigEndian.Uint16(v[0:2])
	h.opcode = (v[2] >> 3) & 0x0F
	h.rd = v[2] & 0x01

	if h.opcode != 0 {
		h.rcode = 4
	}

	h.qdcount = binary.BigEndian.Uint16(v[4:6])

	return h
}

func parseQuestion(v []byte, off int) (Question, int) {
	q := Question{}

	name := decodeLabelSequence(v, off)
	l := len(name)
	off += l
	q.name = name

	q.typ = binary.BigEndian.Uint16(v[off : off+2])
	q.class = binary.BigEndian.Uint16(v[off+2 : off+4])

	return q, l + 4
}

func parseMessage(v []byte) *Message {
	header := parseHeader(v[:HeaderSectionBytes])
	questions := make([]Question, 0, header.qdcount)

	off := HeaderSectionBytes
	for i := uint16(0); i < header.qdcount; i++ {
		question, n := parseQuestion(v, off)
		off += n
		questions = append(questions, question)
	}

	return &Message{
		header:    header,
		questions: questions,
	}
}

func decodeLabelSequence(v []byte, off int) []byte {
	labelSeq := make([]byte, 0)

	for off < len(v) && v[off] != 0 {
		size := uint8(v[off])
		// It's a pointer label
		if size&0xC0 == 0xC0 {
			off = int(uint(size))
			continue
		}
		size += 1
		labelSeq = append(labelSeq, v[off:off+int(size)]...)
		off += int(size)
	}

	labelSeq = append(labelSeq, 0)
	return labelSeq
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

		message := parseMessage(buf)
		message.AddAnswer()
		response := message.Serialize()

		_, err = udpConn.WriteToUDP(response[:], source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
