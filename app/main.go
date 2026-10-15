package main

import (
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

type Message struct {
	header Header
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

		header := Header{id: 1234, qr: 1}
		response := header.Serialize()

		_, err = udpConn.WriteToUDP(response[:], source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
