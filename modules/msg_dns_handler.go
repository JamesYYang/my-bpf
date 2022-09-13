package modules

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
)

type DNS_Msg_Handler struct {
	name string
}

type DNSQuery struct {
	RecordType uint16
	Class      uint16
	Name       [256]byte
}

type DNSRecord struct {
	IP  uint32
	TTL uint32
}

func (dq *DNSQuery) MarshalBinary() ([]byte, error) {
	data := new(bytes.Buffer)
	err := binary.Write(data, binary.LittleEndian, dq)
	log.Printf("do marshal binary")
	return data.Bytes(), err
}

func init() {
	h := &DNS_Msg_Handler{}
	h.name = "tc_dns_events"
	RegisterMsgHandler(h)
}

func (h *DNS_Msg_Handler) Name() string {
	return h.name
}

func (h *DNS_Msg_Handler) SetupKernelMap(m *ebpf.Map) error {
	// get service from k8s informer
	baiduQuery := DNSQuery{
		RecordType: 1,
		Class:      1,
	}
	nameSlice := make([]byte, 256)
	copy(nameSlice, []byte("www.baidu.com"))
	dnsName := replace_dots_with_length_octets(nameSlice)
	copy(baiduQuery.Name[:], dnsName)
	baiduRecord := DNSRecord{
		IP:  binary.LittleEndian.Uint32(net.ParseIP("10.16.75.24").To4()),
		TTL: 30,
	}
	log.Printf("will update dns record: %s", baiduQuery.Name[:])
	err := m.Put(unsafe.Pointer(&baiduQuery), unsafe.Pointer(&baiduRecord))
	return err
}

func (h *DNS_Msg_Handler) Decode(b []byte) ([]byte, error) {
	panic("DNS probe not have event")
}
