package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"my-bpf/config"
	"my-bpf/k8s"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type DNS_Msg_Handler struct {
	name string
	m    *ebpf.Map
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

// func (dq *DNSQuery) MarshalBinary() ([]byte, error) {
// 	data := new(bytes.Buffer)
// 	err := binary.Write(data, binary.LittleEndian, dq)
// 	log.Printf("do marshal binary")
// 	return data.Bytes(), err
// }

func init() {
	h := &DNS_Msg_Handler{}
	h.name = "mh_tc_dns"
	RegisterMsgHandler(h)
}

func (h *DNS_Msg_Handler) Name() string {
	return h.name
}

func (h *DNS_Msg_Handler) SetupMsgFilter(c *config.Configuration) {
}

func (h *DNS_Msg_Handler) SetupKernelMap(m *ebpf.Map, w *k8s.Watcher) error {
	h.m = m
	go func(sd chan k8s.NetAddress, sr chan k8s.NetAddress) {
		for {
			select {
			case na := <-sd:
				h.UpdateDNSMap(na, false)
			case na := <-sr:
				h.UpdateDNSMap(na, true)
			}
		}
	}(w.ServiceAdd, w.ServiceRemove)
	return nil
}

func (h *DNS_Msg_Handler) UpdateDNSMap(addr k8s.NetAddress, isDelete bool) {
	qk := getKey(addr.Host)
	if isDelete {
		log.Printf("remove DNS[%s]", addr.Host)
		err := h.m.Delete(qk)
		if err != nil {
			log.Printf("Remove DNS[%s] map failed, error: %v", addr.Host, err)
		}
	} else {
		ip := net.ParseIP(addr.IP)
		if ip == nil {
			log.Printf("Parse DNS[%s] IP[%s] failed", addr.Host, addr.IP)
			return
		}
		record := DNSRecord{
			IP:  binary.LittleEndian.Uint32(ip.To4()),
			TTL: 30,
		}
		log.Printf("Add DNS[%s] IP[%s]", addr.Host, addr.IP)
		err := h.m.Put(unsafe.Pointer(&qk), unsafe.Pointer(&record))
		if err != nil {
			log.Printf("Add DNS[%s] map failed, error: %v", addr.Host, err)
		}
	}
}

func getKey(host string) DNSQuery {
	queryKey := DNSQuery{
		RecordType: 1,
		Class:      1,
	}
	nameSlice := make([]byte, 256)
	copy(nameSlice, []byte(host))
	dnsName := replace_dots_with_length_octets(nameSlice)
	copy(queryKey.Name[:], dnsName)
	return queryKey
}

func (h *DNS_Msg_Handler) Decode(b []byte, w *k8s.Watcher) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Net_DNS_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	// jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	// if err != nil {
	// 	log.Printf("log mesaage failed: %s", err.Error())
	// }

	// return jsonMsg, nil
	strMsg := fmt.Sprintf("[DNS] [%s] (Type: %d, Match: %d, Spend: %d)",
		unix.ByteSliceToString(replace_length_octets_with_dots(event.Name[:])),
		event.RecordType, event.IsMatch, event.TS)

	return []byte(strMsg), nil
}
