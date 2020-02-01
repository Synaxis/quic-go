package handshake

import (
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	"github.com/marten-seemann/qtls"

	"github.com/lucas-clemente/quic-go/internal/congestion"
)

const clientSessionStateRevision = 1

type nonceField struct {
	Nonce   []byte
	AppData []byte
	RTT     int64 // in ns
}

type clientSessionCache struct {
	tls.ClientSessionCache
	rttStats *congestion.RTTStats

	getAppData func() []byte
	setAppData func([]byte)
}

func newClientSessionCache(
	cache tls.ClientSessionCache,
	rttStats *congestion.RTTStats,
	get func() []byte,
	set func([]byte),
) *clientSessionCache {
	return &clientSessionCache{
		ClientSessionCache: cache,
		rttStats:           rttStats,
		getAppData:         get,
		setAppData:         set,
	}
}

var _ qtls.ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Get(sessionKey string) (*qtls.ClientSessionState, bool) {
	sess, ok := c.ClientSessionCache.Get(sessionKey)
	if sess == nil {
		return nil, ok
	}
	// qtls.ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	tlsSessBytes := (*[unsafe.Sizeof(*sess)]byte)(unsafe.Pointer(sess))[:]
	var session clientSessionState
	sessBytes := (*[unsafe.Sizeof(session)]byte)(unsafe.Pointer(&session))[:]
	copy(sessBytes, tlsSessBytes)
	if len(session.nonce) < 4 {
		fmt.Println(1)
		return nil, false
	}
	if binary.BigEndian.Uint32(session.nonce[:4]) != clientSessionStateRevision {
		fmt.Println(2)
		return nil, false
	}
	var nf nonceField
	if rest, err := asn1.Unmarshal(session.nonce[4:], &nf); err != nil || len(rest) != 0 {
		fmt.Println(3)
		return nil, false
	}
	c.setAppData(nf.AppData)
	session.nonce = nf.Nonce
	c.rttStats.SetInitialRTT(time.Duration(nf.RTT) * time.Nanosecond)
	var qtlsSession qtls.ClientSessionState
	qtlsSessBytes := (*[unsafe.Sizeof(qtlsSession)]byte)(unsafe.Pointer(&qtlsSession))[:]
	copy(qtlsSessBytes, sessBytes)
	return &qtlsSession, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *qtls.ClientSessionState) {
	if cs == nil {
		c.ClientSessionCache.Put(sessionKey, nil)
		return
	}
	// qtls.ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	qtlsSessBytes := (*[unsafe.Sizeof(*cs)]byte)(unsafe.Pointer(cs))[:]
	var session clientSessionState
	sessBytes := (*[unsafe.Sizeof(session)]byte)(unsafe.Pointer(&session))[:]
	copy(sessBytes, qtlsSessBytes)
	data, err := asn1.Marshal(nonceField{
		Nonce:   session.nonce,
		AppData: c.getAppData(),
		RTT:     c.rttStats.SmoothedRTT().Nanoseconds(),
	})
	nonce := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(nonce[:4], clientSessionStateRevision)
	copy(nonce[4:], data)
	if err != nil { // marshaling
		panic(err)
	}
	session.nonce = nonce
	var tlsSession tls.ClientSessionState
	tlsSessBytes := (*[unsafe.Sizeof(tlsSession)]byte)(unsafe.Pointer(&tlsSession))[:]
	copy(tlsSessBytes, sessBytes)
	c.ClientSessionCache.Put(sessionKey, &tlsSession)
}
