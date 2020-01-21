// +build gofuzz

package handshake

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const version = protocol.VersionTLS

func Fuzz(data []byte) int {
	if len(data) < 1 {
		return 0
	}
	var perspective protocol.Perspective
	switch data[0] % 2 {
	case 0:
		perspective = protocol.PerspectiveClient
	case 1:
		perspective = protocol.PerspectiveServer
	}
	data = data[1:]

	params := &handshake.TransportParameters{}
	if err := params.Unmarshal(data, perspective); err != nil {
		return 0
	}
	if params.MaxAckDelay > 365*24*time.Hour {
		return 0
	}
	marshaled := params.Marshal()
	params2 := &handshake.TransportParameters{}
	if err := params2.Unmarshal(marshaled, perspective); err != nil {
		fmt.Printf("%#v\n", params2)
		panic(err)
	}
	// if !reflect.DeepEqual(params, params2) {
	// 	fmt.Printf("%#v vs %#v", params, params2)
	// 	panic("hallo")
	// }
	return 0
}
