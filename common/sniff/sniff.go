package sniff

import (
	"bytes"
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type (
	StreamSniffer = func(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error
	PacketSniffer = func(ctx context.Context, metadata *adapter.InboundContext, packet []byte) error
)

// Sniffers run sequentially and share a single reader over one immutable
// snapshot of the buffered payload. Do not run them concurrently: a
// successful sniffer returns immediately and cancels the context while the
// other goroutines may still be reading, which previously led to rare
// nil-pointer panics inside the sniffers (e.g. sniff.BitTorrent).
func PeekStream(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn, buffer *buf.Buffer, timeout time.Duration, sniffers ...StreamSniffer) error {
	if timeout == 0 {
		timeout = C.ReadPayloadTimeout
	}
	deadline := time.Now().Add(timeout)
	var errors []error

	for i := 0; i < 3; i++ {
		err := conn.SetReadDeadline(deadline)
		if err != nil {
			return E.Cause(err, "set read deadline")
		}
		_, err = buffer.ReadOnceFrom(conn)
		err = E.Errors(err, conn.SetReadDeadline(time.Time{}))
		if err != nil {
			if i > 0 {
				break
			}
			return E.Cause(err, "read payload")
		}
		payload := buffer.Bytes()
		for _, sniffer := range sniffers {
			err = sniffer(ctx, metadata, bytes.NewReader(payload))
			if err == nil {
				return nil
			}
			errors = append(errors, err)
		}
	}
	return E.Errors(errors...)
}

func PeekPacket(ctx context.Context, metadata *adapter.InboundContext, packet []byte, sniffers ...PacketSniffer) error {
	var errors []error
	for _, sniffer := range sniffers {
		err := sniffer(ctx, metadata, packet)
		if err == nil {
			return nil
		}
		errors = append(errors, err)
	}
	return E.Errors(errors...)
}
