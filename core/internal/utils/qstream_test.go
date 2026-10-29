package utils

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func qstreamTestTransport(t *testing.T) *quic.Transport {
	t.Helper()
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = packetConn.Close() })
	transport := &quic.Transport{Conn: packetConn}
	// Register before Listen/Dial, including their failure paths. LIFO cleanup
	// stops the transport before closing its caller-owned UDP socket.
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}

func TestQStreamCloseWrite(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
		NextProtos:   []string{"qstream-test"},
	}
	// Only loopback traffic, on an ephemeral port.
	serverTransport := qstreamTestTransport(t)
	listener, err := serverTransport.Listen(tlsConfig, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientTransport := qstreamTestTransport(t)
	client, err := clientTransport.Dial(ctx, listener.Addr(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         tlsConfig.NextProtos,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })

	for _, firstClose := range []string{"client", "server"} {
		t.Run(firstClose, func(t *testing.T) {
			local, err := client.OpenStreamSync(ctx)
			require.NoError(t, err)
			// Make the stream visible to AcceptStream, whichever end closes first.
			_, err = local.Write([]byte("open"))
			require.NoError(t, err)
			remote, err := server.AcceptStream(ctx)
			require.NoError(t, err)
			require.NoError(t, local.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, remote.SetDeadline(time.Now().Add(5*time.Second)))
			open := make([]byte, len("open"))
			_, err = io.ReadFull(remote, open)
			require.NoError(t, err)
			initiator, responder := &QStream{Stream: local}, &QStream{Stream: remote}
			if firstClose == "server" {
				initiator, responder = responder, initiator
			}
			t.Cleanup(func() {
				_ = initiator.Close()
				_ = responder.Close()
			})
			_, err = initiator.Write([]byte("EOF-terminated request"))
			require.NoError(t, err)
			require.NoError(t, initiator.CloseWrite())
			got, err := io.ReadAll(responder)
			require.NoError(t, err)
			require.Equal(t, "EOF-terminated request", string(got))
			// CloseWrite must not CancelRead: a response is still readable.
			_, err = responder.Write([]byte("response after EOF"))
			require.NoError(t, err)
			require.NoError(t, responder.CloseWrite())
			got, err = io.ReadAll(initiator)
			require.NoError(t, err)
			require.Equal(t, "response after EOF", string(got))
		})
	}

	t.Run("full-close-still-cancels-read", func(t *testing.T) {
		stream, err := client.OpenStreamSync(ctx)
		require.NoError(t, err)
		wrapped := &QStream{Stream: stream}
		require.NoError(t, wrapped.Close())
		_, err = wrapped.Read(make([]byte, 1))
		var streamErr *quic.StreamError
		require.ErrorAs(t, err, &streamErr)
		require.False(t, streamErr.Remote)
		require.Zero(t, streamErr.ErrorCode)
	})
}

func TestQStreamDialFailureCleanup(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	var packetConn net.PacketConn
	t.Run("handshake-timeout", func(t *testing.T) {
		peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = peer.Close() })
		transport := qstreamTestTransport(t)
		packetConn = transport.Conn
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// This timeout deliberately fails the handshake against a silent peer;
		// the functional test's handshake and I/O timeouts are unchanged.
		conn, err := transport.Dial(ctx, peer.LocalAddr(), &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"qstream-test"},
		}, &quic.Config{HandshakeIdleTimeout: 25 * time.Millisecond})
		require.Nil(t, conn)
		var timeout net.Error
		require.ErrorAs(t, err, &timeout)
		require.True(t, timeout.Timeout())
		require.NotErrorIs(t, err, context.DeadlineExceeded)
	})
	require.NotNil(t, packetConn)
	require.ErrorIs(t, packetConn.SetReadDeadline(time.Now()), net.ErrClosed)
}
