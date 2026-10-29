package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
)

func halfCloseQUICTransport(t *testing.T) *quic.Transport {
	t.Helper()
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = packetConn.Close() })
	transport := &quic.Transport{Conn: packetConn}
	// Register before Listen/Dial: even a failed handshake must release the
	// transport goroutines, then its caller-owned socket (cleanup is LIFO).
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}

func halfCloseQUICPair(t *testing.T) (context.Context, *quic.Conn, *quic.Conn) {
	t.Helper()
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
		NextProtos:   []string{"half-close-test"},
	}
	// All sockets are loopback and ephemeral. Idle timeout must not rescue a
	// stranded copy before the test's shorter explicit completion assertion.
	config := &quic.Config{MaxIdleTimeout: time.Minute}
	serverTransport := halfCloseQUICTransport(t)
	listener, err := serverTransport.Listen(tlsConfig, config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	clientTransport := halfCloseQUICTransport(t)
	client, err := clientTransport.Dial(ctx, listener.Addr(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         tlsConfig.NextProtos,
	}, config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })
	return ctx, client, server
}

func TestHalfCloseQUICDialFailureCleanup(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	var packetConn net.PacketConn
	t.Run("handshake-timeout", func(t *testing.T) {
		// An open but silent UDP peer makes the handshake fail, not succeed on
		// retry. Only this deliberate failure uses a shorter handshake timeout.
		peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = peer.Close() })
		transport := halfCloseQUICTransport(t)
		packetConn = transport.Conn
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := transport.Dial(ctx, peer.LocalAddr(), &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"half-close-test"},
		}, &quic.Config{HandshakeIdleTimeout: 25 * time.Millisecond})
		require.Nil(t, conn)
		var timeout net.Error
		require.ErrorAs(t, err, &timeout)
		require.True(t, timeout.Timeout())
		require.NotErrorIs(t, err, context.DeadlineExceeded)
	})
	// Child cleanup has run even though no *quic.Conn was returned.
	require.NotNil(t, packetConn)
	require.ErrorIs(t, packetConn.SetReadDeadline(time.Now()), net.ErrClosed)
}

// Embed net.Conn rather than *net.TCPConn to keep io.Copy from bypassing the
// observed Read/Write methods via TCPConn's optimized copy methods.
type halfCloseObservedConn struct {
	net.Conn
	readStarted, readDone, closed, writeStarted  chan struct{}
	readOnce, readDoneOnce, closeOnce, writeOnce sync.Once
	blockWrites                                  bool
}

func (c *halfCloseObservedConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	defer c.readDoneOnce.Do(func() { close(c.readDone) })
	return c.Conn.Read(p)
}

func (c *halfCloseObservedConn) Write(p []byte) (int, error) {
	if c.blockWrites {
		c.writeOnce.Do(func() { close(c.writeStarted) })
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *halfCloseObservedConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

func (c *halfCloseObservedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

type halfCloseOutbound struct {
	Outbound // Only TCP is used by these handler tests.
	conn     net.Conn
}

func (o *halfCloseOutbound) TCP(string) (net.Conn, error) { return o.conn, nil }

type halfCloseHandlerTest struct {
	client, server             *quic.Conn
	clientStream, serverStream *quic.Stream
	backend                    *net.TCPConn
	outbound                   *halfCloseObservedConn
	done                       <-chan struct{}
}

func newHalfCloseHandlerTest(t *testing.T, logged, blockWrites bool) *halfCloseHandlerTest {
	t.Helper()
	ctx, client, server := halfCloseQUICPair(t)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	upstream, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() })
	backend, err := listener.AcceptTCP()
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	require.NoError(t, backend.SetReadDeadline(time.Now().Add(10*time.Second)))
	outbound := &halfCloseObservedConn{
		Conn: upstream, blockWrites: blockWrites,
		readStarted: make(chan struct{}), readDone: make(chan struct{}),
		closed: make(chan struct{}), writeStarted: make(chan struct{}),
	}
	clientStream, err := client.OpenStreamSync(ctx)
	require.NoError(t, err)
	require.NoError(t, clientStream.SetDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, protocol.WriteTCPRequest(clientStream, "backend.test:80"))
	serverStream, err := server.AcceptStream(ctx)
	require.NoError(t, err)
	// Match ProxyStreamHijacker, which consumes the frame type before dispatch.
	frameType, err := quicvarint.Read(quicvarint.NewReader(serverStream))
	require.NoError(t, err)
	require.EqualValues(t, protocol.FrameTypeTCPRequest, frameType)
	config := &Config{Outbound: &halfCloseOutbound{conn: outbound}}
	if logged {
		config.TrafficLogger = &copyTrafficLogger{}
	}
	handler := &h3sHandler{config: config, conn: server, authID: "test-user"}
	done := make(chan struct{})
	stream := &utils.QStream{Stream: serverStream}
	go func() {
		defer close(done)
		handler.handleTCPRequest(stream)
	}()
	t.Cleanup(func() {
		_ = outbound.Close()
		_ = stream.Close()
		waitHalfCloseSignal(t, done)
	})
	ok, _, err := protocol.ReadTCPResponse(clientStream)
	require.NoError(t, err)
	require.True(t, ok)
	return &halfCloseHandlerTest{client, server, clientStream, serverStream, backend, outbound, done}
}

func waitHalfCloseSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TCP handler/copy did not unblock")
	}
}

func TestHandleTCPRequestCancelAfterFIN(t *testing.T) {
	forEachCopyPath(t, func(t *testing.T, path *copyTestPath) {
		for _, cancel := range []string{"stop-sending", "connection-close"} {
			t.Run(cancel, func(t *testing.T) {
				h := newHalfCloseHandlerTest(t, path.logged, false)
				request := []byte("upload ends with FIN")
				_, err := h.clientStream.Write(request)
				require.NoError(t, err)
				require.NoError(t, h.clientStream.Close())
				got, err := io.ReadAll(h.backend)
				require.NoError(t, err)
				require.Equal(t, request, got)
				waitHalfCloseSignal(t, h.outbound.readStarted)
				// The upload has reached EOF, but the backend sends nothing and
				// stays open. There will be no QUIC Write to detect cancellation.
				require.Nil(t, context.Cause(h.serverStream.Context()))
				if cancel == "stop-sending" {
					h.clientStream.CancelRead(0)
					waitHalfCloseSignal(t, h.serverStream.Context().Done())
					var streamErr *quic.StreamError
					require.ErrorAs(t, context.Cause(h.serverStream.Context()), &streamErr)
					require.True(t, streamErr.Remote)
					require.Zero(t, streamErr.ErrorCode)
				} else {
					require.NoError(t, h.client.CloseWithError(42, "client done"))
					waitHalfCloseSignal(t, h.server.Context().Done())
				}
				// These must happen before test cleanup closes any TCP socket.
				waitHalfCloseSignal(t, h.outbound.closed)
				waitHalfCloseSignal(t, h.outbound.readDone)
				waitHalfCloseSignal(t, h.done)
			})
		}
	})
}

func TestHandleTCPRequestNormalHalfClose(t *testing.T) {
	forEachCopyPath(t, func(t *testing.T, path *copyTestPath) {
		for _, firstFIN := range []string{"client", "backend"} {
			t.Run(firstFIN, func(t *testing.T) {
				h := newHalfCloseHandlerTest(t, path.logged, false)
				request := bytes.Repeat([]byte("request after backend FIN\n"), 10000)
				response := []byte("response after client FIN")
				upload := func() error {
					if _, err := h.clientStream.Write(request); err != nil {
						return err
					}
					return h.clientStream.Close()
				}
				readUpload := func() {
					got, err := io.ReadAll(h.backend)
					require.NoError(t, err)
					require.True(t, bytes.Equal(request, got),
						"upload mismatch: got %d bytes, want %d", len(got), len(request))
				}
				var uploadDone <-chan error
				if firstFIN == "client" {
					uploadDone = copyAsync(upload)
					readUpload()
				}
				_, err := h.backend.Write(response)
				require.NoError(t, err)
				require.NoError(t, h.backend.CloseWrite())
				got, err := io.ReadAll(h.clientStream)
				require.NoError(t, err)
				require.Equal(t, response, got)
				waitHalfCloseSignal(t, h.serverStream.Context().Done())
				require.Equal(t, context.Canceled, context.Cause(h.serverStream.Context()))
				if firstFIN == "backend" {
					// Normal server CloseWrite must not cancel the reverse upload,
					// even though the server stream's Context is already done.
					uploadDone = copyAsync(upload)
					readUpload()
				}
				require.NoError(t, waitCopy(t, uploadDone))
				waitHalfCloseSignal(t, h.done)
			})
		}
	})
}

func TestHandleTCPRequestConnectionCloseAfterNormalFIN(t *testing.T) {
	forEachCopyPath(t, func(t *testing.T, path *copyTestPath) {
		h := newHalfCloseHandlerTest(t, path.logged, true)
		require.NoError(t, h.backend.CloseWrite())
		_, err := io.ReadAll(h.clientStream)
		require.NoError(t, err)
		waitHalfCloseSignal(t, h.serverStream.Context().Done())
		require.Equal(t, context.Canceled, context.Cause(h.serverStream.Context()))
		// Deterministically block the remaining copy in the outbound Write,
		// just as with a backend that has stopped consuming the upload.
		_, err = h.clientStream.Write([]byte("blocked upload"))
		require.NoError(t, err)
		waitHalfCloseSignal(t, h.outbound.writeStarted)
		require.NoError(t, h.client.CloseWithError(42, "client done"))
		waitHalfCloseSignal(t, h.server.Context().Done())
		// The stream context retains its original normal cause. Only the
		// independent connection observer can unblock this outbound Write.
		require.Equal(t, context.Canceled, context.Cause(h.serverStream.Context()))
		waitHalfCloseSignal(t, h.outbound.closed)
		waitHalfCloseSignal(t, h.done)
	})
}
