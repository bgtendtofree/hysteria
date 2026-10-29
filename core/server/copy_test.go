package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// Two crossed pipes provide deterministic, in-memory half-close semantics.
type copyPipeConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newCopyPipe(t *testing.T) (*copyPipeConn, *copyPipeConn) {
	t.Helper()
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	a, b := &copyPipeConn{ar, bw}, &copyPipeConn{br, aw}
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

func (c *copyPipeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *copyPipeConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *copyPipeConn) CloseWrite() error           { return c.w.Close() }
func (c *copyPipeConn) Close() error {
	_ = c.r.Close()
	return c.w.Close()
}

type copyTrafficLogger struct {
	mu        sync.Mutex
	tx, rx    uint64
	invalidID bool
	reject    bool
}

func (l *copyTrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tx += tx
	l.rx += rx
	l.invalidID = l.invalidID || id != "test-user"
	return !l.reject
}

func (*copyTrafficLogger) LogOnlineState(string, bool)        {}
func (*copyTrafficLogger) TraceStream(HyStream, *StreamStats) {}
func (*copyTrafficLogger) UntraceStream(HyStream)             {}

type copyTestPath struct {
	logged bool
	logger copyTrafficLogger
	stats  StreamStats
}

func forEachCopyPath(t *testing.T, test func(*testing.T, *copyTestPath)) {
	t.Helper()
	for _, name := range []string{"fast", "logged"} {
		t.Run(name, func(t *testing.T) {
			baseline := goleak.IgnoreCurrent()
			t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
			test(t, &copyTestPath{logged: name == "logged"})
		})
	}
}

func (p *copyTestPath) run(server, remote io.ReadWriter) error {
	if p.logged {
		return copyTwoWayEx("test-user", server, remote, &p.logger, &p.stats)
	}
	return copyTwoWay(server, remote)
}

func (p *copyTestPath) checkTraffic(t *testing.T, tx, rx uint64) {
	t.Helper()
	if !p.logged {
		tx, rx = 0, 0
	}
	p.logger.mu.Lock()
	defer p.logger.mu.Unlock()
	require.Equal(t, tx, p.logger.tx)
	require.Equal(t, rx, p.logger.rx)
	require.False(t, p.logger.invalidID)
	require.Equal(t, tx, p.stats.Tx.Load())
	require.Equal(t, rx, p.stats.Rx.Load())
	if p.logged {
		require.False(t, p.stats.LastActiveTime.Load().IsZero())
	}
}

func copyAsync(f func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- f() }()
	return done
}

func waitCopy(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("copy did not finish")
		return nil
	}
}

// Mirror handleTCPRequest: full-close only after the copy function returns.
func startCopy(p *copyTestPath, server, remote io.ReadWriteCloser) <-chan error {
	return copyAsync(func() error {
		err := p.run(server, remote)
		_ = server.Close()
		_ = remote.Close()
		return err
	})
}

func TestCopyTwoWayHalfClose(t *testing.T) {
	forEachCopyPath(t, func(t *testing.T, p *copyTestPath) {
		for _, direction := range []string{"server-to-remote", "remote-to-server"} {
			t.Run(direction, func(t *testing.T) {
				path := &copyTestPath{logged: p.logged}
				server, serverPeer := newCopyPipe(t)
				remote, remotePeer := newCopyPipe(t)
				initiator, backend := serverPeer, remotePeer
				if direction == "remote-to-server" {
					initiator, backend = backend, initiator
				}
				request := []byte("request terminated by EOF")
				response := bytes.Repeat([]byte("response after EOF\n"), 10000)
				sendResponse := make(chan struct{})
				release := sync.OnceFunc(func() { close(sendResponse) })
				t.Cleanup(release)
				requestDone := make(chan error, 1)
				backendDone := copyAsync(func() error {
					got, err := io.ReadAll(backend)
					if err == nil && !bytes.Equal(got, request) {
						err = fmt.Errorf("backend received %q, want %q", got, request)
					}
					requestDone <- err
					if err != nil {
						return err
					}
					// The backend deliberately waits for EOF before responding.
					<-sendResponse
					if _, err := backend.Write(response); err != nil {
						return err
					}
					return backend.CloseWrite()
				})
				relayDone := startCopy(path, server, remote)
				clientDone := copyAsync(func() error {
					if _, err := initiator.Write(request); err != nil {
						return err
					}
					if err := initiator.CloseWrite(); err != nil {
						return err
					}
					got, err := io.ReadAll(initiator)
					if err == nil && !bytes.Equal(got, response) {
						err = fmt.Errorf("received %d response bytes, want %d", len(got), len(response))
					}
					return err
				})
				require.NoError(t, waitCopy(t, requestDone))
				select {
				case err := <-relayDone:
					t.Fatalf("copy returned before reverse response: %v", err)
				default:
				}
				release()
				require.NoError(t, waitCopy(t, clientDone))
				require.NoError(t, waitCopy(t, backendDone))
				require.NoError(t, waitCopy(t, relayDone))
				tx, rx := uint64(len(request)), uint64(len(response))
				if direction == "remote-to-server" {
					tx, rx = rx, tx
				}
				path.checkTraffic(t, tx, rx)
			})
		}
	})
}

type copyFaultConn struct {
	*copyPipeConn
	readErr, writeErr, closeWriteErr error
}

func (c *copyFaultConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.copyPipeConn.Read(p)
}

func (c *copyFaultConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.copyPipeConn.Write(p)
}

func (c *copyFaultConn) CloseWrite() error {
	if c.closeWriteErr != nil {
		return c.closeWriteErr
	}
	return c.copyPipeConn.CloseWrite()
}

func TestCopyTwoWayErrorsUnblock(t *testing.T) {
	forEachCopyPath(t, func(t *testing.T, p *copyTestPath) {
		for _, direction := range []string{"server-to-remote", "remote-to-server"} {
			for _, failure := range []string{"read", "write", "close-write"} {
				t.Run(direction+"/"+failure, func(t *testing.T) {
					server, serverPeer := newCopyPipe(t)
					remote, remotePeer := newCopyPipe(t)
					src, dst, peer := server, remote, serverPeer
					if direction == "remote-to-server" {
						src, dst, peer = remote, server, remotePeer
					}
					srcFault := &copyFaultConn{copyPipeConn: src}
					dstFault := &copyFaultConn{copyPipeConn: dst}
					wantErr := errors.New("injected " + failure + " failure")
					switch failure {
					case "read":
						srcFault.readErr = wantErr
					case "write":
						dstFault.writeErr = wantErr
					case "close-write":
						dstFault.closeWriteErr = wantErr
					}
					var s, r io.ReadWriteCloser = srcFault, dstFault
					if direction == "remote-to-server" {
						s, r = r, s
					}
					done := startCopy(p, s, r)
					if failure == "write" {
						require.NoError(t, waitCopy(t, copyAsync(func() error {
							_, err := peer.Write([]byte("trigger write failure"))
							return err
						})))
					} else if failure == "close-write" {
						require.NoError(t, peer.CloseWrite())
					}
					// The reverse source remains open and blocked until caller cleanup.
					require.ErrorIs(t, waitCopy(t, done), wantErr)
				})
			}
		}
	})
}

func TestCopyTwoWayErrorAfterEOF(t *testing.T) {
	forEachCopyPath(t, func(t *testing.T, p *copyTestPath) {
		server, serverPeer := newCopyPipe(t)
		remote, remotePeer := newCopyPipe(t)
		done := startCopy(p, server, remote)
		require.NoError(t, remotePeer.CloseWrite())
		require.NoError(t, waitCopy(t, copyAsync(func() error {
			_, err := io.ReadAll(serverPeer)
			return err
		})))
		wantErr := errors.New("read failed after reverse EOF")
		require.NoError(t, serverPeer.w.CloseWithError(wantErr))
		require.ErrorIs(t, waitCopy(t, done), wantErr)
	})
}

func TestCopyTwoWayFullCloseFallback(t *testing.T) {
	forEachCopyPath(t, func(t *testing.T, p *copyTestPath) {
		for _, noHalfClose := range []string{"server", "remote"} {
			for _, firstEOF := range []string{"server", "remote"} {
				t.Run(noHalfClose+"/EOF-"+firstEOF, func(t *testing.T) {
					server, serverPeer := newCopyPipe(t)
					remote, remotePeer := newCopyPipe(t)
					var s, r io.ReadWriteCloser = server, remote
					// Hide CloseWrite, as with a transport without half-close support.
					if noHalfClose == "server" {
						s = struct{ io.ReadWriteCloser }{s}
					} else {
						r = struct{ io.ReadWriteCloser }{r}
					}
					done := startCopy(p, s, r)
					if firstEOF == "server" {
						require.NoError(t, serverPeer.CloseWrite())
					} else {
						require.NoError(t, remotePeer.CloseWrite())
					}
					require.NoError(t, waitCopy(t, done))
				})
			}
		}
	})
}

func TestCopyTwoWayLoggerDisconnect(t *testing.T) {
	for _, direction := range []string{"server-to-remote", "remote-to-server"} {
		t.Run(direction, func(t *testing.T) {
			baseline := goleak.IgnoreCurrent()
			t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
			p := &copyTestPath{logged: true, logger: copyTrafficLogger{reject: true}}
			server, serverPeer := newCopyPipe(t)
			remote, remotePeer := newCopyPipe(t)
			peer := serverPeer
			if direction == "remote-to-server" {
				peer = remotePeer
			}
			done := startCopy(p, server, remote)
			data := []byte("traffic rejected before destination write")
			require.NoError(t, waitCopy(t, copyAsync(func() error {
				_, err := peer.Write(data)
				return err
			})))
			// No destination reader is needed: rejection happens before Write.
			require.ErrorIs(t, waitCopy(t, done), errDisconnect)
			tx, rx := uint64(len(data)), uint64(0)
			if direction == "remote-to-server" {
				tx, rx = rx, tx
			}
			p.checkTraffic(t, tx, rx)
		})
	}
}
