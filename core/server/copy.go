package server

import (
	"errors"
	"io"
	"sync"
	"time"
)

var errDisconnect = errors.New("traffic logger requested disconnect")

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func copyBufferLog(dst io.Writer, src io.Reader, log func(n uint64) bool) error {
	bufp := copyBufPool.Get().(*[]byte)
	buf := *bufp
	defer copyBufPool.Put(bufp)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if !log(uint64(nr)) {
				// Log returns false, which means that the client should be disconnected
				return errDisconnect
			}
			_, ew := dst.Write(buf[0:nr])
			if ew != nil {
				return ew
			}
		}
		if er != nil {
			if er == io.EOF {
				// EOF should not be considered as an error
				return nil
			}
			return er
		}
	}
}

func copyTwoWayEx(id string, serverRw, remoteRw io.ReadWriter, l TrafficLogger, stats *StreamStats) error {
	return copyTwoWayWith(serverRw, remoteRw, func() error {
		return copyBufferLog(serverRw, remoteRw, func(n uint64) bool {
			stats.LastActiveTime.Store(time.Now())
			stats.Rx.Add(n)
			return l.LogTraffic(id, 0, n)
		})
	}, func() error {
		return copyBufferLog(remoteRw, serverRw, func(n uint64) bool {
			stats.LastActiveTime.Store(time.Now())
			stats.Tx.Add(n)
			return l.LogTraffic(id, n, 0)
		})
	})
}

// copyTwoWay is the "fast-path" version of copyTwoWayEx that does not log traffic or update stream stats.
// It uses the built-in io.Copy instead of our own copyBufferLog.
func copyTwoWay(serverRw, remoteRw io.ReadWriter) error {
	return copyTwoWayWith(serverRw, remoteRw, func() error {
		_, err := io.Copy(serverRw, remoteRw)
		return err
	}, func() error {
		_, err := io.Copy(remoteRw, serverRw)
		return err
	})
}

type closeWriter interface {
	CloseWrite() error
}

// copyTwoWayWith shares EOF/error coordination between the fast and logged paths.
// The caller owns full cleanup, which also unblocks the other copy on error.
func copyTwoWayWith(serverRw, remoteRw io.ReadWriter, rx, tx func() error) error {
	serverCW, serverOK := serverRw.(closeWriter)
	remoteCW, remoteOK := remoteRw.(closeWriter)
	// Without half-close support on both ends, retain first-completion behavior
	// so the caller can fully close transports that cannot propagate a FIN.
	halfClose := serverOK && remoteOK

	errChan := make(chan error, 2)
	copyAndClose := func(copyFunc func() error, dst closeWriter) {
		err := copyFunc()
		if err == nil && halfClose {
			err = dst.CloseWrite()
		}
		errChan <- err
	}
	go copyAndClose(rx, serverCW)
	go copyAndClose(tx, remoteCW)

	if err := <-errChan; err != nil || !halfClose {
		return err
	}
	// A clean EOF only finishes one direction. Let the reverse copy drain,
	// unless it fails, without imposing a timeout on half-closed connections.
	return <-errChan
}
