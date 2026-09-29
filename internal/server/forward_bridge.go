package server

import (
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"rdev/internal/protocol"
)

// Closing either endpoint must release both workers without requiring a device
// acknowledgement. Done cancels producers; WriteCh is never closed concurrently
// with a device frame dispatch.
func bridgeForward(client *ClientConn, fwd *ProxyForward, ch gossh.Channel) {
	var once sync.Once
	stop := func() {
		once.Do(func() { close(fwd.Done); _ = ch.Close() })
	}
	defer stop()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer stop()
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				if e := client.SendBinary(protocol.BinTCPData, fwd.ID, buf[:n]); e != nil {
					return
				}
			}
			if err != nil {
				// Release local resources before a possibly slow notification.
				stop()
				_ = client.Send(&protocol.Message{Type: protocol.MsgTCPClose, ForwardID: fwd.ID})
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer stop()
		for {
			select {
			case <-fwd.Done:
				return
			case data := <-fwd.WriteCh:
				if _, err := ch.Write(data); err != nil {
					return
				}
			case <-fwd.CloseCh:
				// Device frames are ordered. Deliver already queued response
				// bytes before closing on the device's end-of-stream.
				for {
					select {
					case <-fwd.Done:
						return
					case data := <-fwd.WriteCh:
						if _, err := ch.Write(data); err != nil {
							return
						}
					default:
						return
					}
				}
			}
		}
	}()
	<-fwd.Done
	workers.Wait()
}

func (f *ProxyForward) enqueue(data []byte) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-f.Done:
	case f.WriteCh <- data:
	case <-timer.C:
		f.SignalClose()
	}
}
