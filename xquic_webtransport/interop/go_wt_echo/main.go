package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

func main() {
	certFile := "../../certs/localhost.crt"
	keyFile := "../../certs/localhost.key"
	addr := "127.0.0.1:4434"

	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load cert: %v", err)
	}

	h3Server := &http3.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
		EnableDatagrams: true,
	}
	// ConfigureHTTP3Server injects QUIC connection context needed for WebTransport upgrade
	webtransport.ConfigureHTTP3Server(h3Server)

	s := &webtransport.Server{
		H3:          h3Server,
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		session, err := s.Upgrade(w, r)
		if err != nil {
			log.Printf("Upgrade failed: %v", err)
			return
		}
		log.Printf("WebTransport session established: path=%s remote=%s", r.URL.Path, r.RemoteAddr)

		// Handle bidi streams
		go func() {
			for {
				stream, err := session.AcceptStream(context.Background())
				if err != nil {
					log.Printf("AcceptStream done: %v", err)
					return
				}
				go func() {
					defer stream.Close()
					n, err := io.Copy(stream, stream)
					if err != nil {
						log.Printf("Bidi echo error: %v", err)
						return
					}
					log.Printf("Bidi echo: %d bytes", n)
				}()
			}
		}()

		// Handle uni streams
		go func() {
			for {
				recvStream, err := session.AcceptUniStream(context.Background())
				if err != nil {
					log.Printf("AcceptUniStream done: %v", err)
					return
				}
				go func() {
					data, err := io.ReadAll(recvStream)
					if err != nil {
						log.Printf("Uni read error: %v", err)
						return
					}
					log.Printf("Uni received: %d bytes", len(data))

					sendStream, err := session.OpenUniStream()
					if err != nil {
						log.Printf("OpenUniStream error: %v", err)
						return
					}
					sendStream.Write(data)
					sendStream.Close()
					log.Printf("Uni echo sent: %d bytes", len(data))
				}()
			}
		}()

		// Handle datagrams
		go func() {
			for {
				dgram, err := session.ReceiveDatagram(context.Background())
				if err != nil {
					log.Printf("ReceiveDatagram done: %v", err)
					return
				}
				log.Printf("Datagram received: %d bytes", len(dgram))
				err = session.SendDatagram(dgram)
				if err != nil {
					log.Printf("SendDatagram error: %v", err)
				}
			}
		}()

		<-session.Context().Done()
		log.Printf("Session closed")
	})

	log.Printf("webtransport-go echo server listening on %s", addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
