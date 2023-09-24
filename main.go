package main

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"mellium.im/sasl"
	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/dial"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"
)

type logWriter struct {
	logger *log.Logger
}

type messageBody struct {
	stanza.Message
	Body string `xml:"body"`
}

func (w logWriter) Write(p []byte) (int, error) {
	w.logger.Printf("%s", p)
	return len(p), nil
}

func main(){
	// Logger and XML logger during stream negotiations
	logger := log.New(os.Stderr, "", log.LstdFlags)
	sentXML := log.New(io.Discard, "SENT ", log.LstdFlags)
	recvXML := log.New(io.Discard, "RECV ", log.LstdFlags)

	// Handling flags
	var (
		help bool
		verbose bool
		quic bool
	)
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.BoolVar(&help, "h", help, "Show this help message.")
	flags.BoolVar(&verbose, "v", verbose, "Show verbose logging.")
	flags.BoolVar(&quic, "quic", quic, "Use quic to connect to server.")

	err := flags.Parse(os.Args[1:])
	switch err {
	case flag.ErrHelp:
		help = true
	case nil:
	default:
		logger.Fatalf("Error parsing flags: %v", err)
	}

	if help {
		printHelp(flags)
		os.Exit(0)
	}

	if verbose {
		sentXML.SetOutput(os.Stderr)
		recvXML.SetOutput(os.Stderr)
	}

	args := flags.Args()
	if len(args) < 1 {
		printHelp(flags)
		os.Exit(1)
	}

	var (
		addr string
		pass string
	)

	fmt.Printf("Input your JID: ")
	_, err = fmt.Scan(&addr)
	if err != nil {
		logger.Fatalf("Error reading from stdin: %v", err)
	}

	fmt.Printf("Password: ")
	_, err = fmt.Scan(&pass)
	if err != nil {
		logger.Fatalf("Error reading from stdin: %v", err)
	}

	parsedAuthAddr, err := jid.Parse(addr)
	if err != nil {
		logger.Fatalf("Error parsing %q as a JID: %v", addr, err)
	}

	parsedToAddr, err := jid.Parse(args[0])
	if err != nil {
		logger.Fatalf("Error parsing %q as a JID: %v", args[0], err)
	}

	fmt.Println("Logging in...")

	// Different negotiation process for quic and tcp
	var negotiator xmpp.Negotiator
	if quic {
		negotiator = xmpp.NewNegotiator(func(*xmpp.Session, *xmpp.StreamConfig) xmpp.StreamConfig {
			return xmpp.StreamConfig{
				Features: []xmpp.StreamFeature{
					xmpp.SASL(parsedAuthAddr.String(), pass, sasl.ScramSha256Plus, sasl.ScramSha1Plus, sasl.ScramSha256, sasl.ScramSha1, sasl.Plain),
					xmpp.BindResource(),
				},
				TeeIn: logWriter{logger: recvXML},
				TeeOut: logWriter{logger: sentXML},
			}
		})
	} else {
		negotiator = xmpp.NewNegotiator(func(*xmpp.Session, *xmpp.StreamConfig) xmpp.StreamConfig {
			return xmpp.StreamConfig{
				Features: []xmpp.StreamFeature{
					xmpp.StartTLS(&tls.Config{
						ServerName: parsedAuthAddr.Domain().String(),
						MinVersion: tls.VersionTLS12,
					}),
					xmpp.SASL(parsedAuthAddr.String(), pass, sasl.ScramSha256Plus, sasl.ScramSha1Plus, sasl.ScramSha256, sasl.ScramSha1, sasl.Plain),
					xmpp.BindResource(),
				},
				TeeIn: logWriter{logger: recvXML},
				TeeOut: logWriter{logger: sentXML},
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var session *xmpp.Session
	if quic {
		logger.Fatalf("Haven't implemented yet")
	} else {
		d := dial.Dialer{
			NoTLS: true,
		}
		dialCtx, dialCtxCancel := context.WithTimeout(ctx, 30*time.Second)
		conn, err := d.Dial(dialCtx, "tcp", parsedAuthAddr)
		if err != nil {
			logger.Fatalf("Error dialing connection: %v", err)
		}

		session, err = xmpp.NewSession(dialCtx, parsedAuthAddr.Domain(), parsedAuthAddr, conn, 0, negotiator)
		dialCtxCancel()
		if err != nil {
			logger.Fatalf("Error logging in: %v", err)
		}
	}

	defer func() {
		fmt.Println("Closing session...")
		if err := session.Close(); err != nil {
			logger.Fatalf("Error ending session: %v", err)
		}
		if err := session.Conn().Close(); err != nil {
			logger.Fatalf("Error ending connection: %v", err)
		}
	}()
	
	// Send initial presence to let us receive message from server
	err = session.Send(ctx, stanza.Presence{Type: stanza.AvailablePresence}.Wrap(nil))
	if err != nil {
		logger.Fatalf("Error sending initial presence: %v", err)
	}

	// Message receiving handler
	go func() {
		session.Serve(xmpp.HandlerFunc(func(t xmlstream.TokenReadEncoder, start *xml.StartElement) error {
			d := xml.NewTokenDecoder(t)

			// Ignore anything that's not a message. In a real system we'd want to at
			if start.Name.Local != "message" {
				return nil
			}

			msg := messageBody{}
			err = d.DecodeElement(&msg, start)
			if err != nil && err != io.EOF {
				logger.Printf("Error decoding message: %v", err)
				return nil
			}

			if msg.Body == "" || msg.Type != stanza.ChatMessage {
				return nil
			}

			fmt.Printf("%s: %s\n", parsedToAddr.String(), msg.Body) 

			return nil
		}))	
	}()

	// We can start sending our message from here
	fmt.Println("Start messaging (type 'exit' to exit)")
	for {
		var msg string
		_, err := fmt.Scan(&msg)
		if err != nil {
			logger.Fatalf("Error reading input: %v", err)
		}

		if msg == "exit" {
			break
		}

		if msg == "" {
			continue
		}

		err = session.Encode(ctx, messageBody{
			Message: stanza.Message{
				To: parsedToAddr,
				From: parsedAuthAddr,
				Type: stanza.ChatMessage,
			},
			Body: msg,
		})
		if err != nil {
			logger.Fatalf("Error sending message: %v", err)
		}
	}
}

func printHelp(flags *flag.FlagSet) {
	fmt.Fprintf(flags.Output(), "Usage of %s:\n", os.Args[0])
	flags.PrintDefaults()
	fmt.Printf("Running: %s <flags> <JID Target>\n", os.Args[0])
}
