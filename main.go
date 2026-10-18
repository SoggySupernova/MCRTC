// mctunnel: bare-bones WebRTC TCP tunnel with copy/paste signaling.
//
//	host   (machine running the Minecraft server):  ./mctunnel -mode host
//	client (friend):                                ./mctunnel -mode client
//
// The client prints an "offer" blob; paste it into the host. The host prints an
// "answer" blob; paste it back into the client. Then the friend adds
// localhost:25565 as a server in Minecraft.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"
)

var (
	mode       = flag.String("mode", "", "host or client")
	target     = flag.String("target", "127.0.0.1:25565", "host: TCP address to forward tunnel connections to")
	listen     = flag.String("listen", "127.0.0.1:25565", "client: local address to listen on")
	stunURLs   = flag.String("stun", "stun:stun.l.google.com:19302,stun:stun.cloudflare.com:3478", "comma-separated STUN URLs (empty to disable)")
	turnURLs   = flag.String("turn", "turn:staticauth.openrelay.metered.ca:80,turn:staticauth.openrelay.metered.ca:80?transport=tcp,turn:staticauth.openrelay.metered.ca:443,turns:staticauth.openrelay.metered.ca:443?transport=tcp", "comma-separated TURN URLs (empty to disable)")
	turnSecret = flag.String("turn-secret", "openrelayprojectsecret", "TURN shared secret (REST-style time-limited credentials)")
	turnUser   = flag.String("turn-user", "", "static TURN username (overrides -turn-secret)")
	turnPass   = flag.String("turn-pass", "", "static TURN password (overrides -turn-secret)")
	relayOnly  = flag.Bool("relay-only", false, "only use TURN relay candidates (to test the relay path)")
)

var stdin = bufio.NewReaderSize(os.Stdin, 1<<20)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)
	switch *mode {
	case "host":
		runHost()
	case "client":
		runClient()
	default:
		fmt.Fprintln(os.Stderr, "usage: mctunnel -mode host|client  (see -h)")
		os.Exit(2)
	}
}

// ---------- WebRTC setup ----------

func newAPI() *webrtc.API {
	se := webrtc.SettingEngine{}
	se.DetachDataChannels() // lets us treat data channels as plain io.ReadWriteCloser
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

func iceConfig() webrtc.Configuration {
	var servers []webrtc.ICEServer
	if s := splitList(*stunURLs); len(s) > 0 {
		servers = append(servers, webrtc.ICEServer{URLs: s})
	}
	if t := splitList(*turnURLs); len(t) > 0 {
		user, pass := *turnUser, *turnPass
		if user == "" {
			// TURN REST API style: username = expiry timestamp, password = HMAC-SHA1(secret, username)
			user = fmt.Sprintf("%d", time.Now().Add(24*time.Hour).Unix())
			m := hmac.New(sha1.New, []byte(*turnSecret))
			m.Write([]byte(user))
			pass = base64.StdEncoding.EncodeToString(m.Sum(nil))
		}
		servers = append(servers, webrtc.ICEServer{URLs: t, Username: user, Credential: pass})
	}
	cfg := webrtc.Configuration{ICEServers: servers}
	if *relayOnly {
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	return cfg
}

// logPath reports whether the connection ended up direct (host/srflx) or relayed.
func logPath(pc *webrtc.PeerConnection, tag string) {
	pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil {
		log.Printf("%s path: unknown (%v)", tag, err)
		return
	}
	kind := "DIRECT"
	if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
		kind = "RELAYED"
	}
	log.Printf("%s path: %s  local %s %s:%d  <->  remote %s %s:%d", tag, kind,
		pair.Local.Typ, pair.Local.Address, pair.Local.Port,
		pair.Remote.Typ, pair.Remote.Address, pair.Remote.Port)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// gather waits for ICE candidates (non-trickle) so the blob contains everything.
func gather(pc *webrtc.PeerConnection) webrtc.SessionDescription {
	done := webrtc.GatheringCompletePromise(pc)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Println("ICE gathering timed out, continuing with candidates found so far")
	}
	return *pc.LocalDescription()
}

// ---------- copy/paste signaling ----------

func encode(d webrtc.SessionDescription) string {
	j, _ := json.Marshal(d)
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write(j)
	zw.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func decode(s string) (webrtc.SessionDescription, error) {
	var d webrtc.SessionDescription
	s = strings.Join(strings.Fields(s), "")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return d, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return d, err
	}
	j, err := io.ReadAll(zr)
	if err != nil {
		return d, err
	}
	return d, json.Unmarshal(j, &d)
}

func prompt(msg string) webrtc.SessionDescription {
	for {
		fmt.Printf("\n%s\n> ", msg)
		line, err := stdin.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			log.Fatalf("stdin closed: %v", err)
		}
		d, derr := decode(line)
		if derr != nil {
			fmt.Printf("could not parse that (%v). Paste the whole blob on one line.\n", derr)
			continue
		}
		return d
	}
}

func show(label string, d webrtc.SessionDescription) {
	b := encode(d)
	fmt.Printf("\n>>> BEGIN %s (%d chars): copy only the line below this one >>>\n\n%s\n\n<<< END %s: do not copy this line <<<\n", label, len(b), b, label)
}

// ---------- byte pump ----------

func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		// wrappers hide ReadFrom/WriteTo so our 64K buffer is always used
		// (data channel reads fail if the buffer is smaller than the message)
		io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, make([]byte, 65535))
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
}

// ---------- host (Linux box running the server) ----------

func runHost() {
	api := newAPI()
	log.Printf("host mode: forwarding tunnel connections to %s", *target)
	for n := 1; ; n++ {
		pc, err := api.NewPeerConnection(iceConfig())
		if err != nil {
			log.Fatal(err)
		}
		id := n
		pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
			log.Printf("[peer %d] connection state: %s", id, s)
			if s == webrtc.PeerConnectionStateConnected {
				logPath(pc, fmt.Sprintf("[peer %d]", id))
			}
			if s == webrtc.PeerConnectionStateFailed || s == webrtc.PeerConnectionStateClosed {
				pc.Close()
			}
		})
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "tcp" {
				return // ignore the control channel
			}
			dc.OnOpen(func() {
				raw, err := dc.Detach()
				if err != nil {
					log.Printf("detach: %v", err)
					return
				}
				tcp, err := net.DialTimeout("tcp", *target, 5*time.Second)
				if err != nil {
					log.Printf("[peer %d] cannot reach %s: %v", id, *target, err)
					raw.Close()
					return
				}
				log.Printf("[peer %d] new tunneled connection -> %s", id, *target)
				go func() {
					pipe(raw, tcp)
					log.Printf("[peer %d] tunneled connection closed", id)
				}()
			})
		})

		offer := prompt(fmt.Sprintf("Paste the OFFER from peer %d:", id))
		if err := pc.SetRemoteDescription(offer); err != nil {
			log.Printf("bad offer: %v", err)
			pc.Close()
			n--
			continue
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			log.Fatal(err)
		}
		if err := pc.SetLocalDescription(answer); err != nil {
			log.Fatal(err)
		}
		show("ANSWER", gather(pc))
		fmt.Println("Waiting for the connection; you can paste another peer's offer below at any time.")
	}
}

// ---------- client (friend's machine) ----------

func runClient() {
	pc, err := newAPI().NewPeerConnection(iceConfig())
	if err != nil {
		log.Fatal(err)
	}
	connected := make(chan struct{})
	var once bool
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		log.Printf("connection state: %s", s)
		switch s {
		case webrtc.PeerConnectionStateConnected:
			if !once {
				once = true
				logPath(pc, "client")
				close(connected)
			}
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			if once {
				log.Println("tunnel lost, exiting")
				os.Exit(1)
			}
		}
	})

	// A first channel is needed so the offer contains a data-channel section.
	if _, err := pc.CreateDataChannel("ctrl", nil); err != nil {
		log.Fatal(err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		log.Fatal(err)
	}
	show("OFFER", gather(pc))

	answer := prompt("Paste the ANSWER from the host:")
	if err := pc.SetRemoteDescription(answer); err != nil {
		log.Fatal(err)
	}

	select {
	case <-connected:
	case <-time.After(30 * time.Second):
		log.Fatal("timed out waiting for the peer connection (NAT traversal probably failed)")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tunnel up. Point Minecraft at %s", *listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			dc, err := pc.CreateDataChannel("tcp", nil)
			if err != nil {
				log.Printf("create channel: %v", err)
				c.Close()
				return
			}
			dc.OnOpen(func() {
				raw, err := dc.Detach()
				if err != nil {
					log.Printf("detach: %v", err)
					c.Close()
					return
				}
				go pipe(raw, c)
			})
		}(c)
	}
}
