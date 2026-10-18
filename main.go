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
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"
)

var (
	mode       = flag.String("mode", "", "host or client")
	target     = flag.String("target", "127.0.0.1:25565", "host: TCP address to forward tunnel connections to")
	listen     = flag.String("listen", "127.0.0.1:25565", "client: local address to listen on")
	stunURLs   = flag.String("stun", "stun:stun.l.google.com:19302,stun:stun.cloudflare.com:3478", "comma-separated STUN URLs (empty to disable)")
	turnURLs   = flag.String("turn", "", "comma-separated TURN URLs (default: none, i.e. direct connections only)")
	turnSecret = flag.String("turn-secret", "", "optional TURN shared secret: generates time-limited credentials and overrides -turn-user/-turn-pass")
	turnUser   = flag.String("turn-user", "", "TURN username")
	turnPass   = flag.String("turn-pass", "", "TURN password")
	turnConfig = flag.String("turn-config", "", "path to a JSON file listing TURN servers, each with its own credentials (see turn-servers.example.json)")
	relayOnly  = flag.Bool("relay-only", false, "only use TURN relay candidates (to test the relay path)")
)

var stdin = bufio.NewReaderSize(os.Stdin, 1<<20)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)
	if *turnConfig != "" {
		extra, err := loadServers(*turnConfig)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("loaded %d TURN/STUN server entries from %s", len(extra), *turnConfig)
	}
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
		if *turnSecret != "" {
			// TURN REST API style: username = expiry timestamp, password = HMAC-SHA1(secret, username)
			user = fmt.Sprintf("%d", time.Now().Add(24*time.Hour).Unix())
			m := hmac.New(sha1.New, []byte(*turnSecret))
			m.Write([]byte(user))
			pass = base64.StdEncoding.EncodeToString(m.Sum(nil))
		}
		servers = append(servers, webrtc.ICEServer{URLs: t, Username: user, Credential: pass})
	}
	if *turnConfig != "" {
		if extra, err := loadServers(*turnConfig); err != nil {
			log.Printf("ignoring -turn-config: %v", err)
		} else {
			servers = append(servers, extra...)
		}
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

// serverEntry is one object in the -turn-config JSON file.
type serverEntry struct {
	URLs       json.RawMessage `json:"urls"` // a string or a list of strings
	Username   string          `json:"username"`
	Credential string          `json:"credential"`
}

func loadServers(path string) ([]webrtc.ICEServer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []serverEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s: expected a JSON list of server objects: %w", path, err)
	}
	var out []webrtc.ICEServer
	for i, e := range entries {
		var urls []string
		if err := json.Unmarshal(e.URLs, &urls); err != nil {
			var one string
			if err2 := json.Unmarshal(e.URLs, &one); err2 != nil {
				return nil, fmt.Errorf("%s: entry %d: \"urls\" must be a string or a list of strings", path, i+1)
			}
			urls = []string{one}
		}
		if len(urls) == 0 {
			return nil, fmt.Errorf("%s: entry %d: \"urls\" is empty", path, i+1)
		}
		for _, u := range urls {
			if strings.HasPrefix(u, "turn") && (e.Username == "" || e.Credential == "") {
				return nil, fmt.Errorf("%s: entry %d: %s needs \"username\" and \"credential\"", path, i+1, u)
			}
		}
		out = append(out, webrtc.ICEServer{URLs: urls, Username: e.Username, Credential: e.Credential})
	}
	return out, nil
}

// gather waits for ICE candidates (non-trickle) so the blob contains everything.
func gather(pc *webrtc.PeerConnection) webrtc.SessionDescription {
	done := webrtc.GatheringCompletePromise(pc)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Println("ICE gathering timed out, continuing with candidates found so far")
	}
	sdp := pc.LocalDescription().SDP
	log.Printf("gathered candidates: host=%d srflx=%d relay=%d",
		strings.Count(sdp, " typ host"), strings.Count(sdp, " typ srflx"), strings.Count(sdp, " typ relay"))
	if *relayOnly && strings.Count(sdp, " typ relay") == 0 {
		log.Println("WARNING: -relay-only but no relay candidates were gathered: the TURN server is unreachable or rejected the credentials, so this cannot connect")
	}
	return *pc.LocalDescription()
}

// ---------- terminal styling (plain text when piped or NO_COLOR is set) ----------

var useColor = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func style(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// OFFER is cyan, ANSWER is yellow, so the two are never confused.
func kindStyle(kind string) string {
	if kind == "OFFER" {
		return "1;36"
	}
	return "1;33"
}

// ---------- copy/paste signaling ----------
//
// Blobs look like MCT.OFFER.<url-safe base64> or MCT.ANSWER.<...> (no '=' padding, no
// spaces). The prefix says which kind it is, and the parser pulls the blob out of
// whatever text was pasted, so stray surrounding text is harmless.

var blobRe = regexp.MustCompile(`MCT\.(OFFER|ANSWER)\.[A-Za-z0-9_-]+`)

func encode(kind string, d webrtc.SessionDescription) string {
	j, _ := json.Marshal(d)
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write(j)
	zw.Close()
	return "MCT." + kind + "." + base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func decode(kind, text string) (webrtc.SessionDescription, error) {
	var d webrtc.SessionDescription
	m := blobRe.FindString(text)
	if m == "" {
		return d, fmt.Errorf("no MCT.%s.... blob found in what you pasted", kind)
	}
	parts := strings.SplitN(m, ".", 3)
	if parts[1] != kind {
		return d, fmt.Errorf("that is an %s, but an %s is needed here", parts[1], kind)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
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

// prompt asks for a blob of the given kind ("OFFER" or "ANSWER") and retries until it parses.
func prompt(kind, msg string) webrtc.SessionDescription {
	for {
		fmt.Printf("\n%s %s\n%s ", style(kindStyle(kind), "▶ PASTE HERE:"), style("1", msg), style("2", "›"))
		line, err := stdin.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			log.Fatalf("stdin closed: %v", err)
		}
		d, derr := decode(kind, line)
		if derr != nil {
			fmt.Printf("%s %v. Try again.\n", style("1;31", "✗"), derr)
			continue
		}
		return d
	}
}

func toClipboard(text string) bool {
	for _, c := range [][]string{{"pbcopy"}, {"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "-b", "-i"}} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if cmd.Run() == nil {
			return true
		}
	}
	return false
}

func show(kind string, d webrtc.SessionDescription) {
	b := encode(kind, d)
	st := kindStyle(kind)
	rule := strings.Repeat("━", 64)
	fmt.Printf("\n%s\n", style(st, "┏"+rule))
	fmt.Printf("%s  %s\n", style(st, "┃"), style("1", fmt.Sprintf("YOUR %s is ready (%d chars)", kind, len(b))))
	fmt.Printf("%s  Send the single MCT line below to the other person.\n", style(st, "┃"))
	fmt.Printf("%s  It starts with %s and has no spaces.\n", style(st, "┃"), style("1", "MCT."+kind+"."))
	fmt.Printf("%s\n\n", style(st, "┣"+rule))
	fmt.Printf("%s\n\n", style(st, b))
	fmt.Printf("%s\n", style(st, "┗"+rule))
	if toClipboard(b) {
		fmt.Printf("%s copied to your clipboard\n", style("1;32", "✓"))
	}
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

		offer := prompt("OFFER", fmt.Sprintf("Paste the OFFER from peer %d, then press Enter:", id))
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

	answer := prompt("ANSWER", "Paste the ANSWER from the host, then press Enter:")
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
