// mcrtc: bare-bones WebRTC TCP tunnel with copy/paste signaling and a small
// full-screen terminal UI.
//
//	host   (machine running the Minecraft server):  ./mcrtc -mode host
//	client (friend):                                ./mcrtc -mode client
//
// The client prints an "offer" blob; paste it into the host. The host prints an
// "answer" blob; paste it back into the client. Then the friend adds
// localhost:25565 as a server in Minecraft.
//
// Terminal notes (macOS Terminal.app and KDE Konsole are the reference targets):
//   - Only plain ANSI/VT100 sequences are used: alternate screen (?1049), cursor
//     addressing (CUP), erase line/display (EL/ED), and 8/16-colour SGR codes.
//     No truecolor, no OSC 8 hyperlinks, no synchronized-output or kitty extensions.
//   - The tty is switched to non-canonical mode with `stty`. In canonical (line)
//     mode the kernel caps a line at 1024 bytes on macOS, which would truncate
//     the multi-kilobyte blobs that get pasted. No extra Go dependencies are needed.
//   - Unix only (uses stty and SIGWINCH).
package main

import (
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
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

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

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)
	loaded := -1
	if *turnConfig != "" {
		extra, err := loadServers(*turnConfig)
		if err != nil {
			fatalf("%v", err)
		}
		loaded = len(extra)
	}
	switch *mode {
	case "host":
		tui.start("HOST", []string{"Paste offer", "Send answer", "Connected"})
		logStartup(loaded)
		runHost()
	case "client":
		tui.start("CLIENT", []string{"Create offer", "Paste answer", "Connect", "Play"})
		logStartup(loaded)
		runClient()
	default:
		fmt.Fprintln(os.Stderr, "usage: mcrtc -mode host|client  (see -h)")
		os.Exit(2)
	}
}

func logStartup(loaded int) {
	if loaded >= 0 {
		log.Printf("loaded %d TURN/STUN server entries from %s", loaded, *turnConfig)
	}
}

// fatalf leaves the TUI (restoring the terminal), prints the message and exits.
func fatalf(format string, a ...any) {
	tui.exit(fmt.Sprintf(format, a...), 1)
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

// logPath logs and returns whether the connection ended up direct (host/srflx) or relayed.
func logPath(pc *webrtc.PeerConnection, tag string) string {
	pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil {
		log.Printf("%s path: unknown (%v)", tag, err)
		return "unknown"
	}
	kind := "DIRECT"
	if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
		kind = "RELAYED"
	}
	log.Printf("%s path: %s  local %s %s:%d  <->  remote %s %s:%d", tag, kind,
		pair.Local.Typ, pair.Local.Address, pair.Local.Port,
		pair.Remote.Typ, pair.Remote.Address, pair.Remote.Port)
	return kind
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

// ---------- copy/paste signaling ----------
//
// Blobs look like MCRTC.OFFER.<url-safe base64> or MCRTC.ANSWER.<...> (no '=' padding, no
// spaces). The prefix says which kind it is, and the parser pulls the blob out of
// whatever text was pasted, so stray surrounding text is harmless.

var blobRe = regexp.MustCompile(`MCRTC\.(OFFER|ANSWER)\.[A-Za-z0-9_-]+`)

func encode(kind string, d webrtc.SessionDescription) string {
	j, _ := json.Marshal(d)
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write(j)
	zw.Close()
	return "MCRTC." + kind + "." + base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func decode(kind, text string) (webrtc.SessionDescription, error) {
	var d webrtc.SessionDescription
	m := blobRe.FindString(text)
	if m == "" {
		return d, fmt.Errorf("no MCRTC.%s.... blob found in what you pasted", kind)
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

// decodePasted copes with pastes that were hard-wrapped by a chat app or a
// terminal copy: it first tries the text as-is (so stray words around the blob
// are harmless), then with all whitespace removed.
func decodePasted(kind, text string) (webrtc.SessionDescription, error) {
	d, err := decode(kind, strings.Join(strings.Fields(text), " "))
	if err == nil {
		return d, nil
	}
	if d2, err2 := decode(kind, strings.Join(strings.Fields(text), "")); err2 == nil {
		return d2, nil
	}
	return d, err
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

// ====================================================================
// Terminal UI
// ====================================================================

// SGR codes: only the basic 8/16-colour palette plus bold/reverse.
const (
	cBold   = "1"
	cRed    = "1;31"
	cGreen  = "1;32"
	cYellow = "1;33"
	cCyan   = "1;36"
	cGray   = "90"
)

func sty(code, s string) string {
	if code == "" || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// OFFER is cyan, ANSWER is yellow, so the two are never confused.
func kindStyle(kind string) string {
	if kind == "OFFER" {
		return cCyan
	}
	return cYellow
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func visLen(s string) int { return utf8.RuneCountInString(ansiRe.ReplaceAllString(s, "")) }

func rowsFor(n, w int) int {
	if n <= 0 || w <= 0 {
		return 1
	}
	return (n + w - 1) / w
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 2 {
		return ""
	}
	return string(r[:n-1]) + "…"
}

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func wrap(s string, w int) []string {
	if w < 10 {
		w = 10
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			switch {
			case line == "":
				line = word
			case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) <= w:
				line += " " + word
			default:
				out = append(out, line)
				line = word
			}
		}
		out = append(out, line)
	}
	return out
}

var spinFrames = []string{"|", "/", "-", "\\"}

func spin() string {
	return sty(cCyan, spinFrames[(time.Now().UnixNano()/int64(200*time.Millisecond))%4])
}

// A body is a list of items, rebuilt on every render.
const (
	kText = iota // word-wrapped paragraph
	kRaw         // printed as-is (may soft-wrap in the terminal, e.g. the blobs)
	kGap         // blank line that is dropped when the window is short
)

type item struct {
	text  string
	style string
	kind  int
}

func txt(style, s string) item { return item{text: s, style: style, kind: kText} }
func raw(s string) item        { return item{text: s, kind: kRaw} }
func gap() item                { return item{kind: kGap} }

// fline is one logical output line; rows is how many terminal rows it occupies.
type fline struct {
	text string
	rows int
	noEL bool // line exactly fills the width: skip "erase to end of line"
}

func mk(text string, w int) fline {
	n := visLen(text)
	return fline{text: text, rows: rowsFor(n, w), noEL: n > 0 && w > 0 && n%w == 0}
}

func layoutBody(items []item, w int, dropGaps bool) []fline {
	var out []fline
	for _, it := range items {
		switch it.kind {
		case kGap:
			if !dropGaps {
				out = append(out, mk("", w))
			}
		case kRaw:
			out = append(out, mk(it.text, w))
		default:
			for _, l := range wrap(it.text, w-4) {
				out = append(out, mk("  "+sty(it.style, l), w))
			}
		}
	}
	return out
}

func sumRows(ls []fline) int {
	n := 0
	for _, l := range ls {
		n += l.rows
	}
	return n
}

type ui struct {
	mu    sync.Mutex
	w, h  int
	role  string
	steps []string
	cur   int
	body  func(w int) []item
	logs  []string

	inText string // current text-entry contents (see inputItems)
	inErr  string

	prev []string // per-line keys of the last frame, for incremental redraw

	saved       string
	started     atomic.Bool
	closed      atomic.Bool
	restoreOnce sync.Once
}

var tui = &ui{}

// inCh carries raw byte chunks read from the terminal.
var inCh = make(chan []byte, 256)

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func sttyCmd(args ...string) *exec.Cmd {
	c := exec.Command("stty", args...)
	c.Stdin = os.Stdin
	return c
}

func termSize() (w, h int) {
	w, h = 80, 24
	out, err := sttyCmd("size").Output()
	if err != nil {
		return
	}
	var r, c int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d %d", &r, &c); err == nil && r > 0 && c > 0 {
		h, w = r, c
	}
	return
}

func (u *ui) start(role string, steps []string) {
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		fatalf("mcrtc needs an interactive terminal (stdin and stdout must be a TTY)")
	}
	out, err := sttyCmd("-g").Output()
	if err != nil {
		fatalf("cannot read terminal settings with stty: %v", err)
	}
	u.saved = strings.TrimSpace(string(out))
	// Non-canonical, no echo: pasted blobs are not limited to one tty line
	// (1024 bytes on macOS), and we draw the input ourselves. ISIG stays on so
	// Ctrl-C still raises SIGINT.
	if err := sttyCmd("-icanon", "-echo", "min", "1", "time", "0").Run(); err != nil {
		fatalf("cannot configure the terminal with stty: %v", err)
	}
	u.mu.Lock()
	u.role, u.steps = role, steps
	u.w, u.h = termSize()
	u.prev = nil
	u.mu.Unlock()

	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l\x1b[2J") // alternate screen, hide cursor, clear
	u.started.Store(true)
	log.SetOutput(u)

	sc := make(chan os.Signal, 4)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGWINCH)
	signal.Ignore(syscall.SIGTSTP) // Ctrl-Z would leave the terminal in raw mode
	go func() {
		for s := range sc {
			if s == syscall.SIGWINCH {
				u.resize()
			} else {
				u.quit(0)
			}
		}
	}()

	go func() { // keyboard / paste reader
		buf := make([]byte, 65536)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				inCh <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				close(inCh)
				return
			}
		}
	}()
	go func() { // keeps spinners moving; unchanged frames cost nothing
		for range time.Tick(200 * time.Millisecond) {
			u.render()
		}
	}()
	u.render()
}

func (u *ui) restore() {
	u.restoreOnce.Do(func() {
		u.closed.Store(true)
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.started.Load() {
			os.Stdout.WriteString("\x1b[0m\x1b[?25h\x1b[?1049l")
			log.SetOutput(os.Stderr)
		}
		if u.saved != "" {
			sttyCmd(u.saved).Run()
		}
	})
}

func (u *ui) quit(code int) {
	u.restore()
	os.Exit(code)
}

func (u *ui) exit(msg string, code int) {
	u.restore()
	fmt.Fprintln(os.Stderr, "mcrtc: "+msg)
	os.Exit(code)
}

func (u *ui) resize() {
	u.mu.Lock()
	u.w, u.h = termSize()
	u.prev = nil // force a full repaint
	u.mu.Unlock()
	u.render()
}

// Write makes ui an io.Writer so the standard logger feeds the log pane.
func (u *ui) Write(p []byte) (int, error) {
	u.mu.Lock()
	for _, l := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
		u.logs = append(u.logs, strings.ReplaceAll(l, "\t", " "))
	}
	if len(u.logs) > 500 {
		u.logs = u.logs[len(u.logs)-500:]
	}
	u.mu.Unlock()
	u.render()
	return len(p), nil
}

// setStep switches to step i (0-based) with a new body and clears the input field.
func (u *ui) setStep(i int, body func(w int) []item) {
	u.mu.Lock()
	u.cur, u.body = i, body
	u.inText, u.inErr = "", ""
	u.mu.Unlock()
	u.render()
}

func (u *ui) setInput(text, errMsg string) {
	u.mu.Lock()
	u.inText, u.inErr = text, errMsg
	u.mu.Unlock()
	u.render()
}

// inputItems renders the text-entry line. It is called from body functions,
// i.e. with u.mu already held by render.
func (u *ui) inputItems(w int) []item {
	shown := strings.ToValidUTF8(u.inText, "?")
	if n := utf8.RuneCountInString(shown); n > w-10 {
		shown = sty(cGreen, fmt.Sprintf("(%d characters received, press Enter)", n))
	}
	its := []item{raw("  " + sty(cBold, "›") + " " + shown + sty("7", " "))}
	if u.inErr != "" {
		its = append(its, txt(cRed, "✗ "+u.inErr+". Try again."))
	}
	return its
}

func (u *ui) headerLine(w int) string {
	left := " MCRTC · Minecraft over WebRTC"
	right := u.role + " "
	pad := w - utf8.RuneCountInString(left) - utf8.RuneCountInString(right)
	if pad < 1 {
		left = " mcrtc"
		pad = w - utf8.RuneCountInString(left) - utf8.RuneCountInString(right)
	}
	if pad < 0 {
		pad = 0
	}
	return sty("1;7", left+strings.Repeat(" ", pad)+right)
}

func (u *ui) stepLine(w int) string {
	var parts []string
	for i, s := range u.steps {
		switch {
		case i < u.cur:
			parts = append(parts, sty("32", "✓ "+s))
		case i == u.cur:
			parts = append(parts, sty(cCyan, "● "+s))
		default:
			parts = append(parts, sty(cGray, "○ "+s))
		}
	}
	line := " " + strings.Join(parts, sty(cGray, " › "))
	if visLen(line) > w-1 && u.cur < len(u.steps) {
		line = " " + sty(cCyan, fmt.Sprintf("Step %d/%d: %s", u.cur+1, len(u.steps), u.steps[u.cur]))
	}
	return line
}

func (u *ui) render() {
	if !u.started.Load() || u.closed.Load() {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed.Load() || u.w < 1 || u.h < 1 {
		return
	}
	W, H := u.w, u.h

	var items []item
	if u.body != nil {
		items = u.body(W)
	}

	// Soft-wrapped lines (the blobs) are counted by arithmetic; keep a spare
	// row so a miscount can never scroll the screen.
	avail := H
	for _, it := range items {
		if it.kind == kRaw && visLen(it.text) > W {
			avail = H - 1
		}
	}

	showStep := true
	body := layoutBody(items, W, false)
	if 2+sumRows(body) > avail {
		body = layoutBody(items, W, true)
	}
	if 2+sumRows(body) > avail {
		showStep = false
	}
	chrome := 2
	if !showStep {
		chrome = 1
	}
	if chrome+sumRows(body) > avail {
		need := chrome + sumRows(body) + 1
		body = layoutBody([]item{
			txt(cRed, "Window too small"),
			txt("", fmt.Sprintf("This screen needs at least %d rows (the window has %d). Enlarge the window; it redraws automatically.", need, H)),
		}, W, false)
	}
	br := sumRows(body)

	leftover := avail - chrome - br
	spacer := false
	if showStep && leftover > 0 {
		spacer = true
		leftover--
	}
	logN := H / 4
	if logN < 3 {
		logN = 3
	}
	if logN > 8 {
		logN = 8
	}
	logN = imin(logN, leftover-1)

	lines := []fline{mk(u.headerLine(W), W)}
	if showStep {
		lines = append(lines, mk(u.stepLine(W), W))
	}
	if spacer {
		lines = append(lines, mk("", W))
	}
	lines = append(lines, body...)
	if logN >= 1 {
		for i := 0; i < leftover-(logN+1); i++ {
			lines = append(lines, mk("", W))
		}
		label := "── Log "
		lines = append(lines, mk(sty(cGray, label+strings.Repeat("─", imin(W-1, 500)-utf8.RuneCountInString(label))), W))
		tail := u.logs
		if len(tail) > logN {
			tail = tail[len(tail)-logN:]
		}
		for i := 0; i < logN-len(tail); i++ {
			lines = append(lines, mk("", W))
		}
		for _, l := range tail {
			lines = append(lines, mk(sty(cGray, " "+trunc(l, W-2)), W))
		}
	}
	u.flush(lines)
}

// flush writes only the lines that changed since the last frame, each at an
// absolute position. Nothing is cleared wholesale, so there is no flicker and
// a mouse selection over unchanged text (the blob) survives log updates.
func (u *ui) flush(lines []fline) {
	var sb strings.Builder
	full := u.prev == nil
	if full {
		sb.WriteString("\x1b[2J")
	}
	keys := make([]string, len(lines))
	row := 1
	for i, l := range lines {
		keys[i] = strconv.Itoa(row) + "|" + l.text
		if full || i >= len(u.prev) || u.prev[i] != keys[i] {
			fmt.Fprintf(&sb, "\x1b[%d;1H%s", row, l.text)
			if !l.noEL {
				sb.WriteString("\x1b[K")
			}
		}
		row += l.rows
	}
	if sb.Len() == 0 && len(lines) == len(u.prev) {
		return
	}
	if row <= u.h {
		fmt.Fprintf(&sb, "\x1b[%d;1H\x1b[J", row)
	}
	u.prev = keys
	os.Stdout.WriteString(sb.String())
}

// ---------- keyboard handling ----------

type editor struct {
	buf []byte
	esc int // 0 none, 1 after ESC, 2 inside a CSI sequence
}

type feedResult struct{ submit, quit, back bool }

func (e *editor) feed(chunk []byte, allowBack bool) (r feedResult) {
	for i, b := range chunk {
		switch {
		case e.esc == 1:
			if b == '[' || b == 'O' {
				e.esc = 2
			} else {
				e.esc = 0
			}
		case e.esc == 2:
			if b >= 0x40 && b <= 0x7e {
				e.esc = 0
			}
		case b == 0x1b:
			e.esc = 1
		case b == '\r' || b == '\n':
			// Only a newline at the very end of a read counts as "Enter";
			// newlines inside a pasted chunk are hard wraps and are ignored.
			if i == len(chunk)-1 {
				r.submit = true
			}
		case b == 0x7f || b == 0x08:
			if len(e.buf) > 0 {
				_, sz := utf8.DecodeLastRune(e.buf)
				e.buf = e.buf[:len(e.buf)-sz]
			}
		case b == 0x15: // Ctrl-U
			e.buf = e.buf[:0]
		case b == 0x04: // Ctrl-D on an empty line
			if len(e.buf) == 0 {
				r.quit = true
			}
		case b == 0x02: // Ctrl-B
			if allowBack {
				r.back = true
			}
		case b >= 0x20:
			e.buf = append(e.buf, b)
		}
	}
	return
}

func keyEnter(c []byte) bool { return bytes.ContainsAny(c, "\r\n") }
func keyQuit(c []byte) bool  { return bytes.ContainsAny(c, "qQ\x04") }

// drain swallows leftover input (e.g. the second half of a CRLF) for a moment.
func (u *ui) drain(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case _, ok := <-inCh:
			if !ok {
				return
			}
		case <-t.C:
			return
		}
	}
}

// askBlob lets the person paste a blob of the given kind. With allowBack, Ctrl-B
// returns (_, true) so the caller can show the previous screen again.
func (u *ui) askBlob(kind string, allowBack bool) (webrtc.SessionDescription, bool) {
	var ed editor
	u.setInput("", "")
	for {
		chunk, ok := <-inCh
		if !ok {
			u.quit(0)
		}
		res := ed.feed(chunk, allowBack)
		if res.quit {
			u.quit(0)
		}
		if res.back {
			return webrtc.SessionDescription{}, true
		}
		if res.submit {
			if strings.TrimSpace(string(ed.buf)) == "" {
				ed.buf = ed.buf[:0]
				continue
			}
			d, err := decodePasted(kind, string(ed.buf))
			if err == nil {
				u.drain(150 * time.Millisecond)
				return d, false
			}
			ed.buf = ed.buf[:0]
			u.setInput("", err.Error())
			continue
		}
		u.setInput(string(ed.buf), "")
	}
}

func (u *ui) waitEnter() {
	for c := range inCh {
		if keyQuit(c) {
			u.quit(0)
		}
		if keyEnter(c) {
			u.drain(100 * time.Millisecond)
			return
		}
	}
	u.quit(0)
}

// drainQuit keeps reading keys for the rest of the program; q quits.
func (u *ui) drainQuit() {
	for c := range inCh {
		if keyQuit(c) {
			u.quit(0)
		}
	}
	u.quit(0)
}

// ---------- host (Linux box running the server) ----------

type peerInfo struct {
	id    int
	state string
	path  string
	conns int
}

type peerList struct {
	mu   sync.Mutex
	list []*peerInfo
}

func (p *peerList) add(id int) *peerInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	pi := &peerInfo{id: id, state: "new"}
	p.list = append(p.list, pi)
	return pi
}

func (p *peerList) remove(pi *peerInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, x := range p.list {
		if x == pi {
			p.list = append(p.list[:i], p.list[i+1:]...)
			return
		}
	}
}

func (p *peerList) set(pi *peerInfo, f func(*peerInfo)) {
	p.mu.Lock()
	f(pi)
	p.mu.Unlock()
}

func (p *peerList) items() []item {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.list) == 0 {
		return nil
	}
	its := []item{gap(), txt(cBold, "Peers")}
	for _, pi := range p.list {
		col := "33"
		switch pi.state {
		case "connected":
			col = "32"
		case "failed", "closed":
			col = "31"
		}
		its = append(its, raw(sty(col, fmt.Sprintf("  peer %-3d %-12s %-8s %d tunnel(s)", pi.id, pi.state, pi.path, pi.conns))))
	}
	return its
}

// waitPeer waits for the friend to connect. Enter skips ahead to the next friend.
func (u *ui) waitPeer(connected, failed <-chan struct{}) string {
	for {
		select {
		case <-connected:
			return "connected"
		case <-failed:
			return "failed"
		case c, ok := <-inCh:
			if !ok || keyQuit(c) {
				u.quit(0)
			}
			if keyEnter(c) {
				return "skip"
			}
		}
	}
}

func runHost() {
	api := newAPI()
	log.Printf("host mode: forwarding tunnel connections to %s", *target)
	peers := &peerList{}
	notice := ""
	for n := 1; ; n++ {
		pc, err := api.NewPeerConnection(iceConfig())
		if err != nil {
			fatalf("%v", err)
		}
		id := n
		pi := peers.add(id)
		connected := make(chan struct{})
		failed := make(chan struct{})
		var cOnce, fOnce sync.Once
		pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
			log.Printf("[peer %d] connection state: %s", id, s)
			peers.set(pi, func(p *peerInfo) { p.state = s.String() })
			switch s {
			case webrtc.PeerConnectionStateConnected:
				path := logPath(pc, fmt.Sprintf("[peer %d]", id))
				peers.set(pi, func(p *peerInfo) { p.path = path })
				cOnce.Do(func() { close(connected) })
			case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
				fOnce.Do(func() { close(failed) })
				pc.Close()
			}
			tui.render()
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
				peers.set(pi, func(p *peerInfo) { p.conns++ })
				tui.render()
				go func() {
					pipe(raw, tcp)
					log.Printf("[peer %d] tunneled connection closed", id)
					peers.set(pi, func(p *peerInfo) { p.conns-- })
					tui.render()
				}()
			})
		})

		// Step 1: paste the friend's offer.
		note := notice
		notice = ""
		tui.setStep(0, func(w int) []item {
			its := []item{txt(cBold, fmt.Sprintf("Peer %d: paste your friend's OFFER", id))}
			if note != "" {
				its = append(its, txt(cYellow, note))
			}
			its = append(its, gap(),
				txt("", "Your friend runs MCRTC in client mode and gets a line starting with MCRTC.OFFER. Ask them to send it to you (chat, email, anything), paste it here and press Enter."),
				gap())
			its = append(its, tui.inputItems(w)...)
			its = append(its, peers.items()...)
			return its
		})
		offer, _ := tui.askBlob("OFFER", false)

		// Step 2: create and show the answer.
		tui.setStep(1, func(w int) []item {
			return []item{txt(cBold, spin()+" Creating the answer and gathering network candidates (up to 10 s)...")}
		})
		if err := pc.SetRemoteDescription(offer); err != nil {
			log.Printf("bad offer: %v", err)
			pc.Close()
			peers.remove(pi)
			n--
			notice = "That offer was rejected: " + err.Error()
			continue
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			fatalf("%v", err)
		}
		if err := pc.SetLocalDescription(answer); err != nil {
			fatalf("%v", err)
		}
		blob := encode("ANSWER", gather(pc))
		copied := toClipboard(blob)
		tui.setStep(1, func(w int) []item {
			its := []item{
				txt(cBold, "Send this ANSWER back to your friend:"),
				raw(sty(kindStyle("ANSWER"), blob)),
			}
			if copied {
				its = append(its, txt(cGreen, "✓ Copied to your clipboard"))
			}
			its = append(its, gap(),
				txt("", spin()+" Waiting for your friend to connect..."),
				txt(cGray, "Enter: accept another friend meanwhile    q: quit"))
			return its
		})

		switch tui.waitPeer(connected, failed) {
		case "connected":
			// Step 3: connected overview.
			tui.setStep(2, func(w int) []item {
				its := []item{
					txt(cGreen, fmt.Sprintf("✓ Peer %d is connected", id)),
					gap(),
					txt("", fmt.Sprintf("Tunnel traffic from your friends is forwarded to %s.", *target)),
				}
				its = append(its, peers.items()...)
				its = append(its, gap(), txt(cGray, "Enter: accept another friend    q or Ctrl-C: quit"))
				return its
			})
			tui.waitEnter()
		case "failed":
			notice = fmt.Sprintf("Peer %d failed to connect (NAT traversal usually). You can try again.", id)
		}
	}
}

// ---------- client (friend's machine) ----------

func runClient() {
	tui.setStep(0, func(w int) []item {
		return []item{txt(cBold, spin()+" Creating the offer and gathering network candidates (up to 10 s)...")}
	})

	pc, err := newAPI().NewPeerConnection(iceConfig())
	if err != nil {
		fatalf("%v", err)
	}
	connected := make(chan struct{})
	failed := make(chan struct{})
	var up atomic.Bool
	var failOnce sync.Once
	var path atomic.Value // string
	path.Store("")
	var tunnels int32
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		log.Printf("connection state: %s", s)
		switch s {
		case webrtc.PeerConnectionStateConnected:
			if up.CompareAndSwap(false, true) {
				path.Store(logPath(pc, "client"))
				close(connected)
			}
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			if up.Load() {
				tui.exit("tunnel lost, exiting", 1)
			}
			failOnce.Do(func() { close(failed) })
		}
		tui.render()
	})

	// A first channel is needed so the offer contains a data-channel section.
	if _, err := pc.CreateDataChannel("ctrl", nil); err != nil {
		fatalf("%v", err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		fatalf("%v", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		fatalf("%v", err)
	}
	blob := encode("OFFER", gather(pc))
	copied := toClipboard(blob)

	var answer webrtc.SessionDescription
	for {
		// Step 2: show the offer.
		tui.setStep(1, func(w int) []item {
			its := []item{
				txt(cBold, "Send this OFFER to the host:"),
				raw(sty(kindStyle("OFFER"), blob)),
			}
			if copied {
				its = append(its, txt(cGreen, "✓ Copied to your clipboard"))
			}



			its = append(its,
				gap(),
				txt("", "Send it by chat or email, and wait for an answer."),
				gap(),
				gap(),
				txt(cBold, "Paste the host's ANSWER"),
				gap(),
				txt("", "The host replies with a line starting with MCRTC.ANSWER. Paste it here and press Enter."),
				gap())

			its = append(its, tui.inputItems(w)...)
			its = append(its, gap(), txt(cGray, "Ctrl-C: quit"))
			return its
		})
		a, back := tui.askBlob("ANSWER", true)
		if !back {
			answer = a
			break
		}
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		fatalf("%v", err)
	}

	// Step 4: wait for the peer connection.
	start := time.Now()
	tui.setStep(2, func(w int) []item {
		return []item{
			txt(cBold, fmt.Sprintf("%s Connecting to the host (%d s of 30 s)...", spin(), int(time.Since(start).Seconds()))),
			gap(),
			txt(cGray, "This is the NAT traversal step. If it fails, try a TURN server (-turn / -turn-config)."),
		}
	})
	select {
	case <-connected:
	case <-failed:
		fatalf("connection failed: NAT traversal did not work. Try a TURN server (-turn or -turn-config)")
	case <-time.After(30 * time.Second):
		fatalf("timed out waiting for the peer connection (NAT traversal probably failed)")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatalf("%v", err)
	}
	log.Printf("tunnel up. Point Minecraft at %s", *listen)

	// Step 5: play.
	tui.setStep(3, func(w int) []item {
		pathStr, _ := path.Load().(string)
		return []item{
			txt(cGreen, "✓ Tunnel is up"),
			gap(),
			txt("", "In Minecraft choose Multiplayer, Add Server, and enter this server address:"),
			raw("    " + sty(cCyan, *listen)),
			gap(),
			raw(fmt.Sprintf("  Connection path:        %s", pathStr)),
			raw(fmt.Sprintf("  Active Minecraft links: %d", atomic.LoadInt32(&tunnels))),
			gap(),
			txt(cGray, "q or Ctrl-C: quit"),
		}
	})
	go tui.drainQuit()

	for {
		c, err := ln.Accept()
		if err != nil {
			fatalf("%v", err)
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
				atomic.AddInt32(&tunnels, 1)
				tui.render()
				go func() {
					pipe(raw, c)
					atomic.AddInt32(&tunnels, -1)
					tui.render()
				}()
			})
		}(c)
	}
}
