DISCLAIMER: this is vibecoded and intended for personal use. Do not use this in production!

# mctunnel

Bare-bones WebRTC TCP tunnel for Minecraft (Java) with copy/paste signaling.
Untested as shipped: it has not been compiled or run yet.

## Build (needs Go 1.22+ and internet access for the first build)

    mkdir mctunnel && cd mctunnel        # put main.go and go.mod here
    go mod tidy                          # downloads pion/webrtc
    go build -o mctunnel .                                         # Linux
    GOOS=darwin GOARCH=arm64 go build -o mctunnel-mac-arm64 .      # Apple Silicon
    GOOS=darwin GOARCH=amd64 go build -o mctunnel-mac-intel .      # Intel Mac

## Run

Host (you, Linux), with the Minecraft server already running on 25565:

    ./mctunnel -mode host

Client (friend, macOS):

    chmod +x mctunnel-mac-arm64
    xattr -d com.apple.quarantine mctunnel-mac-arm64   # only if downloaded via browser
    ./mctunnel-mac-arm64 -mode client

Handshake:
1. Client prints an OFFER blob. Friend sends it to you (Discord, etc.).
2. Paste it into the host prompt. Host prints an ANSWER blob.
3. Send the ANSWER back; friend pastes it into the client prompt.
4. Client prints "tunnel up". Friend adds `localhost` (port 25565) in Minecraft.

For another friend, paste their offer into the same host process. It loops.

## Useful flags

    -target 127.0.0.1:25565   host: where the real server listens
    -listen 127.0.0.1:25565   client: local port Minecraft connects to
    -stun "" / -turn ""       disable STUN / TURN
    -turn-user U -turn-pass P use your own TURN credentials

## Notes

- Default TURN is Metered's Open Relay static-auth host with its published
  shared secret. I could not verify that it still accepts anonymous use, and
  free TURN is rate-limited, so treat it as best-effort. Without a working
  TURN, a connection only succeeds if hole punching works.
- Everything is encrypted (DTLS) end to end, even when relayed.
- Terminals cut pasted lines at about 4095 characters. The blobs are
  gzip-compressed and normally well under that (length is printed).
- Java Edition only (TCP). Bedrock (UDP) would need an unreliable data channel mode.
