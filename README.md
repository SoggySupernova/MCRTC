DISCLAIMER: this is vibecoded and intended for personal use. Do not use this in production!

# MCRTC

Bare-bones WebRTC TCP tunnel for Minecraft (Java) with copy/paste signaling.
Untested as shipped: it has not been compiled or run yet.

## Build (needs Go 1.22+ and internet access for the first build)

    go mod tidy                          # downloads pion/webrtc
    go build -o mcrtc .            # don't forget the dot there!

## Run

Host, with the Minecraft server already running on port 25565:

    ./mcrtc -mode host

Client:

    ./mcrtc -mode client

Handshake:
1. Client prints an OFFER (one line starting `MCRTC.OFFER.`; also copied to the clipboard when possible). Friend sends it to you (Discord, etc.).
2. Paste it into the host prompt. Host prints an ANSWER (`MCRTC.ANSWER.`).
3. Send the ANSWER back; friend pastes it into the client prompt.
4. Client prints "tunnel up". Friend adds `localhost` (port 25565) in Minecraft.


For another friend, paste their offer into the same host process. It loops.

## Useful flags

    -target 127.0.0.1:25565   host: where the real server listens
    -listen 127.0.0.1:25565   client: local port Minecraft connects to
    -stun "" / -turn ""       disable STUN / TURN
    -turn-user U -turn-pass P use your own TURN credentials

## Notes
 
- Default TURN is Metered's Open Relay (`openrelay.metered.ca`, user/pass `openrelayproject`).
  Free public TURN is rate-limited and can change or disappear; for anything lasting use
  your own credentials (`-turn-user`, `-turn-pass`, `-turn`). `-turn-secret` is only for
  servers that use shared-secret (time-limited) credentials.
- Everything is encrypted (DTLS) end to end, even when relayed.
- Terminals cut pasted lines at about 4095 characters. The blobs are
  gzip-compressed and normally well under that (length is printed).
- Java Edition only (TCP). Bedrock (UDP) would need an unreliable data channel mode.

