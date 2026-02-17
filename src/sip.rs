/// SIP User Agent state machine.
///
/// Supports UDP and TLS transports.
/// Handles REGISTER, INVITE, BYE, ACK, CANCEL flows with digest authentication.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;

use crate::codec::Codec;
use crate::resample::{LinearResampler, ResampleBuffer, FRAME_SAMPLES, INTERNAL_RATE};
use crate::sdp;
use crate::srtp::SrtpContext;

/// SIP transport protocol.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Transport {
    /// Plain UDP (typically port 5060).
    Udp,
    /// TLS over TCP (typically port 5061).
    Tls,
}

impl Transport {
    fn via_transport(self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tls => "TLS",
        }
    }

    fn uri_scheme(self) -> &'static str {
        match self {
            Transport::Udp => "sip",
            Transport::Tls => "sip", // SIPS uses "sips" but most servers accept "sip" with transport=tls
        }
    }
}

/// Commands sent TO the library.
#[derive(Debug)]
pub enum VoipCommand {
    /// Dial a SIP URI.
    Call(String),
    /// Answer an incoming call.
    Answer,
    /// Hang up the current call.
    Hangup,
    /// Send a DTMF digit.
    SendDtmf(char),
    /// Place the current call on hold (sends re-INVITE with `a=sendonly`).
    Hold,
    /// Resume a held call (sends re-INVITE with `a=sendrecv`).
    Unhold,
    /// Blind transfer: ask the remote party to call `target`.
    /// Sends a SIP REFER (RFC 3515).
    Transfer(String),
    /// Attended transfer: transfer the current call to the specified
    /// `call_id` (another active dialog). The library sends REFER with
    /// a `Replaces` header so the two remote parties are connected.
    AttendedTransfer {
        /// Call-ID of the other active dialog to bridge.
        target_call_id: String,
    },
    /// Unregister and shut down.
    Quit,
}

/// Events emitted by the library.
///
/// The consumer receives these through the `event_rx` channel passed to
/// [`SipClient::run`]. Events arrive in chronological order. A typical
/// outgoing call sequence is: `Registered` -> `Ringing` -> `CallConnected`
/// -> `CallEnded`. An incoming call sequence is: `Registered` ->
/// `IncomingCall` -> (consumer sends `VoipCommand::Answer`) ->
/// `CallConnected` -> `CallEnded`.
#[derive(Debug)]
pub enum VoipEvent {
    /// SIP registration succeeded. The client can now make and receive calls.
    Registered,
    /// SIP registration failed (e.g. bad credentials).
    RegistrationFailed(String),
    /// An incoming INVITE was received. The consumer should send
    /// `VoipCommand::Answer` or `VoipCommand::Hangup`.
    IncomingCall {
        /// The SIP From header of the caller.
        from: String,
    },
    /// The remote side is ringing (180/183 received).
    Ringing,
    /// A call has been established. Audio channels are provided for the
    /// consumer to bridge to its audio source and sink.
    ///
    /// Audio format: mono f32 in `[-1.0, 1.0]`, at the rate set by
    /// [`VoipConfig::io_sample_rate`] (default 16 kHz) and frame duration is
    /// set by [`VoipConfig::io_frame_ms`] (default 20 ms).
    /// The channels are dropped when the call ends.
    CallConnected {
        /// Send mono f32 frames here (your mic/source -> remote peer).
        audio_tx: mpsc::Sender<Vec<f32>>,
        /// Receive mono f32 frames here (remote peer -> your speaker/sink).
        audio_rx: mpsc::Receiver<Vec<f32>>,
    },
    /// The call has ended (local hangup, remote BYE, or CANCEL).
    CallEnded,
    /// The call attempt failed (server rejection, timeout, etc.).
    CallFailed { reason: String },
    /// An in-band DTMF digit was received from the remote peer (RFC 4733).
    DtmfReceived(char),
    /// The current call was placed on hold (local or remote).
    CallHeld,
    /// A held call was resumed.
    CallResumed,
    /// Result of a REFER (transfer) request.
    TransferResult {
        /// `true` if the transfer succeeded (202 Accepted + NOTIFY 200).
        success: bool,
        /// Human-readable reason.
        reason: String,
    },
}

/// Configuration for creating a [`SipClient`].
pub struct VoipConfig {
    /// Resolved SIP server socket address.
    pub server_addr: SocketAddr,
    /// SIP username (the part before `@` in `sip:user@realm`).
    pub username: String,
    /// SIP password for digest authentication.
    pub password: String,
    /// SIP realm / domain (used in From/To URIs and auth).
    pub realm: String,
    /// Transport protocol (UDP or TLS).
    pub transport: Transport,
    /// Server hostname for TLS SNI (without port).
    pub hostname: String,
    /// STUN server address for NAT traversal (e.g. `"stun.l.google.com:19302"`).
    /// Set to `None` to disable STUN; UPnP will still be attempted.
    pub stun_server: Option<String>,
    /// Sample rate for the audio channels in [`VoipEvent::CallConnected`].
    ///
    /// The library resamples between this rate and the internal 16 kHz.
    /// Defaults to 16000 (no resampling).
    pub io_sample_rate: u32,
    /// Frame duration in milliseconds for the audio channels.
    ///
    /// Each `Vec<f32>` delivered through the audio channels will contain
    /// `io_sample_rate * io_frame_ms / 1000` samples. For example, 10 ms
    /// at 16 kHz = 160 samples, 20 ms at 48 kHz = 960 samples.
    ///
    /// Defaults to 20.
    pub io_frame_ms: u32,
}

#[derive(Debug, PartialEq)]
enum RegState {
    Unregistered,
    Challenged,
    Registered,
}

#[derive(Debug, PartialEq)]
enum CallState {
    Idle,
    InviteSent,
    Ringing,
    InCall,
    IncomingRinging,
    /// Call is on hold (we sent a=sendonly or received a=inactive).
    Held,
}

/// SIP transport layer — either UDP socket or TLS stream.
enum SipTransport {
    Udp(UdpSocket, SocketAddr),
    Tls(TlsStream<TcpStream>),
}

/// SIP User Agent client.
///
/// Create with [`SipClient::new`], then call [`SipClient::run`] to start
/// the event loop. The client registers with the server, handles incoming
/// and outgoing calls, and emits [`VoipEvent`]s. Send [`VoipCommand`]s to
/// control it.
///
/// The client is `Send` and can be spawned into a tokio task.
pub struct SipClient {
    transport: SipTransport,
    transport_type: Transport,
    server_addr: SocketAddr,
    local_ip: IpAddr,
    local_port: u16,

    username: String,
    password: String,
    realm: String,

    reg_state: RegState,
    reg_cseq: u32,
    reg_call_id: String,
    reg_expires_at: Option<Instant>,

    call_state: CallState,
    call_cseq: u32,
    call_id: Option<String>,
    local_tag: Option<String>,
    remote_tag: Option<String>,
    invite_target: Option<String>,

    auth_nonce: Option<String>,
    auth_realm: Option<String>,
    auth_opaque: Option<String>,
    auth_qop: Option<String>,
    auth_nc: u32,

    rtp_port: u16,
    codec: Codec,
    rtp_shutdown: Option<tokio::sync::oneshot::Sender<()>>,

    /// Channel for emitting events to the consumer.
    event_tx: Option<mpsc::Sender<VoipEvent>>,

    incoming_from: Option<String>,
    incoming_to: Option<String>,
    incoming_via: Option<String>,
    incoming_contact: Option<String>,
    incoming_sdp: Option<String>,
    incoming_cseq: Option<u32>,

    // Session timers (RFC 4028)
    session_expires_at: Option<Instant>,
    session_interval: u32,
    min_se: u32,

    // DTMF sender channel (to RTP task)
    dtmf_tx: Option<mpsc::Sender<char>>,

    /// SRTP local key material (master key + salt, generated per call).
    srtp_local_key: Option<([u8; 16], [u8; 14])>,
    /// Formatted `a=crypto` attribute value for our SDP (e.g. "1 AES_CM_128_HMAC_SHA1_80 inline:<b64>")
    srtp_local_attr: Option<String>,
    /// Remote SRTP crypto attribute value parsed from their SDP
    srtp_remote_crypto: Option<String>,

    // TLS reconnection hostname
    tls_hostname: String,

    // STUN-discovered public address
    pub stun_server: Option<String>,
    pub public_addr: Option<SocketAddr>,

    // TCP/TLS read buffer for message framing
    tcp_buf: Vec<u8>,

    // I/O sample rate for consumer audio channels
    io_sample_rate: u32,
    // I/O frame duration in ms
    io_frame_ms: u32,
}

impl SipClient {
    /// Create a new SIP client.
    ///
    /// Connects to the server (UDP bind or TLS handshake) and discovers the
    /// local IP address. Does **not** register yet — registration happens
    /// when [`run`](Self::run) is called.
    pub async fn new(config: VoipConfig) -> Result<Self> {
        let server_addr = config.server_addr;
        let username = config.username;
        let password = config.password;
        let realm = config.realm;
        let transport_type = config.transport;
        let hostname = config.hostname;
        let stun_server = config.stun_server;
        let io_sample_rate = config.io_sample_rate;
        let io_frame_ms = config.io_frame_ms;
        // Discover our local IP toward the server using a temporary UDP connect
        let local_ip = {
            let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
            probe.connect(server_addr)?;
            probe.local_addr()?.ip()
        };

        let (transport, local_port) = match transport_type {
            Transport::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                let port = socket.local_addr()?.port();
                (SipTransport::Udp(socket, server_addr), port)
            }
            Transport::Tls => {
                let tls_stream = connect_tls(server_addr, &hostname).await?;
                let port = tls_stream.get_ref().0.local_addr()?.port();
                (SipTransport::Tls(tls_stream), port)
            }
        };

        tracing::info!(
            "SIP {transport_type:?} bound to {local_ip}:{local_port}, server={server_addr}"
        );

        Ok(Self {
            transport,
            transport_type,
            server_addr,
            local_ip,
            local_port,
            username,
            password,
            realm,
            reg_state: RegState::Unregistered,
            reg_cseq: 0,
            reg_call_id: generate_call_id(),
            reg_expires_at: None,
            call_state: CallState::Idle,
            call_cseq: 0,
            call_id: None,
            local_tag: None,
            remote_tag: None,
            invite_target: None,
            auth_nonce: None,
            auth_realm: None,
            auth_opaque: None,
            auth_qop: None,
            auth_nc: 0,
            rtp_port: 0,
            codec: Codec::G722,
            rtp_shutdown: None,
            event_tx: None,
            incoming_from: None,
            incoming_to: None,
            incoming_via: None,
            incoming_contact: None,
            incoming_sdp: None,
            incoming_cseq: None,
            session_expires_at: None,
            session_interval: 1800,
            min_se: 90,
            dtmf_tx: None,
            srtp_local_key: None,
            srtp_local_attr: None,
            srtp_remote_crypto: None,
            tls_hostname: hostname,
            stun_server,
            public_addr: None,
            tcp_buf: Vec::with_capacity(65536),
            io_sample_rate,
            io_frame_ms,
        })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Transport send/recv
    // ═══════════════════════════════════════════════════════════════════════

    async fn send_sip(&mut self, data: &[u8]) -> Result<()> {
        if let Ok(text) = std::str::from_utf8(data) {
            tracing::debug!(">>> SIP OUT >>>\n{text}");
        }
        match &mut self.transport {
            SipTransport::Udp(socket, addr) => {
                socket.send_to(data, *addr).await?;
            }
            SipTransport::Tls(stream) => {
                stream.write_all(data).await?;
                stream.flush().await?;
            }
        }
        Ok(())
    }

    /// Run the SIP client event loop.
    ///
    /// Sends a REGISTER request and then loops, processing SIP messages,
    /// commands from `cmd_rx`, re-registration timers, and session timers.
    /// Returns when `VoipCommand::Quit` is received or a fatal error occurs.
    ///
    /// Events are emitted to `event_tx` as they occur. The consumer should
    /// read from the corresponding receiver to handle registration, incoming
    /// calls, call state changes, and DTMF digits.
    pub async fn run(
        &mut self,
        mut cmd_rx: mpsc::Receiver<VoipCommand>,
        event_tx: mpsc::Sender<VoipEvent>,
    ) -> Result<()> {
        self.event_tx = Some(event_tx);
        self.send_register(false).await?;

        let mut recv_buf = vec![0u8; 65535];

        loop {
            // Compute re-registration deadline (or far future if none)
            let rereg_deadline = self.reg_expires_at.unwrap_or_else(|| Instant::now() + Duration::from_secs(86400));

            // Compute session timer deadline
            let session_deadline = self.session_expires_at.unwrap_or_else(|| Instant::now() + Duration::from_secs(86400));

            tokio::select! {
                result = self.recv_sip_data(&mut recv_buf) => {
                    match result {
                        Ok(data) => {
                            if let Err(e) = self.handle_message(&data).await {
                                tracing::warn!("Error handling SIP message: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::error!("SIP recv error: {e}");
                            if self.transport_type == Transport::Tls {
                                // Attempt TLS reconnection
                                if let Err(re) = self.reconnect_tls().await {
                                    tracing::error!("TLS reconnect failed: {re}");
                                    return Err(e);
                                }
                            }
                        }
                    }
                }

                // Re-registration timer
                _ = tokio::time::sleep_until(rereg_deadline) => {
                    tracing::info!("Re-registration timer fired");
                    if let Err(e) = self.send_register(self.auth_nonce.is_some()).await {
                        tracing::error!("Re-registration failed: {e}");
                    }
                }

                // Session timer (re-INVITE keepalive)
                _ = tokio::time::sleep_until(session_deadline) => {
                    tracing::info!("Session timer fired, sending re-INVITE");
                    if let Err(e) = self.send_reinvite().await {
                        tracing::error!("Re-INVITE failed: {e}");
                    }
                }

                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        VoipCommand::Call(target) => {
                            if let Err(e) = self.initiate_call(&target).await {
                                tracing::error!("Call failed: {e}");
                                self.send_event(VoipEvent::CallFailed { reason: e.to_string() }).await;
                            }
                        }
                        VoipCommand::Answer => {
                            if let Err(e) = self.answer_incoming().await {
                                tracing::error!("Answer failed: {e}");
                                self.send_event(VoipEvent::CallFailed { reason: e.to_string() }).await;
                            }
                        }
                        VoipCommand::Hangup => {
                            if let Err(e) = self.hangup().await {
                                tracing::error!("Hangup failed: {e}");
                            }
                        }
                        VoipCommand::SendDtmf(digit) => {
                            if let Some(dtmf_tx) = &self.dtmf_tx {
                                let _ = dtmf_tx.send(digit).await;
                            }
                        }
                        VoipCommand::Hold => {
                            if let Err(e) = self.hold().await {
                                tracing::error!("Hold failed: {e}");
                            }
                        }
                        VoipCommand::Unhold => {
                            if let Err(e) = self.unhold().await {
                                tracing::error!("Unhold failed: {e}");
                            }
                        }
                        VoipCommand::Transfer(target) => {
                            if let Err(e) = self.send_refer(&target).await {
                                tracing::error!("Transfer failed: {e}");
                                self.send_event(VoipEvent::TransferResult {
                                    success: false,
                                    reason: e.to_string(),
                                }).await;
                            }
                        }
                        VoipCommand::AttendedTransfer { target_call_id } => {
                            if let Err(e) = self.send_attended_refer(&target_call_id).await {
                                tracing::error!("Attended transfer failed: {e}");
                                self.send_event(VoipEvent::TransferResult {
                                    success: false,
                                    reason: e.to_string(),
                                }).await;
                            }
                        }
                        VoipCommand::Quit => {
                            self.stop_media().await;
                            let _ = self.send_register_unregister().await;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    async fn recv_sip_data(&mut self, buf: &mut [u8]) -> Result<Vec<u8>> {
        match &mut self.transport {
            SipTransport::Udp(socket, _) => {
                let (len, _from) = socket.recv_from(buf).await?;
                Ok(buf[..len].to_vec())
            }
            SipTransport::Tls(stream) => {
                // TCP/TLS SIP framing: read until we have a complete message
                // A complete message has headers + \r\n\r\n + Content-Length bytes of body
                loop {
                    // Check if we already have a complete message in tcp_buf
                    if let Some(msg) = extract_complete_sip_message(&self.tcp_buf) {
                        let msg_len = msg.len();
                        let result = msg.to_vec();
                        self.tcp_buf.drain(..msg_len);
                        return Ok(result);
                    }

                    // Read more data
                    let n = stream.read(buf).await?;
                    if n == 0 {
                        return Err(anyhow!("TLS connection closed"));
                    }
                    self.tcp_buf.extend_from_slice(&buf[..n]);
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SDP address helper
    // ═══════════════════════════════════════════════════════════════════════

    /// Best IP to advertise in SDP: STUN public addr > local_ip
    fn sdp_ip(&self) -> IpAddr {
        self.public_addr.map(|a| a.ip()).unwrap_or(self.local_ip)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Via/Contact header helpers
    // ═══════════════════════════════════════════════════════════════════════

    fn via_header(&self, branch: &str) -> String {
        let proto = self.transport_type.via_transport();
        format!(
            "Via: SIP/2.0/{proto} {ip}:{port};rport;branch=z9hG4bK{branch}",
            ip = self.local_ip,
            port = self.local_port,
        )
    }

    fn contact_header(&self) -> String {
        let scheme = self.transport_type.uri_scheme();
        let transport_param = match self.transport_type {
            Transport::Tls => ";transport=tls",
            Transport::Udp => "",
        };
        format!(
            "Contact: <{scheme}:{user}@{ip}:{port}{transport_param}>",
            user = self.username,
            ip = self.local_ip,
            port = self.local_port,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Digest auth helper
    // ═══════════════════════════════════════════════════════════════════════

    fn build_auth_header(&mut self, method: &str, uri: &str) -> Option<String> {
        let nonce = self.auth_nonce.as_ref()?.clone();
        let auth_realm = self.auth_realm.as_ref()?.clone();

        self.auth_nc += 1;
        let cnonce = generate_cnonce();
        let qop_ref = self.auth_qop.as_deref();

        let response = compute_digest_response(
            &self.username, &auth_realm, &self.password,
            method, uri, &nonce, qop_ref, self.auth_nc, &cnonce,
        );

        let mut hdr = format!(
            "Authorization: Digest username=\"{user}\", realm=\"{auth_realm}\", \
             nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm=MD5",
            user = self.username,
        );

        if qop_ref.is_some() {
            hdr.push_str(&format!(
                ", qop=auth, nc={nc:08x}, cnonce=\"{cnonce}\"",
                nc = self.auth_nc,
            ));
        }

        if let Some(opaque) = &self.auth_opaque {
            hdr.push_str(&format!(", opaque=\"{opaque}\""));
        }

        hdr.push_str("\r\n");
        Some(hdr)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // REGISTER
    // ═══════════════════════════════════════════════════════════════════════

    async fn send_register(&mut self, with_auth: bool) -> Result<()> {
        self.reg_cseq += 1;
        let branch = generate_branch();

        let mut msg = format!(
            "REGISTER sip:{realm} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={tag}\r\n\
             To: <sip:{user}@{realm}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} REGISTER\r\n\
             {contact}\r\n\
             Max-Forwards: 70\r\n\
             Expires: 3600\r\n\
             Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, PRACK, REFER, NOTIFY\r\n\
             Supported: timer, 100rel\r\n",
            realm = self.realm,
            via = self.via_header(&branch),
            user = self.username,
            tag = generate_tag(),
            call_id = self.reg_call_id,
            cseq = self.reg_cseq,
            contact = self.contact_header(),
        );

        if with_auth {
            let uri = format!("sip:{}", self.realm);
            if let Some(auth_hdr) = self.build_auth_header("REGISTER", &uri) {
                msg.push_str(&auth_hdr);
            }
        }

        msg.push_str("Content-Length: 0\r\n\r\n");

        self.send_sip(msg.as_bytes()).await?;
        tracing::debug!("Sent REGISTER (auth={with_auth})");
        Ok(())
    }

    async fn send_register_unregister(&mut self) -> Result<()> {
        self.reg_cseq += 1;
        let branch = generate_branch();

        let mut msg = format!(
            "REGISTER sip:{realm} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={tag}\r\n\
             To: <sip:{user}@{realm}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} REGISTER\r\n\
             Contact: *\r\n\
             Max-Forwards: 70\r\n\
             Expires: 0\r\n",
            realm = self.realm,
            via = self.via_header(&branch),
            user = self.username,
            tag = generate_tag(),
            call_id = self.reg_call_id,
            cseq = self.reg_cseq,
        );

        let uri = format!("sip:{}", self.realm);
        if let Some(auth_hdr) = self.build_auth_header("REGISTER", &uri) {
            msg.push_str(&auth_hdr);
        }

        msg.push_str("Content-Length: 0\r\n\r\n");
        self.send_sip(msg.as_bytes()).await?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INVITE (outgoing call)
    // ═══════════════════════════════════════════════════════════════════════

    async fn initiate_call(&mut self, target: &str) -> Result<()> {
        if self.call_state != CallState::Idle {
            return Err(anyhow!("already in a call"));
        }

        let rtp_socket = crate::rtp::bind_rtp_socket().await?;
        self.rtp_port = rtp_socket.local_addr()?.port();

        // NAT traversal: discover public address for SDP
        let nat = crate::nat::discover(
            &rtp_socket,
            self.local_ip,
            self.stun_server.as_deref(),
        ).await;
        self.public_addr = Some(nat.public_addr);
        tracing::info!("NAT: {:?} -> {}", nat.method, nat.public_addr);
        drop(rtp_socket);

        let call_id = generate_call_id();
        let local_tag = generate_tag();
        self.call_id = Some(call_id.clone());
        self.local_tag = Some(local_tag.clone());
        self.remote_tag = None;
        self.invite_target = Some(target.to_string());
        self.call_cseq = 1;
        self.srtp_remote_crypto = None;
        self.generate_srtp();

        let sdp_body = sdp::build_offer(self.sdp_ip(), self.rtp_port, self.srtp_attr());

        let target_uri = if target.starts_with("sip:") {
            target.to_string()
        } else {
            format!("sip:{}@{}", target, self.realm)
        };

        let branch = generate_branch();
        let mut msg = format!(
            "INVITE {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} INVITE\r\n\
             {contact}\r\n\
             Max-Forwards: 70\r\n\
             Supported: timer, 100rel\r\n\
             Session-Expires: {se}\r\n\
             Min-SE: {min_se}\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {body_len}\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
            contact = self.contact_header(),
            se = self.session_interval,
            min_se = self.min_se,
            body_len = sdp_body.len(),
        );

        if let Some(auth_hdr) = self.build_auth_header("INVITE", &target_uri) {
            msg.push_str(&auth_hdr);
        }

        msg.push_str("\r\n");
        msg.push_str(&sdp_body);

        self.send_sip(msg.as_bytes()).await?;
        self.call_state = CallState::InviteSent;
        tracing::info!("Sent INVITE to {target_uri}");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Answer incoming call
    // ═══════════════════════════════════════════════════════════════════════

    async fn answer_incoming(&mut self) -> Result<()> {
        if self.call_state != CallState::IncomingRinging {
            return Err(anyhow!("no incoming call to answer"));
        }

        let incoming_sdp = self.incoming_sdp.as_ref().ok_or(anyhow!("no SDP in INVITE"))?;
        let remote_offer = sdp::parse_offer(incoming_sdp)?;
        let (remote_rtp_addr, codec) = (
            SocketAddr::new(remote_offer.ip, remote_offer.port),
            remote_offer.codecs.first().map(|&(_, c)| c).unwrap_or(Codec::Ulaw),
        );
        self.codec = codec;

        // SRTP: store remote crypto, generate our own
        self.srtp_remote_crypto = remote_offer.crypto.clone();
        self.generate_srtp();

        let rtp_socket = crate::rtp::bind_rtp_socket().await?;
        self.rtp_port = rtp_socket.local_addr()?.port();

        // NAT traversal for incoming call answer
        let nat = crate::nat::discover(
            &rtp_socket,
            self.local_ip,
            self.stun_server.as_deref(),
        ).await;
        self.public_addr = Some(nat.public_addr);
        tracing::info!("NAT: {:?} -> {}", nat.method, nat.public_addr);
        drop(rtp_socket);

        let sdp_body = sdp::build_answer(self.sdp_ip(), self.rtp_port, &remote_offer, self.srtp_attr());

        let call_id = self.call_id.as_ref().unwrap();
        let local_tag = self.local_tag.as_ref().unwrap();
        let from_hdr = self.incoming_from.as_deref().unwrap_or("");
        let to_hdr = self.incoming_to.as_deref().unwrap_or("");
        let via_hdr = self.incoming_via.as_deref().unwrap_or("");
        let cseq_num = self.incoming_cseq.unwrap_or(1);

        let msg = format!(
            "SIP/2.0 200 OK\r\n\
             Via: {via_hdr}\r\n\
             From: {from_hdr}\r\n\
             To: {to_hdr};tag={local_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq_num} INVITE\r\n\
             {contact}\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {body_len}\r\n\
             \r\n\
             {sdp_body}",
            contact = self.contact_header(),
            body_len = sdp_body.len(),
        );

        self.send_sip(msg.as_bytes()).await?;
        self.call_state = CallState::InCall;
        self.start_media(remote_rtp_addr).await?;

        tracing::info!("Answered incoming call, codec={:?}", self.codec);
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Hangup
    // ═══════════════════════════════════════════════════════════════════════

    async fn hangup(&mut self) -> Result<()> {
        match self.call_state {
            CallState::InCall | CallState::Held => {
                self.send_bye().await?;
            }
            CallState::IncomingRinging => {
                self.send_decline().await?;
            }
            CallState::InviteSent | CallState::Ringing => {
                self.send_cancel().await?;
            }
            CallState::Idle => {
                return Ok(());
            }
        }
        self.stop_media().await;
        self.call_state = CallState::Idle;
        self.call_id = None;
        self.local_tag = None;
        self.remote_tag = None;
        Ok(())
    }

    async fn send_bye(&mut self) -> Result<()> {
        self.call_cseq += 1;
        let call_id = self.call_id.as_ref().unwrap().clone();
        let local_tag = self.local_tag.as_ref().unwrap().clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let raw_uri = self.incoming_contact.as_deref()
            .or(self.invite_target.as_deref())
            .unwrap_or(&default_uri)
            .to_string();

        let target_uri = if raw_uri.starts_with("sip:") || raw_uri.starts_with("<sip:") {
            raw_uri.trim_matches(|c| c == '<' || c == '>').to_string()
        } else {
            format!("sip:{}@{}", raw_uri, self.realm)
        };

        let branch = generate_branch();
        let msg = format!(
            "BYE {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>;tag={remote_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} BYE\r\n\
             Max-Forwards: 70\r\n\
             Content-Length: 0\r\n\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
        );

        self.send_sip(msg.as_bytes()).await?;
        tracing::info!("Sent BYE");
        Ok(())
    }

    async fn send_cancel(&mut self) -> Result<()> {
        let call_id = self.call_id.as_ref().unwrap().clone();
        let local_tag = self.local_tag.as_ref().unwrap().clone();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let target_uri = self.invite_target.as_deref().unwrap_or(&default_uri).to_string();

        let branch = generate_branch();
        let msg = format!(
            "CANCEL {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 CANCEL\r\n\
             Max-Forwards: 70\r\n\
             Content-Length: 0\r\n\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
        );

        self.send_sip(msg.as_bytes()).await?;
        tracing::info!("Sent CANCEL");
        Ok(())
    }

    async fn send_decline(&mut self) -> Result<()> {
        let call_id = self.call_id.as_ref().unwrap().clone();
        let local_tag = self.local_tag.as_ref().unwrap().clone();
        let from_hdr = self.incoming_from.as_deref().unwrap_or("").to_string();
        let to_hdr = self.incoming_to.as_deref().unwrap_or("").to_string();
        let via_hdr = self.incoming_via.as_deref().unwrap_or("").to_string();

        let msg = format!(
            "SIP/2.0 603 Decline\r\n\
             Via: {via_hdr}\r\n\
             From: {from_hdr}\r\n\
             To: {to_hdr};tag={local_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n",
        );

        self.send_sip(msg.as_bytes()).await?;
        tracing::info!("Sent 603 Decline");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ACK
    // ═══════════════════════════════════════════════════════════════════════

    async fn send_ack(&mut self, target_uri: &str) -> Result<()> {
        let call_id = self.call_id.as_ref().unwrap().clone();
        let local_tag = self.local_tag.as_ref().unwrap().clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let to_tag = if remote_tag.is_empty() {
            String::new()
        } else {
            format!(";tag={remote_tag}")
        };

        let branch = generate_branch();
        let msg = format!(
            "ACK {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} ACK\r\n\
             Max-Forwards: 70\r\n\
             Content-Length: 0\r\n\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
        );

        self.send_sip(msg.as_bytes()).await?;
        tracing::debug!("Sent ACK");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TLS reconnection
    // ═══════════════════════════════════════════════════════════════════════

    async fn reconnect_tls(&mut self) -> Result<()> {
        if self.transport_type != Transport::Tls {
            return Err(anyhow!("not a TLS connection"));
        }

        let mut delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(30);

        for attempt in 1..=5 {
            tracing::info!("TLS reconnect attempt {attempt}, delay={delay:?}");
            tokio::time::sleep(delay).await;

            match connect_tls(self.server_addr, &self.tls_hostname).await {
                Ok(tls_stream) => {
                    self.local_port = tls_stream.get_ref().0.local_addr()?.port();
                    self.transport = SipTransport::Tls(tls_stream);
                    self.tcp_buf.clear();
                    tracing::info!("TLS reconnected, re-registering");
                    // Re-register with auth if we have credentials
                    self.reg_state = RegState::Unregistered;
                    self.send_register(self.auth_nonce.is_some()).await?;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("TLS reconnect attempt {attempt} failed: {e}");
                    delay = (delay * 2).min(max_delay);
                }
            }
        }

        Err(anyhow!("TLS reconnection failed after 5 attempts"))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Session timer / re-INVITE (RFC 4028)
    // ═══════════════════════════════════════════════════════════════════════

    async fn send_reinvite(&mut self) -> Result<()> {
        if self.call_state != CallState::InCall {
            self.session_expires_at = None;
            return Ok(());
        }

        let call_id = self.call_id.as_ref().ok_or(anyhow!("no call_id"))?.clone();
        let local_tag = self.local_tag.as_ref().ok_or(anyhow!("no local_tag"))?.clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let target_uri = self.invite_target.as_deref()
            .or(self.incoming_contact.as_deref())
            .unwrap_or(&default_uri)
            .to_string();

        let target_uri = if target_uri.starts_with("sip:") || target_uri.starts_with("<sip:") {
            target_uri.trim_matches(|c| c == '<' || c == '>').to_string()
        } else {
            format!("sip:{}@{}", target_uri, self.realm)
        };

        self.call_cseq += 1;
        let sdp_body = sdp::build_offer(self.sdp_ip(), self.rtp_port, self.srtp_attr());
        let branch = generate_branch();

        let to_tag = if remote_tag.is_empty() { String::new() } else { format!(";tag={remote_tag}") };

        let mut msg = format!(
            "INVITE {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} INVITE\r\n\
             {contact}\r\n\
             Max-Forwards: 70\r\n\
             Supported: timer, 100rel\r\n\
             Session-Expires: {se};refresher=uac\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {body_len}\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
            contact = self.contact_header(),
            se = self.session_interval,
            body_len = sdp_body.len(),
        );

        if let Some(auth_hdr) = self.build_auth_header("INVITE", &target_uri) {
            msg.push_str(&auth_hdr);
        }

        msg.push_str("\r\n");
        msg.push_str(&sdp_body);

        self.send_sip(msg.as_bytes()).await?;
        tracing::info!("Sent re-INVITE for session refresh");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PRACK (RFC 3262)
    // ═══════════════════════════════════════════════════════════════════════

    async fn send_prack(&mut self, rseq: u32, cseq_num: u32) -> Result<()> {
        let call_id = self.call_id.as_ref().ok_or(anyhow!("no call_id"))?.clone();
        let local_tag = self.local_tag.as_ref().ok_or(anyhow!("no local_tag"))?.clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let target_uri = self.invite_target.as_deref().unwrap_or(&default_uri).to_string();

        let to_tag = if remote_tag.is_empty() { String::new() } else { format!(";tag={remote_tag}") };

        self.call_cseq += 1;
        let branch = generate_branch();

        let msg = format!(
            "PRACK {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} PRACK\r\n\
             RAck: {rseq} {cseq_num} INVITE\r\n\
             Max-Forwards: 70\r\n\
             Content-Length: 0\r\n\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
        );

        self.send_sip(msg.as_bytes()).await?;
        tracing::debug!("Sent PRACK for RSeq {rseq}");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SRTP helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Generate local SRTP key material and return the `a=crypto` attribute value.
    fn generate_srtp(&mut self) -> String {
        let (key, salt) = SrtpContext::generate_key_salt();
        let b64 = SrtpContext::key_salt_to_base64(&key, &salt);
        let attr = format!("1 AES_CM_128_HMAC_SHA1_80 inline:{b64}");
        self.srtp_local_key = Some((key, salt));
        self.srtp_local_attr = Some(attr.clone());
        attr
    }

    /// Build SRTP send/recv contexts from local key and remote crypto attribute.
    /// Returns (send_ctx, recv_ctx) or (None, None) if crypto exchange is incomplete.
    fn build_srtp_contexts(&self) -> (Option<SrtpContext>, Option<SrtpContext>) {
        let local = match &self.srtp_local_key {
            Some(k) => k,
            None => return (None, None),
        };
        let remote_attr = match &self.srtp_remote_crypto {
            Some(a) => a,
            None => return (None, None),
        };
        // Parse remote crypto: "1 AES_CM_128_HMAC_SHA1_80 inline:<b64>"
        let remote_key_salt = remote_attr
            .split("inline:")
            .nth(1)
            .and_then(|b64| SrtpContext::parse_key_salt(b64.trim()));
        match remote_key_salt {
            Some((rkey, rsalt)) => {
                let send_ctx = SrtpContext::new(&local.0, &local.1);
                let recv_ctx = SrtpContext::new(&rkey, &rsalt);
                (Some(send_ctx), Some(recv_ctx))
            }
            None => {
                tracing::warn!("Failed to parse remote SRTP crypto attribute");
                (None, None)
            }
        }
    }

    /// Get the local crypto attribute for SDP, if available.
    fn srtp_attr(&self) -> Option<&str> {
        self.srtp_local_attr.as_deref()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Media start/stop
    // ═══════════════════════════════════════════════════════════════════════

    async fn start_media(&mut self, remote_addr: SocketAddr) -> Result<()> {
        // Create per-call audio channels (RTP side, always 16 kHz)
        let (mic_tx, mic_rx) = mpsc::channel::<Vec<f32>>(32);
        let (spk_tx, mut spk_rx) = mpsc::channel::<Vec<f32>>(32);

        let (dtmf_tx, dtmf_rx) = mpsc::channel::<char>(16);
        self.dtmf_tx = Some(dtmf_tx);

        let event_tx_for_rtp = self.event_tx.clone();
        let (srtp_send, srtp_recv) = self.build_srtp_contexts();
        let (rtp_port, shutdown_tx) =
            crate::rtp::start_session(remote_addr, self.codec, mic_rx, spk_tx, dtmf_rx, event_tx_for_rtp, srtp_send, srtp_recv).await?;

        self.rtp_port = rtp_port;
        self.rtp_shutdown = Some(shutdown_tx);
        let srtp_status = if self.srtp_remote_crypto.is_some() { "SRTP" } else { "RTP" };
        tracing::info!("Media started: {srtp_status} port={rtp_port}, remote={remote_addr}");

        // Build consumer-facing channels, resampling/reframing if needed
        let io_rate = self.io_sample_rate;
        let io_frame = (io_rate as usize) * (self.io_frame_ms as usize) / 1000;
        let needs_bridge = io_rate != INTERNAL_RATE || io_frame != FRAME_SAMPLES;

        if !needs_bridge {
            // No resampling or reframing — hand channels directly to consumer
            self.send_event(VoipEvent::CallConnected {
                audio_tx: mic_tx,
                audio_rx: spk_rx,
            }).await;
        } else {
            let (user_mic_tx, mut user_mic_rx) = mpsc::channel::<Vec<f32>>(32);
            let (user_spk_tx, user_spk_rx) = mpsc::channel::<Vec<f32>>(32);

            // Mic bridge: user io_rate -> resample -> 16 kHz 320-sample frames -> RTP
            tokio::spawn(async move {
                let mut resampler = LinearResampler::new(io_rate, INTERNAL_RATE);
                let mut resampled = Vec::new();
                let mut acc = ResampleBuffer::new(INTERNAL_RATE as usize);
                let mut frame = vec![0.0f32; FRAME_SAMPLES];
                while let Some(data) = user_mic_rx.recv().await {
                    resampler.process(&data, &mut resampled);
                    acc.push(&resampled);
                    while acc.pop_exact(&mut frame) {
                        if mic_tx.send(frame.clone()).await.is_err() {
                            return;
                        }
                    }
                }
            });

            // Speaker bridge: RTP 16 kHz -> resample -> io_rate -> user-sized frames
            tokio::spawn(async move {
                let mut resampler = LinearResampler::new(INTERNAL_RATE, io_rate);
                let mut resampled = Vec::new();
                let mut acc = ResampleBuffer::new(io_rate as usize);
                let mut frame = vec![0.0f32; io_frame];
                while let Some(data) = spk_rx.recv().await {
                    resampler.process(&data, &mut resampled);
                    acc.push(&resampled);
                    while acc.pop_exact(&mut frame) {
                        if user_spk_tx.send(frame.clone()).await.is_err() {
                            return;
                        }
                    }
                }
            });

            self.send_event(VoipEvent::CallConnected {
                audio_tx: user_mic_tx,
                audio_rx: user_spk_rx,
            }).await;
        }

        Ok(())
    }

    async fn stop_media(&mut self) {
        if let Some(shutdown) = self.rtp_shutdown.take() {
            let _ = shutdown.send(());
        }
        // Clean up UPnP mapping if we created one
        if let Some(addr) = self.public_addr.take() {
            let port = addr.port();
            tokio::spawn(async move {
                crate::nat::remove_upnp_mapping(port).await;
            });
        }
        self.dtmf_tx = None;
        self.session_expires_at = None;
        self.srtp_local_key = None;
        self.srtp_local_attr = None;
        self.srtp_remote_crypto = None;
        self.send_event(VoipEvent::CallEnded).await;
        tracing::info!("Media stopped");
    }

    /// Send an event to the consumer. Non-blocking best-effort.
    async fn send_event(&self, event: VoipEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event).await;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Message handling (incoming)
    // ═══════════════════════════════════════════════════════════════════════

    async fn handle_message(&mut self, data: &[u8]) -> Result<()> {
        let text = std::str::from_utf8(data)?;
        tracing::debug!("<<< SIP IN <<<\n{text}");
        let first_line = text.lines().next().unwrap_or("");

        if first_line.starts_with("SIP/2.0 ") {
            let status_code = parse_status_code(first_line)?;
            let method = parse_cseq_method(text);
            tracing::debug!("Received {status_code} for {method}");
            self.handle_response(status_code, &method, text).await
        } else {
            let method = first_line.split_whitespace().next().unwrap_or("");
            tracing::debug!("Received {method} request");
            self.handle_request(method, text).await
        }
    }

    async fn handle_response(&mut self, status: u16, method: &str, text: &str) -> Result<()> {
        match (method, status) {
            ("REGISTER", 401) => {
                if self.reg_state == RegState::Challenged {
                    tracing::error!("Auth failed — wrong credentials or digest mismatch");
                    self.send_event(VoipEvent::RegistrationFailed("authentication error".to_string())).await;
                    return Ok(());
                }
                if let Some(challenge) = parse_www_authenticate(text) {
                    self.auth_nonce = Some(challenge.nonce);
                    self.auth_realm = Some(challenge.realm);
                    self.auth_opaque = challenge.opaque;
                    self.auth_qop = challenge.qop;
                    self.auth_nc = 0;
                    self.reg_state = RegState::Challenged;
                    tracing::info!("Received 401, re-registering with auth");
                    self.send_register(true).await?;
                }
            }
            ("REGISTER", 200) => {
                self.reg_state = RegState::Registered;
                // Parse Expires from response (server may override our 3600)
                let expires = parse_expires(text).unwrap_or(3600);
                // Re-register at 80% of Expires
                let rereg_secs = (expires as f64 * 0.8) as u64;
                self.reg_expires_at = Some(Instant::now() + Duration::from_secs(rereg_secs));
                self.send_event(VoipEvent::Registered).await;
                tracing::info!("Registered with {}, expires={expires}s", self.realm);
            }

            ("INVITE", 100) => {
                tracing::debug!("100 Trying");
            }
            ("INVITE", 180 | 183) => {
                if self.call_state == CallState::InviteSent || self.call_state == CallState::Ringing {
                    self.call_state = CallState::Ringing;
                    if let Some(tag) = parse_to_tag(text) {
                        self.remote_tag = Some(tag);
                    }
                    // 100rel PRACK support (RFC 3262)
                    if has_require_100rel(text) {
                        if let Some(rseq) = parse_rseq(text) {
                            let cseq_num: u32 = extract_header(text, "CSeq")
                                .split_whitespace().next()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(1);
                            if let Err(e) = self.send_prack(rseq, cseq_num).await {
                                tracing::warn!("PRACK failed: {e}");
                            }
                        }
                    }
                    self.send_event(VoipEvent::Ringing).await;
                }
            }
            ("INVITE", 200) => {
                if self.call_state == CallState::InviteSent
                    || self.call_state == CallState::Ringing
                {
                    if let Some(tag) = parse_to_tag(text) {
                        self.remote_tag = Some(tag);
                    }

                    let body = extract_body(text);
                    let (remote_rtp_addr, codec, remote_crypto) = sdp::parse_answer(body)?;
                    self.codec = codec;
                    self.srtp_remote_crypto = remote_crypto;

                    let target = self.invite_target.clone().unwrap_or_default();
                    self.send_ack(&target).await?;

                    self.start_media(remote_rtp_addr).await?;
                    self.call_state = CallState::InCall;

                    // Session timer (RFC 4028)
                    if let Some((se, we_refresh)) = parse_session_expires(text) {
                        self.session_interval = se;
                        if we_refresh {
                            let refresh_at = (se as f64 * 0.5) as u64;
                            self.session_expires_at = Some(Instant::now() + Duration::from_secs(refresh_at));
                            tracing::info!("Session timer: {se}s, refresh in {refresh_at}s");
                        }
                    }

                    tracing::info!("Call established, codec={:?}", self.codec);
                } else if self.call_state == CallState::InCall || self.call_state == CallState::Held {
                    // Re-INVITE 200 OK (session refresh, hold, or unhold response)
                    let target = self.invite_target.clone()
                        .or_else(|| self.incoming_contact.clone())
                        .unwrap_or_default();
                    self.send_ack(&target).await?;

                    if let Some((se, we_refresh)) = parse_session_expires(text) {
                        self.session_interval = se;
                        if we_refresh {
                            let refresh_at = (se as f64 * 0.5) as u64;
                            self.session_expires_at = Some(Instant::now() + Duration::from_secs(refresh_at));
                        }
                    }
                    tracing::info!("Re-INVITE 200 OK processed (state={:?})", self.call_state);
                }
            }
            ("INVITE", 401 | 407) => {
                if let Some(challenge) = parse_www_authenticate(text)
                    .or_else(|| parse_proxy_authenticate(text))
                {
                    self.auth_nonce = Some(challenge.nonce);
                    self.auth_realm = Some(challenge.realm);
                    self.auth_opaque = challenge.opaque;
                    self.auth_qop = challenge.qop;
                    self.auth_nc = 0;

                    let target = self.invite_target.clone().unwrap_or_default();
                    self.send_ack(&target).await?;

                    self.call_state = CallState::Idle;
                    if let Some(target) = self.invite_target.clone() {
                        self.initiate_call(&target).await?;
                    }
                }
            }
            ("INVITE", 422) => {
                // Session Interval Too Small — resend with higher value
                if let Some(min_se) = parse_min_se(text) {
                    self.min_se = min_se;
                    self.session_interval = self.session_interval.max(min_se);
                    tracing::info!("422 received, adjusting Session-Expires to {}", self.session_interval);
                    let target = self.invite_target.clone().unwrap_or_default();
                    self.send_ack(&target).await?;
                    // Re-send INVITE with adjusted timer
                    if self.call_state == CallState::InCall {
                        self.send_reinvite().await?;
                    } else {
                        self.call_state = CallState::Idle;
                        if let Some(target) = self.invite_target.clone() {
                            self.initiate_call(&target).await?;
                        }
                    }
                }
            }
            ("INVITE", 486 | 600 | 603) => {
                let target = self.invite_target.clone().unwrap_or_default();
                self.send_ack(&target).await?;
                self.stop_media().await;
                self.call_state = CallState::Idle;
                self.send_event(VoipEvent::CallFailed { reason: format!("Call rejected ({status})") }).await;
            }
            ("INVITE", status) if status >= 400 => {
                let target = self.invite_target.clone().unwrap_or_default();
                self.send_ack(&target).await?;
                self.stop_media().await;
                self.call_state = CallState::Idle;
                self.send_event(VoipEvent::CallFailed { reason: format!("Call failed ({status})") }).await;
            }

            ("REFER", 202) => {
                tracing::info!("REFER accepted (202)");
                // Transfer progress will come via NOTIFY
            }
            ("REFER", 401 | 407) => {
                // Auth challenge for REFER
                if let Some(challenge) = parse_www_authenticate(text)
                    .or_else(|| parse_proxy_authenticate(text))
                {
                    self.auth_nonce = Some(challenge.nonce);
                    self.auth_realm = Some(challenge.realm);
                    self.auth_opaque = challenge.opaque;
                    self.auth_qop = challenge.qop;
                    self.auth_nc = 0;
                    tracing::debug!("REFER auth challenge, retry needed");
                }
            }
            ("REFER", s) if s >= 400 => {
                self.send_event(VoipEvent::TransferResult {
                    success: false,
                    reason: format!("REFER rejected ({s})"),
                }).await;
            }

            ("BYE", 200) => {
                tracing::debug!("BYE acknowledged");
            }

            _ => {
                tracing::debug!("Unhandled response: {status} {method}");
            }
        }
        Ok(())
    }

    async fn handle_request(&mut self, method: &str, text: &str) -> Result<()> {
        match method {
            "INVITE" => {
                let incoming_call_id = extract_header_value(text, "Call-ID").to_string();

                // Check if this is a re-INVITE for the current dialog (hold/unhold/refresh)
                let is_reinvite = (self.call_state == CallState::InCall
                    || self.call_state == CallState::Held)
                    && self.call_id.as_deref() == Some(incoming_call_id.as_str());

                if is_reinvite {
                    // Re-INVITE: remote party changing media (hold/unhold/codec change)
                    let via = extract_header(text, "Via").to_string();
                    let from_hdr = extract_header(text, "From").to_string();
                    let to_hdr = extract_header(text, "To").to_string();
                    let cseq_num: u32 = extract_header(text, "CSeq")
                        .split_whitespace().next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(1);

                    let body = extract_body(text);
                    let local_tag = self.local_tag.as_ref().unwrap().clone();

                    // Detect hold from SDP direction attribute
                    let direction = parse_sdp_direction(body);
                    let remote_holding = direction == "sendonly" || direction == "inactive";

                    // Send 200 OK with our SDP (mirror their direction)
                    let our_direction = if remote_holding { "recvonly" } else { "sendrecv" };
                    let sdp_body = crate::sdp::build_offer_with_direction(
                        self.sdp_ip(), self.rtp_port, our_direction, self.srtp_attr(),
                    );

                    let msg = format!(
                        "SIP/2.0 200 OK\r\n\
                         Via: {via}\r\n\
                         From: {from_hdr}\r\n\
                         To: {to_hdr};tag={local_tag}\r\n\
                         Call-ID: {incoming_call_id}\r\n\
                         CSeq: {cseq_num} INVITE\r\n\
                         {contact}\r\n\
                         Content-Type: application/sdp\r\n\
                         Content-Length: {body_len}\r\n\
                         \r\n\
                         {sdp_body}",
                        contact = self.contact_header(),
                        body_len = sdp_body.len(),
                    );
                    self.send_sip(msg.as_bytes()).await?;

                    if remote_holding && self.call_state == CallState::InCall {
                        self.call_state = CallState::Held;
                        self.send_event(VoipEvent::CallHeld).await;
                        tracing::info!("Remote party placed call on hold");
                    } else if !remote_holding && self.call_state == CallState::Held {
                        self.call_state = CallState::InCall;
                        self.send_event(VoipEvent::CallResumed).await;
                        tracing::info!("Remote party resumed call");
                    }
                    return Ok(());
                }

                if self.call_state != CallState::Idle {
                    self.send_busy_response(text).await?;
                    return Ok(());
                }

                let via = extract_header(text, "Via").to_string();
                let from_hdr = extract_header(text, "From").to_string();
                let to_hdr = extract_header(text, "To").to_string();
                let call_id = incoming_call_id;
                let contact = extract_header(text, "Contact").to_string();
                let body = extract_body(text).to_string();
                let remote_tag = parse_from_tag(text);
                let cseq_num: u32 = extract_header(text, "CSeq")
                    .split_whitespace().next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);

                self.call_id = Some(call_id.clone());
                self.local_tag = Some(generate_tag());
                self.remote_tag = remote_tag;
                self.incoming_from = Some(from_hdr.clone());
                self.incoming_to = Some(to_hdr.clone());
                self.incoming_via = Some(via.clone());
                self.incoming_contact = Some(contact);
                self.incoming_sdp = Some(body);
                self.incoming_cseq = Some(cseq_num);

                let local_tag = self.local_tag.as_ref().unwrap();
                let ringing_msg = format!(
                    "SIP/2.0 180 Ringing\r\n\
                     Via: {via}\r\n\
                     From: {from_hdr}\r\n\
                     To: {to_hdr};tag={local_tag}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: {cseq_num} INVITE\r\n\
                     {contact}\r\n\
                     Content-Length: 0\r\n\r\n",
                    contact = self.contact_header(),
                );

                self.send_sip(ringing_msg.as_bytes()).await?;
                self.call_state = CallState::IncomingRinging;

                self.send_event(VoipEvent::IncomingCall { from: from_hdr.clone() }).await;
            }

            "ACK" => {
                tracing::debug!("Received ACK");
            }

            "BYE" => {
                let via = extract_header(text, "Via").to_string();
                let from_hdr = extract_header(text, "From").to_string();
                let to_hdr = extract_header(text, "To").to_string();
                let call_id = extract_header_value(text, "Call-ID").to_string();
                let cseq = extract_header_value(text, "CSeq").to_string();

                let ok_msg = format!(
                    "SIP/2.0 200 OK\r\n\
                     Via: {via}\r\n\
                     From: {from_hdr}\r\n\
                     To: {to_hdr}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: {cseq}\r\n\
                     Content-Length: 0\r\n\r\n",
                );

                self.send_sip(ok_msg.as_bytes()).await?;
                self.stop_media().await;
                self.call_state = CallState::Idle;
                self.call_id = None;
                self.local_tag = None;
                self.remote_tag = None;

                tracing::info!("Received BYE, call ended");
            }

            "CANCEL" => {
                let via = extract_header(text, "Via").to_string();
                let from_hdr = extract_header(text, "From").to_string();
                let to_hdr = extract_header(text, "To").to_string();
                let call_id = extract_header_value(text, "Call-ID").to_string();

                let ok_msg = format!(
                    "SIP/2.0 200 OK\r\n\
                     Via: {via}\r\n\
                     From: {from_hdr}\r\n\
                     To: {to_hdr}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: 1 CANCEL\r\n\
                     Content-Length: 0\r\n\r\n",
                );
                self.send_sip(ok_msg.as_bytes()).await?;

                let terminated_msg = format!(
                    "SIP/2.0 487 Request Terminated\r\n\
                     Via: {via}\r\n\
                     From: {from_hdr}\r\n\
                     To: {to_hdr}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: 1 INVITE\r\n\
                     Content-Length: 0\r\n\r\n",
                );
                self.send_sip(terminated_msg.as_bytes()).await?;

                self.stop_media().await;
                self.call_state = CallState::Idle;
            }

            "REFER" => {
                // Incoming REFER: remote party wants us to transfer.
                let via = extract_header(text, "Via").to_string();
                let from_hdr = extract_header(text, "From").to_string();
                let to_hdr = extract_header(text, "To").to_string();
                let call_id = extract_header_value(text, "Call-ID").to_string();
                let cseq = extract_header_value(text, "CSeq").to_string();
                let refer_to = extract_header(text, "Refer-To")
                    .trim_matches(|c| c == '<' || c == '>')
                    .to_string();

                if refer_to.is_empty() {
                    // Missing Refer-To header
                    let bad_msg = format!(
                        "SIP/2.0 400 Bad Request\r\n\
                         Via: {via}\r\n\
                         From: {from_hdr}\r\n\
                         To: {to_hdr}\r\n\
                         Call-ID: {call_id}\r\n\
                         CSeq: {cseq}\r\n\
                         Content-Length: 0\r\n\r\n",
                    );
                    self.send_sip(bad_msg.as_bytes()).await?;
                } else {
                    // Accept the REFER with 202 Accepted
                    let local_tag = self.local_tag.as_deref().unwrap_or("");
                    let accepted_msg = format!(
                        "SIP/2.0 202 Accepted\r\n\
                         Via: {via}\r\n\
                         From: {from_hdr}\r\n\
                         To: {to_hdr};tag={local_tag}\r\n\
                         Call-ID: {call_id}\r\n\
                         CSeq: {cseq}\r\n\
                         Content-Length: 0\r\n\r\n",
                    );
                    self.send_sip(accepted_msg.as_bytes()).await?;

                    // Send NOTIFY with sipfrag "SIP/2.0 100 Trying"
                    self.send_refer_notify(&call_id, "SIP/2.0 100 Trying").await.ok();

                    tracing::info!("Received REFER to {refer_to}, accepted");

                    // Notify consumer about the transfer
                    self.send_event(VoipEvent::TransferResult {
                        success: true,
                        reason: format!("transferred to {refer_to}"),
                    }).await;
                }
            }

            "NOTIFY" => {
                // NOTIFY is used for REFER progress (sipfrag) and other subscriptions.
                let via = extract_header(text, "Via").to_string();
                let from_hdr = extract_header(text, "From").to_string();
                let to_hdr = extract_header(text, "To").to_string();
                let call_id = extract_header_value(text, "Call-ID").to_string();
                let cseq = extract_header_value(text, "CSeq").to_string();
                let body = extract_body(text);

                // Send 200 OK for the NOTIFY
                let ok_msg = format!(
                    "SIP/2.0 200 OK\r\n\
                     Via: {via}\r\n\
                     From: {from_hdr}\r\n\
                     To: {to_hdr}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: {cseq}\r\n\
                     Content-Length: 0\r\n\r\n",
                );
                self.send_sip(ok_msg.as_bytes()).await?;

                // Parse sipfrag body for REFER status
                let content_type = extract_header(text, "Content-Type").to_lowercase();
                if content_type.contains("sipfrag") {
                    let first_line = body.lines().next().unwrap_or("").trim();
                    tracing::info!("REFER NOTIFY: {first_line}");

                    if first_line.starts_with("SIP/2.0 2") {
                        self.send_event(VoipEvent::TransferResult {
                            success: true,
                            reason: first_line.to_string(),
                        }).await;
                    } else if first_line.starts_with("SIP/2.0 4") || first_line.starts_with("SIP/2.0 5") || first_line.starts_with("SIP/2.0 6") {
                        self.send_event(VoipEvent::TransferResult {
                            success: false,
                            reason: first_line.to_string(),
                        }).await;
                    }
                    // 1xx responses are progress — no event needed
                }
            }

            "OPTIONS" => {
                let via = extract_header(text, "Via").to_string();
                let from_hdr = extract_header(text, "From").to_string();
                let to_hdr = extract_header(text, "To").to_string();
                let call_id = extract_header_value(text, "Call-ID").to_string();
                let cseq = extract_header_value(text, "CSeq").to_string();

                let ok_msg = format!(
                    "SIP/2.0 200 OK\r\n\
                     Via: {via}\r\n\
                     From: {from_hdr}\r\n\
                     To: {to_hdr}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: {cseq}\r\n\
                     Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, REFER, NOTIFY\r\n\
                     Content-Length: 0\r\n\r\n",
                );
                self.send_sip(ok_msg.as_bytes()).await?;
            }

            _ => {
                tracing::debug!("Unhandled request: {method}");
            }
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Hold / Unhold
    // ═══════════════════════════════════════════════════════════════════════

    async fn hold(&mut self) -> Result<()> {
        if self.call_state != CallState::InCall {
            return Err(anyhow!("no active call to hold"));
        }
        self.send_hold_reinvite(true).await?;
        self.call_state = CallState::Held;
        self.send_event(VoipEvent::CallHeld).await;
        tracing::info!("Call placed on hold");
        Ok(())
    }

    async fn unhold(&mut self) -> Result<()> {
        if self.call_state != CallState::Held {
            return Err(anyhow!("no held call to resume"));
        }
        self.send_hold_reinvite(false).await?;
        self.call_state = CallState::InCall;
        self.send_event(VoipEvent::CallResumed).await;
        tracing::info!("Call resumed");
        Ok(())
    }

    async fn send_hold_reinvite(&mut self, hold: bool) -> Result<()> {
        let call_id = self.call_id.as_ref().ok_or(anyhow!("no call_id"))?.clone();
        let local_tag = self.local_tag.as_ref().ok_or(anyhow!("no local_tag"))?.clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let target_uri = self.invite_target.as_deref()
            .or(self.incoming_contact.as_deref())
            .unwrap_or(&default_uri)
            .to_string();

        let target_uri = if target_uri.starts_with("sip:") || target_uri.starts_with("<sip:") {
            target_uri.trim_matches(|c| c == '<' || c == '>').to_string()
        } else {
            format!("sip:{}@{}", target_uri, self.realm)
        };

        self.call_cseq += 1;
        let direction = if hold { "sendonly" } else { "sendrecv" };
        let sdp_body = crate::sdp::build_offer_with_direction(
            self.sdp_ip(), self.rtp_port, direction, self.srtp_attr(),
        );
        let branch = generate_branch();

        let to_tag = if remote_tag.is_empty() { String::new() } else { format!(";tag={remote_tag}") };

        let mut msg = format!(
            "INVITE {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} INVITE\r\n\
             {contact}\r\n\
             Max-Forwards: 70\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {body_len}\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
            contact = self.contact_header(),
            body_len = sdp_body.len(),
        );

        if let Some(auth_hdr) = self.build_auth_header("INVITE", &target_uri) {
            msg.push_str(&auth_hdr);
        }

        msg.push_str("\r\n");
        msg.push_str(&sdp_body);

        self.send_sip(msg.as_bytes()).await?;
        tracing::info!("Sent re-INVITE for {direction}");
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // REFER (call transfer, RFC 3515)
    // ═══════════════════════════════════════════════════════════════════════

    /// Send a blind transfer REFER.
    async fn send_refer(&mut self, target: &str) -> Result<()> {
        if self.call_state != CallState::InCall && self.call_state != CallState::Held {
            return Err(anyhow!("no active call to transfer"));
        }

        let call_id = self.call_id.as_ref().ok_or(anyhow!("no call_id"))?.clone();
        let local_tag = self.local_tag.as_ref().ok_or(anyhow!("no local_tag"))?.clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let request_uri = self.invite_target.as_deref()
            .or(self.incoming_contact.as_deref())
            .unwrap_or(&default_uri)
            .to_string();

        let request_uri = if request_uri.starts_with("sip:") || request_uri.starts_with("<sip:") {
            request_uri.trim_matches(|c| c == '<' || c == '>').to_string()
        } else {
            format!("sip:{}@{}", request_uri, self.realm)
        };

        let refer_to = if target.starts_with("sip:") {
            target.to_string()
        } else {
            format!("sip:{}@{}", target, self.realm)
        };

        self.call_cseq += 1;
        let branch = generate_branch();
        let to_tag = if remote_tag.is_empty() { String::new() } else { format!(";tag={remote_tag}") };

        let msg = format!(
            "REFER {request_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{request_uri}>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} REFER\r\n\
             {contact}\r\n\
             Max-Forwards: 70\r\n\
             Refer-To: <{refer_to}>\r\n\
             Referred-By: <sip:{user}@{realm}>\r\n\
             Content-Length: 0\r\n\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
            contact = self.contact_header(),
        );

        self.send_sip(msg.as_bytes()).await?;
        tracing::info!("Sent REFER (blind transfer) to {refer_to}");
        Ok(())
    }

    /// Send an attended transfer REFER with Replaces header.
    async fn send_attended_refer(&mut self, target_call_id: &str) -> Result<()> {
        if self.call_state != CallState::InCall && self.call_state != CallState::Held {
            return Err(anyhow!("no active call to transfer"));
        }

        let call_id = self.call_id.as_ref().ok_or(anyhow!("no call_id"))?.clone();
        let local_tag = self.local_tag.as_ref().ok_or(anyhow!("no local_tag"))?.clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let request_uri = self.invite_target.as_deref()
            .or(self.incoming_contact.as_deref())
            .unwrap_or(&default_uri)
            .to_string();

        let request_uri = if request_uri.starts_with("sip:") || request_uri.starts_with("<sip:") {
            request_uri.trim_matches(|c| c == '<' || c == '>').to_string()
        } else {
            format!("sip:{}@{}", request_uri, self.realm)
        };

        // The Refer-To URI includes a Replaces parameter pointing to the target dialog
        // Refer-To: <sip:user@host?Replaces=callid%3Bto-tag%3D...%3Bfrom-tag%3D...>
        let replaces = format!(
            "{}%3Bto-tag%3D{}%3Bfrom-tag%3D{}",
            url_encode(target_call_id),
            url_encode(self.remote_tag.as_deref().unwrap_or("")),
            url_encode(self.local_tag.as_deref().unwrap_or("")),
        );

        let refer_to = format!(
            "sip:{}@{}?Replaces={}",
            self.username, self.realm, replaces
        );

        self.call_cseq += 1;
        let branch = generate_branch();
        let to_tag = if remote_tag.is_empty() { String::new() } else { format!(";tag={remote_tag}") };

        let msg = format!(
            "REFER {request_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{request_uri}>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} REFER\r\n\
             {contact}\r\n\
             Max-Forwards: 70\r\n\
             Refer-To: <{refer_to}>\r\n\
             Referred-By: <sip:{user}@{realm}>\r\n\
             Content-Length: 0\r\n\r\n",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
            contact = self.contact_header(),
        );

        self.send_sip(msg.as_bytes()).await?;
        tracing::info!("Sent REFER (attended transfer) with Replaces={target_call_id}");
        Ok(())
    }

    async fn send_busy_response(&mut self, text: &str) -> Result<()> {
        let via = extract_header(text, "Via").to_string();
        let from_hdr = extract_header(text, "From").to_string();
        let to_hdr = extract_header(text, "To").to_string();
        let call_id = extract_header_value(text, "Call-ID").to_string();

        let msg = format!(
            "SIP/2.0 486 Busy Here\r\n\
             Via: {via}\r\n\
             From: {from_hdr}\r\n\
             To: {to_hdr};tag={tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n",
            tag = generate_tag(),
        );

        self.send_sip(msg.as_bytes()).await?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS connection
// ═══════════════════════════════════════════════════════════════════════════

async fn connect_tls(addr: SocketAddr, hostname: &str) -> Result<TlsStream<TcpStream>> {
    let tcp_stream = TcpStream::connect(addr).await?;
    tracing::info!("TCP connected to {addr}");

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls_pki_types::ServerName::try_from(hostname.to_string())?;

    let tls_stream = connector.connect(server_name, tcp_stream).await?;
    tracing::info!("TLS handshake complete with {hostname}");

    Ok(tls_stream)
}

// ═══════════════════════════════════════════════════════════════════════════
// TCP SIP message framing
// ═══════════════════════════════════════════════════════════════════════════

/// Extract a complete SIP message from a TCP buffer.
/// SIP over TCP uses Content-Length to delimit messages.
fn extract_complete_sip_message(buf: &[u8]) -> Option<&[u8]> {
    let text = std::str::from_utf8(buf).ok()?;

    // Find end of headers
    let header_end = text.find("\r\n\r\n")?;
    let body_start = header_end + 4;

    // Parse Content-Length
    let headers = &text[..header_end];
    let content_length = parse_content_length(headers);

    let total_len = body_start + content_length;
    if buf.len() >= total_len {
        Some(&buf[..total_len])
    } else {
        None
    }
}

fn parse_content_length(headers: &str) -> usize {
    for line in headers.lines() {
        let line = line.trim();
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") || lower.starts_with("l:") {
            let val = line.splitn(2, ':').nth(1).unwrap_or("0").trim();
            return val.parse().unwrap_or(0);
        }
    }
    0
}

// ═══════════════════════════════════════════════════════════════════════════
// SIP message parsing helpers
// ═══════════════════════════════════════════════════════════════════════════

fn parse_status_code(first_line: &str) -> Result<u16> {
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        Ok(parts[1].parse()?)
    } else {
        Err(anyhow!("invalid status line"))
    }
}

fn parse_cseq_method(text: &str) -> String {
    for line in text.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("cseq:") {
            let value = line.splitn(2, ':').nth(1).unwrap_or("").trim();
            return value.split_whitespace().nth(1).unwrap_or("").to_string();
        }
    }
    String::new()
}

fn extract_header<'a>(text: &'a str, name: &str) -> &'a str {
    let name_lower = name.to_lowercase();
    for line in text.lines() {
        let line_trimmed = line.trim();
        let line_lower = line_trimmed.to_lowercase();
        if line_lower.starts_with(&format!("{}:", name_lower)) {
            return line_trimmed.splitn(2, ':').nth(1).unwrap_or("").trim();
        }
    }
    ""
}

fn extract_header_value<'a>(text: &'a str, name: &str) -> &'a str {
    extract_header(text, name)
}

fn extract_body(text: &str) -> &str {
    if let Some(idx) = text.find("\r\n\r\n") {
        &text[idx + 4..]
    } else if let Some(idx) = text.find("\n\n") {
        &text[idx + 2..]
    } else {
        ""
    }
}

fn parse_to_tag(text: &str) -> Option<String> {
    extract_tag_param(extract_header(text, "To"))
}

fn parse_from_tag(text: &str) -> Option<String> {
    extract_tag_param(extract_header(text, "From"))
}

fn extract_tag_param(header: &str) -> Option<String> {
    for part in header.split(';') {
        let part = part.trim();
        if part.starts_with("tag=") {
            return Some(part[4..].to_string());
        }
    }
    None
}

fn parse_expires(text: &str) -> Option<u32> {
    // First try Expires header
    let val = extract_header(text, "Expires");
    if !val.is_empty() {
        if let Ok(v) = val.trim().parse::<u32>() {
            return Some(v);
        }
    }
    // Try Contact header expires param
    let contact = extract_header(text, "Contact");
    for part in contact.split(';') {
        let part = part.trim();
        if part.starts_with("expires=") {
            if let Ok(v) = part[8..].parse::<u32>() {
                return Some(v);
            }
        }
    }
    None
}

fn parse_session_expires(text: &str) -> Option<(u32, bool)> {
    let val = extract_header(text, "Session-Expires");
    if val.is_empty() {
        return None;
    }
    let mut parts = val.split(';');
    let secs: u32 = parts.next()?.trim().parse().ok()?;
    let mut we_refresh = true;
    for param in parts {
        let param = param.trim();
        if param.starts_with("refresher=") {
            let refresher = param[10..].trim();
            we_refresh = refresher == "uac";
        }
    }
    Some((secs, we_refresh))
}

fn parse_min_se(text: &str) -> Option<u32> {
    let val = extract_header(text, "Min-SE");
    if val.is_empty() {
        return None;
    }
    val.trim().split(';').next()?.trim().parse().ok()
}

fn parse_rseq(text: &str) -> Option<u32> {
    let val = extract_header(text, "RSeq");
    if !val.is_empty() {
        return val.trim().parse().ok();
    }
    None
}

fn has_require_100rel(text: &str) -> bool {
    let val = extract_header(text, "Require");
    val.to_lowercase().contains("100rel")
}

/// Parse the media direction from SDP body (sendrecv, sendonly, recvonly, inactive).
fn parse_sdp_direction(sdp: &str) -> &str {
    for line in sdp.lines() {
        let line = line.trim();
        if line == "a=sendonly" { return "sendonly"; }
        if line == "a=recvonly" { return "recvonly"; }
        if line == "a=inactive" { return "inactive"; }
        if line == "a=sendrecv" { return "sendrecv"; }
    }
    "sendrecv" // default per RFC 3264
}

/// Parsed digest auth challenge.
struct DigestChallenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    qop: Option<String>,
}

fn parse_www_authenticate(text: &str) -> Option<DigestChallenge> {
    parse_auth_header(text, "WWW-Authenticate")
}

fn parse_proxy_authenticate(text: &str) -> Option<DigestChallenge> {
    parse_auth_header(text, "Proxy-Authenticate")
}

fn parse_auth_header(text: &str, header_name: &str) -> Option<DigestChallenge> {
    let value = extract_header(text, header_name);
    if value.is_empty() {
        return None;
    }

    let mut realm = None;
    let mut nonce = None;
    let mut opaque = None;
    let mut qop = None;

    let digest_part = value.strip_prefix("Digest ").unwrap_or(value);
    for param in digest_part.split(',') {
        let param = param.trim();
        if param.starts_with("realm=") {
            realm = Some(param[6..].trim_matches('"').to_string());
        } else if param.starts_with("nonce=") {
            nonce = Some(param[6..].trim_matches('"').to_string());
        } else if param.starts_with("opaque=") {
            opaque = Some(param[7..].trim_matches('"').to_string());
        } else if param.starts_with("qop=") {
            qop = Some(param[4..].trim_matches('"').to_string());
        }
    }

    match (realm, nonce) {
        (Some(realm), Some(nonce)) => Some(DigestChallenge { realm, nonce, opaque, qop }),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Digest authentication (RFC 2617)
// ═══════════════════════════════════════════════════════════════════════════

fn compute_digest_response(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    qop: Option<&str>,
    nc: u32,
    cnonce: &str,
) -> String {
    use md5::{Digest, Md5};

    let ha1 = hex::encode(Md5::digest(format!("{username}:{realm}:{password}")));
    let ha2 = hex::encode(Md5::digest(format!("{method}:{uri}")));

    if qop.is_some() {
        // RFC 2617 qop=auth: response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        let nc_str = format!("{nc:08x}");
        hex::encode(Md5::digest(format!("{ha1}:{nonce}:{nc_str}:{cnonce}:auth:{ha2}")))
    } else {
        hex::encode(Md5::digest(format!("{ha1}:{nonce}:{ha2}")))
    }
}

impl SipClient {
    /// Send a NOTIFY with sipfrag body (used for REFER progress).
    async fn send_refer_notify(&mut self, call_id: &str, sipfrag: &str) -> Result<()> {
        let local_tag = self.local_tag.as_ref().ok_or(anyhow!("no local_tag"))?.clone();
        let remote_tag = self.remote_tag.as_deref().unwrap_or("").to_string();

        let default_uri = format!("sip:{}@{}", self.username, self.realm);
        let target_uri = self.invite_target.as_deref()
            .or(self.incoming_contact.as_deref())
            .unwrap_or(&default_uri)
            .to_string();

        let target_uri = if target_uri.starts_with("sip:") || target_uri.starts_with("<sip:") {
            target_uri.trim_matches(|c| c == '<' || c == '>').to_string()
        } else {
            format!("sip:{}@{}", target_uri, self.realm)
        };

        self.call_cseq += 1;
        let branch = generate_branch();
        let to_tag = if remote_tag.is_empty() { String::new() } else { format!(";tag={remote_tag}") };

        let msg = format!(
            "NOTIFY {target_uri} SIP/2.0\r\n\
             {via}\r\n\
             From: <sip:{user}@{realm}>;tag={local_tag}\r\n\
             To: <{target_uri}>{to_tag}\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {cseq} NOTIFY\r\n\
             Max-Forwards: 70\r\n\
             Event: refer\r\n\
             Subscription-State: terminated;reason=noresource\r\n\
             Content-Type: message/sipfrag;version=2.0\r\n\
             Content-Length: {body_len}\r\n\
             \r\n\
             {sipfrag}",
            via = self.via_header(&branch),
            user = self.username,
            realm = self.realm,
            cseq = self.call_cseq,
            body_len = sipfrag.len(),
        );

        self.send_sip(msg.as_bytes()).await?;
        Ok(())
    }
}

/// Minimal URL-encoding for SIP Replaces parameter.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn generate_cnonce() -> String {
    format!("{:016x}", rand::random::<u64>())
}

fn generate_branch() -> String {
    format!("{:016x}", rand::random::<u64>())
}

fn generate_tag() -> String {
    format!("{:08x}", rand::random::<u32>())
}

fn generate_call_id() -> String {
    format!("{:016x}@voip_client", rand::random::<u64>())
}
