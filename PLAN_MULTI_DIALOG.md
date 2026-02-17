# Plan: Multiple Concurrent Dialogs

This plan describes how to refactor `SipClient` to support multiple simultaneous
SIP dialogs (calls), enabling attended transfer and call waiting.

## Current Architecture (Single Dialog)

`SipClient` stores one set of call state fields directly on the struct:

```rust
pub struct SipClient {
    call_state: CallState,
    call_cseq: u32,
    call_id: Option<String>,
    local_tag: Option<String>,
    remote_tag: Option<String>,
    invite_target: Option<String>,
    rtp_port: u16,
    codec: Codec,
    rtp_shutdown: Option<oneshot::Sender<()>>,
    dtmf_tx: Option<mpsc::Sender<char>>,
    srtp_local_key: Option<([u8; 16], [u8; 14])>,
    srtp_local_attr: Option<String>,
    srtp_remote_crypto: Option<String>,
    incoming_from: Option<String>,
    incoming_to: Option<String>,
    incoming_via: Option<String>,
    incoming_contact: Option<String>,
    incoming_sdp: Option<String>,
    incoming_cseq: Option<u32>,
    // ...
}
```

Only one call can exist at a time. Starting a second call requires ending the first.

## Target Architecture (Dialog Map)

### Step 1: Extract `Dialog` struct

Move all per-call fields into a `Dialog` struct:

```rust
struct Dialog {
    id: String,  // Call-ID (unique identifier)
    state: CallState,
    cseq: u32,
    local_tag: String,
    remote_tag: Option<String>,
    invite_target: Option<String>,

    // Media
    rtp_port: u16,
    codec: Codec,
    rtp_shutdown: Option<oneshot::Sender<()>>,
    dtmf_tx: Option<mpsc::Sender<char>>,

    // SRTP
    srtp_local_key: Option<([u8; 16], [u8; 14])>,
    srtp_local_attr: Option<String>,
    srtp_remote_crypto: Option<String>,

    // Incoming INVITE context (for answering)
    incoming_from: Option<String>,
    incoming_to: Option<String>,
    incoming_via: Option<String>,
    incoming_contact: Option<String>,
    incoming_sdp: Option<String>,
    incoming_cseq: Option<u32>,
}
```

### Step 2: Replace flat fields with a dialog map

```rust
pub struct SipClient {
    // ... transport, auth, registration fields stay the same ...

    /// All active dialogs, keyed by Call-ID.
    dialogs: HashMap<String, Dialog>,
    /// The "focused" dialog (receives audio, DTMF commands, etc.)
    active_dialog_id: Option<String>,

    // ... rest stays the same ...
}
```

### Step 3: Update VoipCommand to target specific dialogs

Currently commands implicitly target the single active call. With multiple dialogs,
commands need a target:

```rust
pub enum VoipCommand {
    Call(String),
    Answer,                       // Answer the most recent incoming call
    AnswerDialog(String),         // Answer a specific Call-ID
    Hangup,                       // Hangup the active dialog
    HangupDialog(String),         // Hangup a specific Call-ID
    SendDtmf(char),
    Hold,                         // Hold the active dialog
    HoldDialog(String),
    Unhold,
    UnholdDialog(String),
    Transfer(String),
    AttendedTransfer {
        held_call_id: String,     // The call to transfer (currently on hold)
        active_call_id: String,   // The consultation call (currently active)
    },
    SwitchDialog(String),         // Make a different dialog the active one
    Quit,
}
```

The non-`Dialog` variants continue to work on `active_dialog_id` for backwards
compatibility. Simple consumers can ignore the `*Dialog` variants entirely.

### Step 4: Update VoipEvent to identify which dialog

```rust
pub enum VoipEvent {
    Registered,
    RegistrationFailed(String),
    IncomingCall { from: String, call_id: String },  // added call_id
    Ringing { call_id: String },
    CallConnected {
        call_id: String,
        audio_tx: mpsc::Sender<Vec<f32>>,
        audio_rx: mpsc::Receiver<Vec<f32>>,
    },
    CallEnded { call_id: String },
    CallFailed { call_id: String, reason: String },
    DtmfReceived(char),
    CallHeld { call_id: String },
    CallResumed { call_id: String },
    TransferResult { call_id: String, success: bool, reason: String },
}
```

### Step 5: Update message routing

Incoming SIP messages are matched to dialogs by Call-ID:

```rust
fn route_message(&mut self, text: &str) -> Option<&mut Dialog> {
    let call_id = parse_header(text, "Call-ID")?;
    self.dialogs.get_mut(&call_id)
}
```

For new incoming INVITEs (no matching dialog), create a new `Dialog` entry.

### Step 6: Media isolation

Each dialog gets its own:
- RTP session (separate UDP port, separate `start_session` call)
- SRTP contexts (separate key pairs)
- Audio channels (`audio_tx`/`audio_rx`)
- Codec state

The consumer receives separate channel pairs per dialog via `CallConnected { call_id, ... }`.

## Implementation Order

1. **Extract `Dialog` struct** — purely mechanical refactor, no behavior change.
   Move fields, update all method signatures to take `&mut Dialog`.
   Test: all 31 tests still pass, single-call behavior unchanged.

2. **Add `HashMap<String, Dialog>`** — replace flat fields with the map.
   Keep `active_dialog_id` pointing to the single dialog.
   Route incoming messages by Call-ID.
   Test: single-call behavior still works.

3. **Support second dialog** — allow `VoipCommand::Call` while another dialog is
   in `Held` state. Creates a second entry in the map.
   Test: hold call A, dial call B, both have separate RTP sessions.

4. **Add `SwitchDialog` command** — switch which dialog is "active" (receives
   default commands and audio focus).

5. **Wire attended transfer** — `AttendedTransfer { held_call_id, active_call_id }`
   sends REFER with Replaces from `active_call_id` referencing `held_call_id`.

6. **Wire call waiting** — incoming INVITE during active call creates a new
   `IncomingRinging` dialog. Consumer can `Hold` + `AnswerDialog(new_id)`.

## Estimated Scope

| Step | Files changed | Risk |
|------|--------------|------|
| 1. Extract Dialog | sip.rs | Low — pure refactor |
| 2. Dialog map | sip.rs | Medium — routing logic |
| 3. Second dialog | sip.rs, rtp.rs | Medium — concurrent RTP sessions |
| 4. SwitchDialog | sip.rs | Low — just swaps active_dialog_id |
| 5. Attended transfer | sip.rs | Low — REFER code already exists |
| 6. Call waiting | sip.rs | Low — IncomingCall event already fires |

## Breaking Changes

- `VoipEvent::CallConnected` gains a `call_id` field
- `VoipEvent::IncomingCall` gains a `call_id` field
- `VoipEvent::CallEnded` gains a `call_id` field
- Other events gain `call_id` fields

Existing consumers that destructure events will need updating.
The `call_id` can be ignored by single-call consumers.

## Alternative: Keep It Simple

If multiple concurrent calls are not needed, none of this is required.
The current single-dialog architecture handles all common VoIP scenarios:
one active call with hold/unhold, blind transfer, and DTMF.
