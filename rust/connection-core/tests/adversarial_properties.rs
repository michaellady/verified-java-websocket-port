//! Deterministic adversarial properties exercised through the public core seam.
//!
//! The campaign structure is adapted from Claude's `dc07516` adversarial
//! suites, while the assertions remain bound to this branch's documented
//! RFC-strict, explicit-entropy `ConnectionCore` contract.

#![forbid(unsafe_code)]

use websocket_core::{
    AutomaticPongPolicy, ClientRequestDescriptor, CloseCodeRejection, CloseFailure,
    ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState, CoreInput, CoreOutput,
    FailureKind, FrameEncoder, LocalCommand, Opcode, OutboundFrame, Role, SemanticEvent,
    TransportBytes, apply_mask_in_place,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

#[derive(Clone, Copy)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, upper: u64) -> u64 {
        assert!(upper > 0);
        self.next_u64() % upper
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

fn config() -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits::default()).expect("default limits")
}

fn open_core(role: Role, config: ConnectionConfig) -> ConnectionCore {
    let mut core = ConnectionCore::new(config, role);
    match role {
        Role::Client => {
            let descriptor =
                ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
            assert_eq!(
                core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
                    descriptor,
                    nonce: *b"the sample nonce",
                }))
                .failure(),
                None
            );
            assert_eq!(
                core.step(CoreInput::Transport(TransportBytes::new(RFC_RESPONSE)))
                    .failure(),
                None
            );
        }
        Role::Server => assert_eq!(
            core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)))
                .failure(),
            None
        ),
    }
    assert_eq!(core.state(), ConnectionState::Open);
    core
}

fn encoded_client_frame(
    config: &ConnectionConfig,
    opcode: Opcode,
    payload: &[u8],
    mask_key: [u8; 4],
) -> Vec<u8> {
    FrameEncoder::new(config.clone(), Role::Client)
        .encode(OutboundFrame::new(true, opcode, payload), Some(mask_key))
        .expect("generated frame satisfies configured limits")
        .as_slice()
        .to_vec()
}

#[test]
fn random_text_payloads_match_the_standard_utf8_oracle() {
    let config = config();
    let mut rng = SplitMix64::new(0xc0de_0001);
    for case in 0..20_000_u32 {
        let length = rng.below(65) as usize;
        let bytes: Vec<u8> = (0..length)
            .map(|_| match rng.below(4) {
                0 => rng.byte(),
                1 => 0x80 | (rng.byte() & 0x3f),
                2 => 0xc0 | (rng.byte() & 0x3f),
                _ => 0xe0 | (rng.byte() & 0x1f),
            })
            .collect();
        let wire = encoded_client_frame(&config, Opcode::Text, &bytes, [1, 3, 5, 7]);
        let result = open_core(Role::Server, config.clone())
            .step(CoreInput::Transport(TransportBytes::new(&wire)));
        let expected_valid = std::str::from_utf8(&bytes).is_ok();
        assert_eq!(
            result.failure().is_none(),
            expected_valid,
            "case {case}, bytes={bytes:02x?}, failure={:?}",
            result.failure()
        );
        if expected_valid {
            assert_eq!(result.state(), ConnectionState::Open);
            assert!(result.outputs().any(|output| matches!(
                output,
                CoreOutput::SemanticEvent(SemanticEvent::Text { message })
                    if message.as_bytes() == bytes
            )));
        } else {
            assert!(matches!(
                result.failure().map(|failure| &failure.kind),
                Some(FailureKind::Utf8(_))
            ));
            assert_eq!(result.state(), ConnectionState::Closed);
        }
    }
}

#[test]
fn masking_is_an_involution_and_matches_the_repeating_xor_equation() {
    let mut rng = SplitMix64::new(0xc0de_0002);
    for case in 0..5_000_u32 {
        let length = rng.below(513) as usize;
        let payload: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
        let key = [rng.byte(), rng.byte(), rng.byte(), rng.byte()];
        let offset = rng.below(17) as usize;

        let mut masked = payload.clone();
        apply_mask_in_place(&mut masked, key, offset);
        let expected: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[(offset + index) % 4])
            .collect();
        assert_eq!(masked, expected, "case {case}: XOR equation");

        apply_mask_in_place(&mut masked, key, offset);
        assert_eq!(masked, payload, "case {case}: involution");

        let split = rng.below(length as u64 + 1) as usize;
        let mut chunked = payload.clone();
        apply_mask_in_place(&mut chunked[..split], key, offset);
        apply_mask_in_place(&mut chunked[split..], key, offset + split);
        let mut whole = payload;
        apply_mask_in_place(&mut whole, key, offset);
        assert_eq!(chunked, whole, "case {case}: chunk equivalence");
    }
}

#[test]
fn canonical_lengths_round_trip_at_boundaries_and_random_sites() {
    let config = config();
    let mut rng = SplitMix64::new(0xc0de_0003);
    let mut lengths = vec![0_usize, 1, 125, 126, 127, 65_535, 65_536];
    lengths.extend((0..500).map(|_| rng.below(2_001) as usize));
    for (case, length) in lengths.into_iter().enumerate() {
        let payload: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
        let key = [rng.byte(), rng.byte(), rng.byte(), rng.byte()];
        let wire = encoded_client_frame(&config, Opcode::Binary, &payload, key);
        let marker = wire[1] & 0x7f;
        assert_eq!(
            marker,
            match length {
                0..=125 => length as u8,
                126..=65_535 => 126,
                _ => 127,
            },
            "case {case}: canonical marker for {length}"
        );

        let result = open_core(Role::Server, config.clone())
            .step(CoreInput::Transport(TransportBytes::new(&wire)));
        assert_eq!(result.failure(), None, "case {case}, length {length}");
        assert!(result.outputs().any(|output| matches!(
            output,
            CoreOutput::SemanticEvent(SemanticEvent::Binary { message })
                if message.as_slice() == payload
        )));
    }
}

fn model_close_rejection(code: u16, sender: Role) -> Option<CloseCodeRejection> {
    if !(1000..=4999).contains(&code) {
        return Some(CloseCodeRejection::OutsideWireRange);
    }
    if [1004, 1005, 1006, 1015].contains(&code) {
        return Some(CloseCodeRejection::ForbiddenWireCode);
    }
    if code == 1010 && sender == Role::Server {
        return Some(CloseCodeRejection::WrongSenderRole);
    }
    if (1016..=2999).contains(&code) {
        return Some(CloseCodeRejection::UnassignedOrExtensionReserved);
    }
    None
}

#[test]
fn local_close_code_table_is_exhaustive_for_both_sender_roles() {
    for role in [Role::Client, Role::Server] {
        let mut core = open_core(role, config());
        for code in 0..=u16::MAX {
            let command = LocalCommand::Close {
                code: Some(code),
                reason: "".into(),
                mask_key: (role == Role::Client).then_some([1, 2, 3, 4]),
            };
            let result = core.step(CoreInput::Command(command));
            match model_close_rejection(code, role) {
                Some(rejection) => {
                    assert_eq!(
                        result.failure().map(|failure| &failure.kind),
                        Some(&FailureKind::Close(CloseFailure::InvalidCode {
                            code,
                            rejection,
                        })),
                        "role={role:?} code={code}"
                    );
                    assert_eq!(result.state(), ConnectionState::Open);
                }
                None => {
                    assert_eq!(result.failure(), None, "role={role:?} code={code}");
                    assert_eq!(result.state(), ConnectionState::Closing);
                    core = open_core(role, config());
                }
            }
        }
    }
}

fn run_stream(config: &ConnectionConfig, stream: &[u8], cuts: &[usize]) -> Vec<CoreOutput> {
    let mut core = open_core(Role::Server, config.clone());
    let mut outputs = Vec::new();
    let mut start = 0;
    for &end in cuts {
        assert!((start..=stream.len()).contains(&end));
        let result = core.step(CoreInput::Transport(TransportBytes::new(
            &stream[start..end],
        )));
        assert_eq!(result.failure(), None, "chunk {start}..{end}");
        outputs.extend(result.outputs().cloned());
        start = end;
    }
    assert_eq!(start, stream.len());
    assert_eq!(core.state(), ConnectionState::Open);
    outputs
}

#[test]
fn valid_multiframe_streams_are_invariant_under_random_rechunking() {
    let config = config().with_automatic_pong_policy(AutomaticPongPolicy::ServerOnly);
    let mut rng = SplitMix64::new(0xc0de_0004);
    for case in 0..2_000_u32 {
        let frame_count = 1 + rng.below(8) as usize;
        let mut stream = Vec::new();
        for frame_index in 0..frame_count {
            let opcode = match rng.below(4) {
                0 => Opcode::Text,
                1 => Opcode::Binary,
                2 => Opcode::Ping,
                _ => Opcode::Pong,
            };
            let maximum = if matches!(opcode, Opcode::Ping | Opcode::Pong) {
                126
            } else {
                257
            };
            let length = rng.below(maximum) as usize;
            let payload: Vec<u8> = (0..length)
                .map(|_| {
                    if opcode == Opcode::Text {
                        rng.byte() & 0x7f
                    } else {
                        rng.byte()
                    }
                })
                .collect();
            stream.extend_from_slice(&encoded_client_frame(
                &config,
                opcode,
                &payload,
                [case as u8, frame_index as u8, rng.byte(), rng.byte()],
            ));
        }

        let whole = run_stream(&config, &stream, &[stream.len()]);
        let mut cuts = Vec::new();
        let mut offset = 0;
        while offset < stream.len() {
            if rng.below(5) == 0 {
                cuts.push(offset);
            }
            offset = (offset + 1 + rng.below(31) as usize).min(stream.len());
            cuts.push(offset);
        }
        let chunked = run_stream(&config, &stream, &cuts);
        assert_eq!(chunked, whole, "case {case}, cuts={cuts:?}");
    }
}

#[test]
fn arbitrary_open_state_byte_soup_is_deterministic_and_bounded() {
    let config = config();
    let mut rng = SplitMix64::new(0xc0de_0005);
    for case in 0..10_000_u32 {
        let length = rng.below(129) as usize;
        let bytes: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
        let mut left = open_core(Role::Server, config.clone());
        let mut right = open_core(Role::Server, config.clone());
        let left_result = left.step(CoreInput::Transport(TransportBytes::new(&bytes)));
        let right_result = right.step(CoreInput::Transport(TransportBytes::new(&bytes)));
        assert_eq!(left_result, right_result, "case {case}");
        assert_eq!(
            left.last_step_observation(),
            right.last_step_observation(),
            "case {case}: observation"
        );
        let accounting = left.last_step_observation().accounting();
        assert!(accounting.wire_buffered_bytes <= bytes.len());
        assert!(accounting.message_buffered_bytes <= bytes.len());
        assert!(left_result.outputs().len() <= bytes.len().saturating_mul(3).saturating_add(1));
    }
}
