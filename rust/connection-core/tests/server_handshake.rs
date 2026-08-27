#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState,
    CoreInput, CoreOutput, FailureKind, HandshakeFailure, InputKind, LimitKind, LocalCommand, Role,
    SemanticEvent, TransportBytes,
};

fn server() -> ConnectionCore {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    ConnectionCore::new(config, Role::Server)
}

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

include!("data/us011_nonce_vectors.rs");

include!("data/us011_frozen_cases.rs");

fn server_with_limits(handshake_bytes: u64, header_count: u64, line_bytes: u64) -> ConnectionCore {
    let limits = ConnectionLimits {
        handshake_bytes,
        handshake_header_count: header_count,
        handshake_header_line_bytes: line_bytes.min(handshake_bytes),
        ..ConnectionLimits::default()
    };
    let config = ConnectionConfig::try_from(limits).unwrap();
    ConnectionCore::new(config, Role::Server)
}

fn expected_response(accept: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    .into_bytes()
}

fn assert_opened_result(
    result: &websocket_core::StepResult,
    target: &str,
    host: &str,
    accept: &str,
    context: &str,
) {
    assert_eq!(result.failure(), None, "{context}");
    assert_eq!(result.state(), ConnectionState::Open, "{context}");
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 3, "{context}");
    let CoreOutput::TransportWrite(write) = outputs[0] else {
        panic!("{context}: transport write must be first");
    };
    assert_eq!(write.as_slice(), expected_response(accept), "{context}");
    assert_eq!(
        outputs[1],
        &CoreOutput::StateChanged(ConnectionState::Open),
        "{context}"
    );
    let CoreOutput::SemanticEvent(SemanticEvent::ServerHandshakeOpened { descriptor }) = outputs[2]
    else {
        panic!("{context}: descriptor event must be last");
    };
    assert_eq!(descriptor.request_target(), target, "{context}");
    assert_eq!(descriptor.host(), host, "{context}");
}

fn assert_fatal_handshake(
    core: &mut ConnectionCore,
    request: &[u8],
    expected: &HandshakeFailure,
    context: &str,
) {
    let result = core.step(CoreInput::Transport(TransportBytes::new(request)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(expected.clone())),
        "{context}"
    );
    assert_eq!(result.state(), ConnectionState::Closed, "{context}");
    assert_eq!(
        result.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)],
        "{context}"
    );
}

const VALID_REQUEST_HEADERS: &[&[u8]] = &[
    b"Host: server.example.com",
    b"Upgrade: websocket",
    b"Connection: Upgrade",
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    b"Sec-WebSocket-Version: 13",
];

fn request_with(start_line: &[u8], headers: &[&[u8]]) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(start_line);
    request.extend_from_slice(b"\r\n");
    for header in headers {
        request.extend_from_slice(header);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request
}

fn request_replacing_header(index: usize, replacement: &[u8]) -> Vec<u8> {
    let mut headers = VALID_REQUEST_HEADERS.to_vec();
    headers[index] = replacement;
    request_with(b"GET / HTTP/1.1", &headers)
}

fn request_with_added_header(addition: &[u8]) -> Vec<u8> {
    let mut headers = VALID_REQUEST_HEADERS.to_vec();
    headers.push(addition);
    request_with(b"GET / HTTP/1.1", &headers)
}

struct AdditiveFailureCase {
    id: &'static str,
    request: Vec<u8>,
    limits: Option<(u64, u64, u64)>,
    expected: FailureKind,
}

fn additive_failure_cases() -> Vec<AdditiveFailureCase> {
    let handshake_bytes = u64::try_from(RFC_REQUEST.len() - 1).unwrap();
    let request_line_bytes = u64::try_from(b"GET /chat HTTP/1.1\r\n".len() - 1).unwrap();
    vec![
        AdditiveFailureCase {
            id: "lowercase-method",
            request: request_with(b"get / HTTP/1.1", VALID_REQUEST_HEADERS),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::MethodNotGet),
        },
        AdditiveFailureCase {
            id: "extra-request-line-token",
            request: request_with(b"GET / HTTP/1.1 EXTRA", VALID_REQUEST_HEADERS),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::MalformedRequestLine),
        },
        AdditiveFailureCase {
            id: "absolute-form-target",
            request: request_with(
                b"GET http://example.com/chat HTTP/1.1",
                VALID_REQUEST_HEADERS,
            ),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidRequestTarget),
        },
        AdditiveFailureCase {
            id: "asterisk-form-target",
            request: request_with(b"GET * HTTP/1.1", VALID_REQUEST_HEADERS),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidRequestTarget),
        },
        AdditiveFailureCase {
            id: "fragment-target",
            request: request_with(b"GET /chat#fragment HTTP/1.1", VALID_REQUEST_HEADERS),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidRequestTarget),
        },
        AdditiveFailureCase {
            id: "invalid-host",
            request: request_replacing_header(0, b"Host: two words"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidHost),
        },
        AdditiveFailureCase {
            id: "required-token-placement",
            request: request_replacing_header(3, b"X-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::MissingKey),
        },
        AdditiveFailureCase {
            id: "version-plus-13",
            request: request_replacing_header(4, b"Sec-WebSocket-Version: +13"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::UnsupportedVersion),
        },
        AdditiveFailureCase {
            id: "version-leading-zero",
            request: request_replacing_header(4, b"Sec-WebSocket-Version: 0013"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::UnsupportedVersion),
        },
        AdditiveFailureCase {
            id: "base64-alphabet-boundary",
            request: request_replacing_header(3, b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ-_"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidKeyEncoding),
        },
        AdditiveFailureCase {
            id: "base64-padding-boundary",
            request: request_replacing_header(3, b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ="),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidKeyEncoding),
        },
        AdditiveFailureCase {
            id: "base64-pad-bit-mutation",
            request: request_replacing_header(3, b"Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAB=="),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidKeyEncoding),
        },
        AdditiveFailureCase {
            id: "request-line-control",
            request: request_with(b"GET /bad\x01target HTTP/1.1", VALID_REQUEST_HEADERS),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidRequestTarget),
        },
        AdditiveFailureCase {
            id: "request-line-del",
            request: request_with(b"GET /bad\x7ftarget HTTP/1.1", VALID_REQUEST_HEADERS),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidRequestTarget),
        },
        AdditiveFailureCase {
            id: "header-name-control",
            request: request_with_added_header(b"Bad\x01Name: value"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidHeaderName),
        },
        AdditiveFailureCase {
            id: "header-name-del",
            request: request_with_added_header(b"Bad\x7fName: value"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidHeaderName),
        },
        AdditiveFailureCase {
            id: "header-value-control",
            request: request_with_added_header(b"X-Test: before\x01after"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidHeaderValueOctet),
        },
        AdditiveFailureCase {
            id: "header-value-del",
            request: request_with_added_header(b"X-Test: before\x7fafter"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::InvalidHeaderValueOctet),
        },
        AdditiveFailureCase {
            id: "case-insensitive-duplicate",
            request: request_with_added_header(b"hOsT: other.example"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::DuplicateHeader),
        },
        AdditiveFailureCase {
            id: "content-length",
            request: request_with_added_header(b"Content-Length: 0"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::UnexpectedContentLength),
        },
        AdditiveFailureCase {
            id: "transfer-encoding",
            request: request_with_added_header(b"Transfer-Encoding: identity"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::UnexpectedTransferEncoding),
        },
        AdditiveFailureCase {
            id: "unexpected-extension",
            request: request_with_added_header(b"Sec-WebSocket-Extensions: permessage-deflate"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::UnexpectedExtension),
        },
        AdditiveFailureCase {
            id: "unexpected-subprotocol",
            request: request_with_added_header(b"Sec-WebSocket-Protocol: chat"),
            limits: None,
            expected: FailureKind::Handshake(HandshakeFailure::UnexpectedSubprotocol),
        },
        AdditiveFailureCase {
            id: "total-limit",
            request: RFC_REQUEST.to_vec(),
            limits: Some((handshake_bytes, 32, 512)),
            expected: FailureKind::LimitExceeded {
                limit: LimitKind::HandshakeBytes,
                attempted: handshake_bytes + 1,
                maximum: handshake_bytes,
            },
        },
        AdditiveFailureCase {
            id: "line-limit",
            request: RFC_REQUEST.to_vec(),
            limits: Some((512, 32, request_line_bytes)),
            expected: FailureKind::LimitExceeded {
                limit: LimitKind::HandshakeHeaderLineBytes,
                attempted: request_line_bytes + 1,
                maximum: request_line_bytes,
            },
        },
        AdditiveFailureCase {
            id: "count-limit",
            request: RFC_REQUEST.to_vec(),
            limits: Some((512, 4, 512)),
            expected: FailureKind::LimitExceeded {
                limit: LimitKind::HandshakeHeaderCount,
                attempted: 5,
                maximum: 4,
            },
        },
        AdditiveFailureCase {
            id: "response-capacity",
            request: RFC_REQUEST.to_vec(),
            limits: Some((512, 32, 51)),
            expected: FailureKind::LimitExceeded {
                limit: LimitKind::HandshakeHeaderLineBytes,
                attempted: 52,
                maximum: 51,
            },
        },
    ]
}

fn assert_rejected(request: &[u8], expected: HandshakeFailure, context: &str) {
    let mut core = server();
    assert_fatal_handshake(&mut core, request, &expected, context);
}

fn assert_rejected_result(
    result: &websocket_core::StepResult,
    expected: &HandshakeFailure,
    context: &str,
) {
    assert_failure_result(result, &FailureKind::Handshake(expected.clone()), context);
}

fn assert_failure_result(
    result: &websocket_core::StepResult,
    expected: &FailureKind,
    context: &str,
) {
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(expected),
        "{context}"
    );
    assert_eq!(result.state(), ConnectionState::Closed, "{context}");
    assert_eq!(
        result.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)],
        "{context}"
    );
}

fn assert_rejected_at_every_split(request: &[u8], expected: HandshakeFailure, context: &str) {
    let expected = FailureKind::Handshake(expected);
    assert_failure_at_every_split_with(request, &expected, context, server);
}

fn assert_failure_at_every_split_with<F>(
    request: &[u8],
    expected: &FailureKind,
    context: &str,
    make_core: F,
) -> usize
where
    F: Fn() -> ConnectionCore,
{
    for split in 0..=request.len() {
        let mut core = make_core();
        let first = core.step(CoreInput::Transport(TransportBytes::new(&request[..split])));
        let split_context = format!("{context} split {split}");
        if first.failure().is_some() {
            assert_failure_result(&first, expected, &split_context);
            continue;
        }
        assert_eq!(
            first.state(),
            ConnectionState::Connecting,
            "{split_context}"
        );
        assert_eq!(first.outputs().len(), 0, "{split_context}");
        let second = core.step(CoreInput::Transport(TransportBytes::new(&request[split..])));
        assert_failure_result(&second, expected, &split_context);
    }
    request.len() + 1
}

fn assert_incomplete_at_every_split_then_eof(request: &[u8], context: &str) -> usize {
    for split in 0..=request.len() {
        let mut core = server();
        let split_context = format!("{context} split {split}");
        for (chunk_index, chunk) in [&request[..split], &request[split..]]
            .into_iter()
            .enumerate()
        {
            let partial = core.step(CoreInput::Transport(TransportBytes::new(chunk)));
            assert_eq!(
                partial.failure(),
                None,
                "{split_context} chunk {chunk_index}"
            );
            assert_eq!(
                partial.state(),
                ConnectionState::Connecting,
                "{split_context} chunk {chunk_index}"
            );
            assert_eq!(
                partial.outputs().len(),
                0,
                "{split_context} chunk {chunk_index}"
            );
        }
        let eof = core.step(CoreInput::TransportEof);
        assert_rejected_result(
            &eof,
            &HandshakeFailure::UnexpectedEof,
            &format!("{split_context} EOF"),
        );
    }
    request.len() + 1
}

fn assert_limit_result(result: &websocket_core::StepResult, expected: FailureKind, context: &str) {
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&expected),
        "{context}"
    );
    assert_eq!(result.state(), ConnectionState::Closed, "{context}");
    assert_eq!(
        result.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)],
        "{context}"
    );
}

fn decode_hex_seed(hex: &str) -> Vec<u8> {
    let compact: Vec<_> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(compact.len() % 2, 0, "seed hex must contain whole bytes");
    compact
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).expect("hex high nibble");
            let low = char::from(pair[1]).to_digit(16).expect("hex low nibble");
            u8::try_from(high * 16 + low).unwrap()
        })
        .collect()
}

fn encode_nonce_for_test(nonce: [u8; 16]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = [b'='; 24];
    let mut input = 0usize;
    let mut output = 0usize;
    while input + 3 <= nonce.len() {
        let first = nonce[input];
        let second = nonce[input + 1];
        let third = nonce[input + 2];
        encoded[output] = ALPHABET[usize::from(first >> 2)];
        encoded[output + 1] = ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))];
        encoded[output + 2] = ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))];
        encoded[output + 3] = ALPHABET[usize::from(third & 0x3f)];
        input += 3;
        output += 4;
    }
    encoded[output] = ALPHABET[usize::from(nonce[input] >> 2)];
    encoded[output + 1] = ALPHABET[usize::from((nonce[input] & 0x03) << 4)];
    String::from_utf8(encoded.to_vec()).unwrap()
}

#[test]
fn rfc_request_emits_canonical_response_before_open_and_descriptor() {
    let mut core = server();
    let result = core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));

    assert_eq!(result.failure(), None);
    assert_eq!(result.state(), ConnectionState::Open);
    assert_eq!(core.state(), ConnectionState::Open);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 3);
    let CoreOutput::TransportWrite(write) = outputs[0] else {
        panic!("the 101 transport write must be first");
    };
    assert_eq!(write.as_slice(), RFC_RESPONSE);
    assert!(
        !write
            .as_slice()
            .windows(6)
            .any(|window| window == b"Date: ")
    );
    assert!(
        !write
            .as_slice()
            .windows(8)
            .any(|window| window == b"Server: ")
    );
    assert_eq!(outputs[1], &CoreOutput::StateChanged(ConnectionState::Open));
    let CoreOutput::SemanticEvent(SemanticEvent::ServerHandshakeOpened { descriptor }) = outputs[2]
    else {
        panic!("the parser-produced descriptor event must be last");
    };
    assert_eq!(descriptor.request_target(), "/chat");
    assert_eq!(descriptor.host(), "server.example.com");
}

#[test]
fn all_39_frozen_client_request_cases_keep_exact_typed_verdicts() {
    assert_eq!(FROZEN_ACCEPTED.len(), 6);
    assert_eq!(FROZEN_REJECTED.len(), 26);
    assert_eq!(FROZEN_LIMIT_REJECTED.len(), 3);
    assert_eq!(FROZEN_INCOMPLETE.len(), 4);
    assert_eq!(
        FROZEN_ACCEPTED.len()
            + FROZEN_REJECTED.len()
            + FROZEN_LIMIT_REJECTED.len()
            + FROZEN_INCOMPLETE.len(),
        39
    );
    for case in FROZEN_ACCEPTED {
        let mut core = server();
        let result = core.step(CoreInput::Transport(TransportBytes::new(case.request)));
        assert_opened_result(&result, case.target, case.host, case.accept, case.id);
        assert_eq!(core.state(), ConnectionState::Open, "{}", case.id);
    }

    for case in FROZEN_REJECTED {
        let mut core = server();
        assert_fatal_handshake(&mut core, case.request, &case.expected, case.id);
    }

    for case in FROZEN_LIMIT_REJECTED {
        let (bytes, count, line) = case.limits;
        let mut core = server_with_limits(bytes, count, line);
        let result = core.step(CoreInput::Transport(TransportBytes::new(case.request)));
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&case.expected),
            "{}",
            case.id
        );
        assert_eq!(result.state(), ConnectionState::Closed, "{}", case.id);
        assert_eq!(
            result.outputs().collect::<Vec<_>>(),
            vec![&CoreOutput::StateChanged(ConnectionState::Closed)],
            "{}",
            case.id
        );
    }

    for (id, request) in FROZEN_INCOMPLETE {
        let mut core = server();
        let partial = core.step(CoreInput::Transport(TransportBytes::new(request)));
        assert_eq!(partial.failure(), None, "{id}");
        assert_eq!(partial.state(), ConnectionState::Connecting, "{id}");
        assert_eq!(partial.outputs().len(), 0, "{id}");

        let eof = core.step(CoreInput::TransportEof);
        assert_eq!(
            eof.failure().map(|failure| &failure.kind),
            Some(&FailureKind::Handshake(HandshakeFailure::UnexpectedEof)),
            "{id} EOF"
        );
        assert_eq!(eof.state(), ConnectionState::Closed, "{id} EOF");
        assert_eq!(
            eof.outputs().collect::<Vec<_>>(),
            vec![&CoreOutput::StateChanged(ConnectionState::Closed)],
            "{id} EOF"
        );
    }
}

#[test]
fn every_frozen_nonaccept_runs_at_every_two_chunk_split_with_exact_outcome() {
    let mut reject_executions = 0usize;
    for case in FROZEN_REJECTED {
        let expected = FailureKind::Handshake(case.expected.clone());
        reject_executions +=
            assert_failure_at_every_split_with(case.request, &expected, case.id, server);
    }

    let mut limit_executions = 0usize;
    for case in FROZEN_LIMIT_REJECTED {
        let (bytes, count, line) = case.limits;
        limit_executions +=
            assert_failure_at_every_split_with(case.request, &case.expected, case.id, || {
                server_with_limits(bytes, count, line)
            });
    }

    let mut incomplete_executions = 0usize;
    for (id, request) in FROZEN_INCOMPLETE {
        incomplete_executions += assert_incomplete_at_every_split_then_eof(request, id);
    }

    assert_eq!(
        reject_executions, 4_496,
        "bind frozen reject split executions"
    );
    assert_eq!(limit_executions, 522, "bind frozen limit split executions");
    assert_eq!(
        incomplete_executions, 265,
        "bind frozen EOF split executions"
    );
}

#[test]
fn every_frozen_accept_is_equivalent_at_every_two_chunk_split() {
    let mut executions = 0usize;
    for case in FROZEN_ACCEPTED {
        for split in 0..=case.request.len() {
            let mut core = server();
            let first = core.step(CoreInput::Transport(TransportBytes::new(
                &case.request[..split],
            )));
            let context = format!("{} split {split}", case.id);
            let result = if split == case.request.len() {
                first
            } else {
                assert_eq!(first.failure(), None, "{context} first chunk");
                assert_eq!(first.state(), ConnectionState::Connecting, "{context}");
                assert_eq!(first.outputs().len(), 0, "{context} first chunk");
                core.step(CoreInput::Transport(TransportBytes::new(
                    &case.request[split..],
                )))
            };
            assert_opened_result(&result, case.target, case.host, case.accept, &context);
            assert_eq!(core.state(), ConnectionState::Open, "{context}");
            executions += 1;
        }
    }
    assert_eq!(executions, 1_092, "contractual two-chunk executions");
}

#[test]
fn frozen_accepts_survive_bytewise_and_three_deterministic_chunk_plans() {
    for case in FROZEN_ACCEPTED {
        let mut bytewise = server();
        let mut result = None;
        for (index, byte) in case.request.iter().enumerate() {
            let step = bytewise.step(CoreInput::Transport(TransportBytes::new(
                core::slice::from_ref(byte),
            )));
            if index + 1 < case.request.len() {
                assert_eq!(step.failure(), None, "{} byte {index}", case.id);
                assert_eq!(step.outputs().len(), 0, "{} byte {index}", case.id);
            }
            result = Some(step);
        }
        assert_opened_result(
            &result.expect("accepted request is nonempty"),
            case.target,
            case.host,
            case.accept,
            &format!("{} bytewise", case.id),
        );

        let lengths = case.request.len();
        let plans = [
            vec![0, 1, lengths],
            vec![lengths / 3, lengths * 2 / 3, lengths],
            vec![4, 31.min(lengths), 97.min(lengths), lengths],
        ];
        for (plan_index, plan) in plans.iter().enumerate() {
            let mut core = server();
            let mut start = 0usize;
            let mut final_result = None;
            for &end in plan {
                let step = core.step(CoreInput::Transport(TransportBytes::new(
                    &case.request[start..end],
                )));
                if end < lengths {
                    assert_eq!(
                        step.failure(),
                        None,
                        "{} plan {plan_index} end {end}",
                        case.id
                    );
                    assert_eq!(
                        step.outputs().len(),
                        0,
                        "{} plan {plan_index} end {end}",
                        case.id
                    );
                }
                final_result = Some(step);
                start = end;
            }
            assert_opened_result(
                &final_result.expect("plan has a final boundary"),
                case.target,
                case.host,
                case.accept,
                &format!("{} plan {plan_index}", case.id),
            );
        }
    }
}

#[test]
fn request_line_method_version_and_origin_target_have_exact_classification() {
    let malformed: &[&[u8]] = &[
        b"",
        b" GET / HTTP/1.1",
        b"GET  / HTTP/1.1",
        b"GET /  HTTP/1.1",
        b"GET / HTTP/1.1 ",
        b"GET / HTTP/1.1 EXTRA",
        b"GET\t/ HTTP/1.1",
        b"GET /\tHTTP/1.1",
    ];
    for start in malformed {
        assert_rejected(
            &request_with(start, VALID_REQUEST_HEADERS),
            HandshakeFailure::MalformedRequestLine,
            &format!("malformed start {start:?}"),
        );
    }

    for start in [b"get / HTTP/1.1".as_slice(), b"HEAD / HTTP/1.1"] {
        assert_rejected(
            &request_with(start, VALID_REQUEST_HEADERS),
            HandshakeFailure::MethodNotGet,
            &format!("method start {start:?}"),
        );
    }

    for start in [
        b"GET / HTTP/1.0".as_slice(),
        b"GET / http/1.1",
        b"GET / HTTP/2",
    ] {
        assert_rejected(
            &request_with(start, VALID_REQUEST_HEADERS),
            HandshakeFailure::HttpVersionNot11,
            &format!("version start {start:?}"),
        );
    }

    for start in [
        b"GET http://example.com/chat HTTP/1.1".as_slice(),
        b"GET * HTTP/1.1",
        b"GET /chat#fragment HTTP/1.1",
        b"GET /chat\tmore HTTP/1.1",
        b"GET /chat\x1f HTTP/1.1",
        b"GET /chat\x7f HTTP/1.1",
        b"GET /chat\x80 HTTP/1.1",
    ] {
        assert_rejected(
            &request_with(start, VALID_REQUEST_HEADERS),
            HandshakeFailure::InvalidRequestTarget,
            &format!("target start {start:?}"),
        );
    }

    let request = request_with(b"GET /chat?next=%2Froom HTTP/1.1", VALID_REQUEST_HEADERS);
    let mut core = server();
    let result = core.step(CoreInput::Transport(TransportBytes::new(&request)));
    assert_opened_result(
        &result,
        "/chat?next=%2Froom",
        "server.example.com",
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "visible query and percent encoding",
    );
}

#[test]
fn header_syntax_and_host_boundaries_follow_validation_order() {
    let malformed: &[(&[u8], HandshakeFailure)] = &[
        (b"No-Colon", HandshakeFailure::MalformedHeader),
        (b": value", HandshakeFailure::MalformedHeader),
        (b"Ho st: value", HandshakeFailure::InvalidHeaderName),
        (b"Bad\"Name: value", HandshakeFailure::InvalidHeaderName),
        (b"Bad\x80Name: value", HandshakeFailure::InvalidHeaderName),
        (b" folded", HandshakeFailure::ObsoleteLineFolding),
        (b"\tfolded", HandshakeFailure::ObsoleteLineFolding),
        (
            b"X-Test: bad\x00value",
            HandshakeFailure::InvalidHeaderValueOctet,
        ),
        (
            b"X-Test: bad\x1fvalue",
            HandshakeFailure::InvalidHeaderValueOctet,
        ),
        (
            b"X-Test: bad\x7fvalue",
            HandshakeFailure::InvalidHeaderValueOctet,
        ),
    ];
    for (line, expected) in malformed {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        headers.insert(1, line);
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            expected.clone(),
            &format!("header syntax {line:?}"),
        );
    }

    let invalid_hosts: &[&[u8]] = &[
        b"Host:",
        b"Host: \t ",
        b"Host: two words",
        b"Host: two\twords",
        b"Host: first,second",
        b"Host: host\x80",
    ];
    for line in invalid_hosts {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        headers[0] = line;
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::InvalidHost,
            &format!("invalid host {line:?}"),
        );
    }
    for line in [b"Host: host\x01".as_slice(), b"Host: host\x7f"] {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        headers[0] = line;
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::InvalidHeaderValueOctet,
            &format!("syntactically forbidden host {line:?}"),
        );
    }

    let mut accepted_headers = VALID_REQUEST_HEADERS.to_vec();
    accepted_headers[0] = b"Host:\t server.example.com \t";
    accepted_headers.push(b"X-Observed:\tvisible\x80");
    let request = request_with(b"GET / HTTP/1.1", &accepted_headers);
    let mut core = server();
    let result = core.step(CoreInput::Transport(TransportBytes::new(&request)));
    assert_opened_result(
        &result,
        "/",
        "server.example.com",
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "Host OWS and unknown obs-text",
    );
}

#[test]
fn every_header_name_is_duplicate_checked_before_field_semantics() {
    let duplicate_additions: &[(&str, &[&[u8]])] = &[
        ("Host", &[b"hOsT: other.example"]),
        ("Upgrade", &[b"UPGRADE: websocket"]),
        ("Connection", &[b"connection: Upgrade"]),
        (
            "Sec-WebSocket-Key",
            &[b"SEC-WEBSOCKET-KEY: dGhlIHNhbXBsZSBub25jZQ=="],
        ),
        ("Sec-WebSocket-Version", &[b"sec-websocket-version: 13"]),
        ("unknown", &[b"X-Trace: one", b"x-tRaCe: two"]),
        (
            "Content-Length",
            &[b"Content-Length: 0", b"content-length: 0"],
        ),
        (
            "Transfer-Encoding",
            &[
                b"Transfer-Encoding: identity",
                b"TRANSFER-ENCODING: identity",
            ],
        ),
        (
            "Sec-WebSocket-Extensions",
            &[
                b"Sec-WebSocket-Extensions: x-one",
                b"sec-websocket-extensions: x-two",
            ],
        ),
        (
            "Sec-WebSocket-Protocol",
            &[
                b"Sec-WebSocket-Protocol: one",
                b"SEC-WEBSOCKET-PROTOCOL: two",
            ],
        ),
    ];
    for (name, additions) in duplicate_additions {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        headers.extend_from_slice(additions);
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::DuplicateHeader,
            &format!("duplicate {name}"),
        );
    }
}

#[test]
fn framing_negotiation_and_required_fields_have_stable_precedence() {
    let exclusions: &[(&[u8], HandshakeFailure)] = &[
        (
            b"Content-Length: 0",
            HandshakeFailure::UnexpectedContentLength,
        ),
        (
            b"Transfer-Encoding: identity",
            HandshakeFailure::UnexpectedTransferEncoding,
        ),
        (
            b"Sec-WebSocket-Extensions: permessage-deflate",
            HandshakeFailure::UnexpectedExtension,
        ),
        (
            b"Sec-WebSocket-Protocol: chat",
            HandshakeFailure::UnexpectedSubprotocol,
        ),
    ];
    for (line, expected) in exclusions {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        headers.push(line);
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            expected.clone(),
            &format!("excluded header {line:?}"),
        );
    }

    let headers = [
        b"Content-Length: 0".as_slice(),
        b"Later-Bad-Header",
        b"Host: server.example.com",
        b"Upgrade: websocket",
        b"Connection: Upgrade",
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        b"Sec-WebSocket-Version: 13",
    ];
    assert_rejected(
        &request_with(b"GET / HTTP/1.1", &headers),
        HandshakeFailure::MalformedHeader,
        "all header syntax precedes body framing semantics",
    );

    let headers = [
        b"Host: server.example.com".as_slice(),
        b"Upgrade: websocket",
        b"Connection: Upgrade",
        b"Sec-WebSocket-Version: 13",
        b"Sec-WebSocket-Extensions: x-test",
    ];
    assert_rejected(
        &request_with(b"GET / HTTP/1.1", &headers),
        HandshakeFailure::MissingKey,
        "required key precedes excluded negotiation",
    );
}

#[test]
fn upgrade_connection_and_version_require_exact_tokens_and_scalar_value() {
    let mut accepted = VALID_REQUEST_HEADERS.to_vec();
    accepted[1] = b"Upgrade:\t h2c, WebSocket \t";
    accepted[2] = b"Connection: keep-alive,\tUPGRADE";
    accepted[4] = b"Sec-WebSocket-Version:\t13 \t";
    let request = request_with(b"GET / HTTP/1.1", &accepted);
    let mut core = server();
    let result = core.step(CoreInput::Transport(TransportBytes::new(&request)));
    assert_opened_result(
        &result,
        "/",
        "server.example.com",
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "case-insensitive comma tokens and scalar OWS",
    );

    for value in [
        b"websocket,".as_slice(),
        b",websocket",
        b"h2c,,websocket",
        b"xwebsocket",
        b"\"websocket\"",
    ] {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        let mut line = b"Upgrade: ".to_vec();
        line.extend_from_slice(value);
        headers[1] = &line;
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::InvalidUpgrade,
            &format!("upgrade token list {value:?}"),
        );
    }

    for value in [
        b"upgrade,".as_slice(),
        b",upgrade",
        b"keep-alive,,upgrade",
        b"xupgrade",
        b"\"upgrade\"",
    ] {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        let mut line = b"Connection: ".to_vec();
        line.extend_from_slice(value);
        headers[2] = &line;
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::InvalidConnection,
            &format!("connection token list {value:?}"),
        );
    }

    for value in [b"+13".as_slice(), b"0013", b"13, 13", b"thirteen"] {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        let mut line = b"Sec-WebSocket-Version: ".to_vec();
        line.extend_from_slice(value);
        headers[4] = &line;
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::UnsupportedVersion,
            &format!("version scalar {value:?}"),
        );
    }
}

#[test]
fn websocket_key_distinguishes_encoding_from_decoded_length() {
    let mut accepted = VALID_REQUEST_HEADERS.to_vec();
    accepted[3] = b"Sec-WebSocket-Key:\t dGhlIHNhbXBsZSBub25jZQ== \t";
    let request = request_with(b"GET / HTTP/1.1", &accepted);
    let mut core = server();
    let result = core.step(CoreInput::Transport(TransportBytes::new(&request)));
    assert_opened_result(
        &result,
        "/",
        "server.example.com",
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "key outer OWS",
    );

    let invalid_encoding: &[&[u8]] = &[
        b"dGhlIHNhbXBsZSBub25jZQ-_",
        b"dGhlIHNhbXBsZSBub25jZQ",
        b"dGhlIHNhbXBsZSBub25jZQ=",
        b"dGhlIHNhbXBsZSBub25jZQ===",
        b"dGhlIHNhbXBs ZSBub25jZQ==",
        b"dGhlIHNhbXBs=ZSBub25jZQ=",
        b"AAAAAAAAAAAAAAAAAAAAAB==",
        b"!!!!!!!!!!!!!!!!!!!!!!!!",
    ];
    for value in invalid_encoding {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        let mut line = b"Sec-WebSocket-Key: ".to_vec();
        line.extend_from_slice(value);
        headers[3] = &line;
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::InvalidKeyEncoding,
            &format!("invalid key encoding {value:?}"),
        );
    }

    let wrong_lengths: &[(&[u8], u64)] = &[
        (b"", 0),
        (b"AAAA", 3),
        (b"SAuhh/j8UeHIPI/gvZGV", 15),
        (b"+HeopVrRQFMFI1vriQI0efI=", 17),
    ];
    for (value, decoded) in wrong_lengths {
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        let mut line = b"Sec-WebSocket-Key: ".to_vec();
        line.extend_from_slice(value);
        headers[3] = &line;
        assert_rejected(
            &request_with(b"GET / HTTP/1.1", &headers),
            HandshakeFailure::InvalidKeyLength { decoded: *decoded },
            &format!("decoded key length {decoded}"),
        );
    }
}

#[test]
fn selected_rejections_are_stable_across_every_two_chunk_split() {
    let cases: &[(&str, &[u8], HandshakeFailure)] = &[
        (
            "bare LF",
            b"GET / HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            HandshakeFailure::BareLineEnding,
        ),
        (
            "obsolete folding",
            b"GET / HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n folded\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            HandshakeFailure::ObsoleteLineFolding,
        ),
        (
            "duplicate casing",
            b"GET / HTTP/1.1\r\nHost: server.example.com\r\nhOsT: other.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            HandshakeFailure::DuplicateHeader,
        ),
        (
            "forbidden value control",
            b"GET / HTTP/1.1\r\nHost: server.example.com\r\nX-Bad: before\x7fafter\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            HandshakeFailure::InvalidHeaderValueOctet,
        ),
        (
            "noncanonical key pad bits",
            b"GET / HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAB==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            HandshakeFailure::InvalidKeyEncoding,
        ),
    ];
    for (name, request, expected) in cases {
        assert_rejected_at_every_split(request, expected.clone(), name);
    }
}

#[test]
fn every_additive_failure_vector_runs_at_every_two_chunk_split() {
    let cases = additive_failure_cases();
    assert_eq!(
        cases.len(),
        27,
        "24 non-EOF/suffix additive classes plus explicit control and DEL variants"
    );
    let mut executions = 0usize;
    for case in &cases {
        executions += if let Some((bytes, count, line)) = case.limits {
            assert_failure_at_every_split_with(&case.request, &case.expected, case.id, || {
                server_with_limits(bytes, count, line)
            })
        } else {
            assert_failure_at_every_split_with(&case.request, &case.expected, case.id, server)
        };
    }
    assert_eq!(executions, 4_557, "bind additive failure split executions");
}

#[test]
fn additive_partial_eof_runs_at_every_two_chunk_split() {
    let executions = assert_incomplete_at_every_split_then_eof(
        b"GET / HTTP/1.1\r\nHost: server.example.com\r",
        "partial-eof",
    );
    assert_eq!(executions, 42, "bind additive partial-EOF split executions");
}

#[test]
fn valid_plus_suffix_has_exact_results_at_every_transport_boundary() {
    let mut request = RFC_REQUEST.to_vec();
    request.push(b'x');
    let mut trailing_rejections = 0usize;
    let mut frame_boundary_executions = 0usize;
    for split in 0..=request.len() {
        let mut core = server();
        let first = core.step(CoreInput::Transport(TransportBytes::new(&request[..split])));
        let context = format!("valid-plus-suffix split {split}");
        if split < RFC_REQUEST.len() {
            assert_eq!(first.failure(), None, "{context} first chunk");
            assert_eq!(first.state(), ConnectionState::Connecting, "{context}");
            assert_eq!(first.outputs().len(), 0, "{context}");
            let second = core.step(CoreInput::Transport(TransportBytes::new(&request[split..])));
            assert_rejected_result(
                &second,
                &HandshakeFailure::TrailingData { bytes: 1 },
                &context,
            );
            trailing_rejections += 1;
        } else if split == RFC_REQUEST.len() {
            // CRLFCRLF is the protocol phase transition. At this one exact
            // transport boundary the first call is a complete valid handshake,
            // so the following byte is frame input; treating it as handshake
            // smuggling would contradict both incremental streaming and the
            // required one-call valid-handshake contract.
            assert_opened_result(
                &first,
                "/chat",
                "server.example.com",
                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                &context,
            );
            let second = core.step(CoreInput::Transport(TransportBytes::new(b"x")));
            assert_eq!(second.state(), ConnectionState::Open, "{context}");
            assert_eq!(second.outputs().len(), 0, "{context}");
            assert_eq!(second.failure(), None, "{context}");
            frame_boundary_executions += 1;
        } else {
            assert_rejected_result(
                &first,
                &HandshakeFailure::TrailingData { bytes: 1 },
                &context,
            );
            trailing_rejections += 1;
        }
    }
    assert_eq!(trailing_rejections, RFC_REQUEST.len() + 1);
    assert_eq!(frame_boundary_executions, 1);
}

#[test]
fn bare_line_endings_and_incomplete_crlf_are_not_normalized() {
    let bare: &[&[u8]] = &[
        b"GET / HTTP/1.1\nHost: server.example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: server.example.com\n\r\n",
        b"GET / HTTP/1.1\rX-Test: value\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: server.example.com\r\n\n",
    ];
    for request in bare {
        assert_rejected(
            request,
            HandshakeFailure::BareLineEnding,
            "bare line ending",
        );
    }

    let mut core = server();
    let partial = core.step(CoreInput::Transport(TransportBytes::new(
        b"GET / HTTP/1.1\r\nHost: server.example.com\r",
    )));
    assert_eq!(partial.failure(), None);
    assert_eq!(partial.state(), ConnectionState::Connecting);
    assert_eq!(partial.outputs().len(), 0);
    let eof = core.step(CoreInput::TransportEof);
    assert_rejected_result(&eof, &HandshakeFailure::UnexpectedEof, "partial CRLF EOF");
}

#[test]
fn same_step_suffix_is_smuggling_but_a_later_step_belongs_to_frames() {
    for suffix in [b"x".as_slice(), b"body", b"\x81\x00"] {
        let mut request = RFC_REQUEST.to_vec();
        request.extend_from_slice(suffix);
        assert_rejected(
            &request,
            HandshakeFailure::TrailingData {
                bytes: u64::try_from(suffix.len()).unwrap(),
            },
            &format!("same-step suffix {suffix:?}"),
        );
    }

    let mut core = server();
    let opened = core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
    assert_eq!(opened.state(), ConnectionState::Open);
    let later = core.step(CoreInput::Transport(TransportBytes::new(b"x")));
    assert_eq!(later.outputs().len(), 0);
    assert_eq!(later.state(), ConnectionState::Open);
    assert_eq!(later.failure(), None);
}

#[test]
fn request_and_response_limits_fail_at_the_exact_attempt_without_partial_write() {
    let total_max = u64::try_from(RFC_REQUEST.len() - 1).unwrap();
    let mut total = server_with_limits(total_max, 32, 512);
    let result = total.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeBytes,
            attempted: total_max + 1,
            maximum: total_max,
        },
        "request total bytes",
    );

    let request_line_len = b"GET /chat HTTP/1.1\r\n".len();
    let line_max = u64::try_from(request_line_len - 1).unwrap();
    let mut line = server_with_limits(512, 32, line_max);
    let result = line.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: u64::try_from(request_line_len).unwrap(),
            maximum: line_max,
        },
        "request line bytes",
    );

    let mut count = server_with_limits(512, 4, 512);
    let result = count.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderCount,
            attempted: 5,
            maximum: 4,
        },
        "request header count",
    );

    let mut response_line = server_with_limits(512, 32, 51);
    let result = response_line.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: 52,
            maximum: 51,
        },
        "canonical response line capacity",
    );

    let exact_bytes = u64::try_from(RFC_REQUEST.len()).unwrap();
    let mut exact = server_with_limits(exact_bytes, 5, 52);
    let result = exact.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
    assert_opened_result(
        &result,
        "/chat",
        "server.example.com",
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "exact request and response capacity",
    );
}

#[test]
fn arrival_limits_precede_line_framing_for_bytes_still_inside_the_head() {
    let request = b"GET\n";
    let mut core = server_with_limits(3, 32, 3);
    let result = core.step(CoreInput::Transport(TransportBytes::new(request)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeBytes,
            attempted: 4,
            maximum: 3,
        },
        "total arrival limit precedes line and bare-LF framing",
    );

    let request = b"GET\n";
    let mut core = server_with_limits(512, 32, 3);
    let result = core.step(CoreInput::Transport(TransportBytes::new(request)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: 4,
            maximum: 3,
        },
        "line arrival limit precedes bare-LF framing",
    );

    let request = b"GET / HTTP/1.1\r\nX: y\r\nXY\n";
    let mut core = server_with_limits(512, 1, 512);
    let result = core.step(CoreInput::Transport(TransportBytes::new(request)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderCount,
            attempted: 2,
            maximum: 1,
        },
        "header arrival limit precedes bare-LF framing",
    );
}

#[test]
fn bytes_after_the_online_head_terminator_are_only_trailing_data() {
    let long_suffix = vec![b'x'; 1_024];
    let mut request = RFC_REQUEST.to_vec();
    request.extend_from_slice(&long_suffix);
    let exact_head_bytes = u64::try_from(RFC_REQUEST.len()).unwrap();
    let mut core = server_with_limits(exact_head_bytes, 5, 52);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&request)));
    assert_rejected_result(
        &result,
        &HandshakeFailure::TrailingData { bytes: 1_024 },
        "long suffix is not fed through total or line accounting",
    );

    let mut request = RFC_REQUEST.to_vec();
    request.extend_from_slice(b"\r\n");
    let mut core = server_with_limits(exact_head_bytes, 5, 52);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&request)));
    assert_rejected_result(
        &result,
        &HandshakeFailure::TrailingData { bytes: 2 },
        "CRLF suffix is not fed through header accounting",
    );
}

#[test]
fn wrong_role_and_terminal_failures_are_non_mutating_or_single_transition() {
    let descriptor = ClientRequestDescriptor::try_new("/", "example.com").unwrap();
    let mut wrong_role = server();
    let wrong = wrong_role.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor,
        nonce: [0; 16],
    }));
    assert_eq!(
        wrong.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(HandshakeFailure::WrongRole))
    );
    assert_eq!(wrong.outputs().len(), 0);
    assert_eq!(wrong.state(), ConnectionState::Connecting);
    let opened = wrong_role.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
    assert_eq!(opened.failure(), None, "wrong-role command did not mutate");
    assert_eq!(opened.state(), ConnectionState::Open);

    let mut fatal = server();
    assert_fatal_handshake(
        &mut fatal,
        &request_with(b"GET / HTTP/1.1", &VALID_REQUEST_HEADERS[1..]),
        &HandshakeFailure::MissingHost,
        "initial fatal request",
    );
    let repeated_inputs = [
        CoreInput::Transport(TransportBytes::new(b"ignored")),
        CoreInput::Command(LocalCommand::SendText {
            payload: "ignored".into(),
            mask_key: None,
        }),
    ];
    let expected_kinds = [InputKind::TransportBytes, InputKind::LocalCommand];
    for (input, input_kind) in repeated_inputs.into_iter().zip(expected_kinds) {
        let repeated = fatal.step(input);
        assert_eq!(repeated.outputs().len(), 0, "no repeated Closed transition");
        assert_eq!(repeated.state(), ConnectionState::Closed);
        assert_eq!(
            repeated.failure().map(|failure| &failure.kind),
            Some(&FailureKind::InvalidState {
                input: input_kind,
                state: ConnectionState::Closed,
            })
        );
    }
    let repeated_eof = fatal.step(CoreInput::TransportEof);
    assert_eq!(repeated_eof.outputs().len(), 0);
    assert_eq!(
        repeated_eof.failure().map(|failure| &failure.kind),
        Some(&FailureKind::InvalidState {
            input: InputKind::TransportEof,
            state: ConnectionState::Closed,
        })
    );
    assert_eq!(repeated_eof.state(), ConnectionState::Closed);
}

#[test]
fn every_committed_us011_fuzz_seed_replays_in_the_normal_test_harness() {
    let ordinary = [
        (
            include_str!("../fuzz-seeds/us011/bare-lf.hex"),
            HandshakeFailure::BareLineEnding,
        ),
        (
            include_str!("../fuzz-seeds/us011/obs-fold.hex"),
            HandshakeFailure::ObsoleteLineFolding,
        ),
        (
            include_str!("../fuzz-seeds/us011/invalid-header-name.hex"),
            HandshakeFailure::InvalidHeaderName,
        ),
        (
            include_str!("../fuzz-seeds/us011/forbidden-value-control.hex"),
            HandshakeFailure::InvalidHeaderValueOctet,
        ),
        (
            include_str!("../fuzz-seeds/us011/malformed-request-line.hex"),
            HandshakeFailure::MalformedRequestLine,
        ),
        (
            include_str!("../fuzz-seeds/us011/duplicate-casing.hex"),
            HandshakeFailure::DuplicateHeader,
        ),
        (
            include_str!("../fuzz-seeds/us011/content-length.hex"),
            HandshakeFailure::UnexpectedContentLength,
        ),
        (
            include_str!("../fuzz-seeds/us011/transfer-encoding.hex"),
            HandshakeFailure::UnexpectedTransferEncoding,
        ),
        (
            include_str!("../fuzz-seeds/us011/noncanonical-key.hex"),
            HandshakeFailure::InvalidKeyEncoding,
        ),
        (
            include_str!("../fuzz-seeds/us011/wrong-key-length.hex"),
            HandshakeFailure::InvalidKeyLength { decoded: 3 },
        ),
        (
            include_str!("../fuzz-seeds/us011/extension.hex"),
            HandshakeFailure::UnexpectedExtension,
        ),
        (
            include_str!("../fuzz-seeds/us011/subprotocol.hex"),
            HandshakeFailure::UnexpectedSubprotocol,
        ),
        (
            include_str!("../fuzz-seeds/us011/valid-plus-suffix.hex"),
            HandshakeFailure::TrailingData { bytes: 1 },
        ),
    ];
    assert_eq!(ordinary.len() + 4, 17, "exact US-011 fuzz-seed inventory");
    for (hex, expected) in ordinary {
        assert_rejected(&decode_hex_seed(hex), expected, "US-011 fuzz seed");
    }

    let incomplete = decode_hex_seed(include_str!("../fuzz-seeds/us011/incomplete-crlf.hex"));
    let mut partial = server();
    let result = partial.step(CoreInput::Transport(TransportBytes::new(&incomplete)));
    assert_eq!(result.failure(), None);
    assert_eq!(result.state(), ConnectionState::Connecting);
    assert_eq!(result.outputs().len(), 0);
    let eof = partial.step(CoreInput::TransportEof);
    assert_rejected_result(
        &eof,
        &HandshakeFailure::UnexpectedEof,
        "incomplete CRLF seed EOF",
    );

    let total_seed = decode_hex_seed(include_str!("../fuzz-seeds/us011/total-limit.hex"));
    let mut total = server_with_limits(8, 32, 8);
    let result = total.step(CoreInput::Transport(TransportBytes::new(&total_seed)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeBytes,
            attempted: 9,
            maximum: 8,
        },
        "total-limit seed",
    );

    let line_seed = decode_hex_seed(include_str!("../fuzz-seeds/us011/line-limit.hex"));
    let mut line = server_with_limits(16, 32, 8);
    let result = line.step(CoreInput::Transport(TransportBytes::new(&line_seed)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: 9,
            maximum: 8,
        },
        "line-limit seed",
    );

    let count_seed = decode_hex_seed(include_str!("../fuzz-seeds/us011/count-limit.hex"));
    let mut count = server_with_limits(128, 2, 64);
    let result = count.step(CoreInput::Transport(TransportBytes::new(&count_seed)));
    assert_limit_result(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderCount,
            attempted: 3,
            maximum: 2,
        },
        "count-limit seed",
    );
}

#[test]
fn all_256_deterministic_nonce_literals_produce_the_bound_accept() {
    assert_eq!(DETERMINISTIC_NONCE_VECTORS.len(), 256);
    for (index, (key, accept)) in DETERMINISTIC_NONCE_VECTORS.iter().enumerate() {
        let mut nonce = [0u8; 16];
        nonce[0] = u8::try_from(index).unwrap();
        for (offset, byte) in nonce[1..].iter_mut().enumerate() {
            *byte = u8::try_from(offset + 1).unwrap();
        }
        assert_eq!(
            encode_nonce_for_test(nonce),
            *key,
            "vector {index} canonical key literal"
        );

        let key_line = format!("Sec-WebSocket-Key: {key}");
        let mut headers = VALID_REQUEST_HEADERS.to_vec();
        headers[3] = key_line.as_bytes();
        let request = request_with(b"GET / HTTP/1.1", &headers);
        let mut core = server();
        let result = core.step(CoreInput::Transport(TransportBytes::new(&request)));
        assert_opened_result(
            &result,
            "/",
            "server.example.com",
            accept,
            &format!("deterministic nonce vector {index}"),
        );
    }
}
