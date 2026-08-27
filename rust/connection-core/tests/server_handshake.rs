#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState,
    CoreInput, CoreOutput, FailureKind, HandshakeFailure, InputKind, LimitKind, LocalCommand,
    ProtocolStory, Role, SemanticEvent, TransportBytes,
};

fn server() -> ConnectionCore {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    ConnectionCore::new(config, Role::Server)
}

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

include!("data/us011_nonce_vectors.rs");

struct AcceptedCase {
    id: &'static str,
    request: &'static [u8],
    target: &'static str,
    host: &'static str,
    accept: &'static str,
}

const FROZEN_ACCEPTED: &[AcceptedCase] = &[
    AcceptedCase {
        id: "us005.hs.0000",
        request: b"GET /socket/35ae55c9 HTTP/1.1\r\nHost: host-87cb10.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 7Qg8Jw3qQL4ERr/n83YN7w==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        target: "/socket/35ae55c9",
        host: "host-87cb10.example",
        accept: "FJGDqEtc/7v2gIxV23nYHrpYQtU=",
    },
    AcceptedCase {
        id: "us005.hs.0001",
        request: b"GET /socket/b65a0c5d HTTP/1.1\r\nHost: host-f94b92.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ELk6s4dWP8nDk6qRlvVz3A==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        target: "/socket/b65a0c5d",
        host: "host-f94b92.example",
        accept: "xxh//UeNk5UT6CLqbMYJVwJ8Jc4=",
    },
    AcceptedCase {
        id: "us005.hs.0002",
        request: b"GET /socket/de57cda0 HTTP/1.1\r\nHost: host-7bfc5e.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 5a/f98AIO67dkJ4kgDPQ0g==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        target: "/socket/de57cda0",
        host: "host-7bfc5e.example",
        accept: "anmPZy77QwJDJ7Gam1zzXE72gAc=",
    },
    AcceptedCase {
        id: "us005.hs.0003",
        request: b"GET /socket/e54adc81 HTTP/1.1\r\nHost: host-f616f2.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: TAUt2mybLrjVItMi/PIXCg==\r\nSec-WebSocket-Version: 13\r\nX-Extra-Header: @5XdJ]\r\n\r\n",
        target: "/socket/e54adc81",
        host: "host-f616f2.example",
        accept: "pJ19F7Oh+pYlj5U+C286qNuOEeQ=",
    },
    AcceptedCase {
        id: "us005.hs.0004",
        request: b"GET /socket/93c0d2eb HTTP/1.1\r\nhost: host-2d50b4.example\r\nupgrade: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\nsec-websocket-key: 4Qqb0izhQnRB4yw5/nY/JA==\r\nSEC-WEBSOCKET-VERSION: 13\r\n\r\n",
        target: "/socket/93c0d2eb",
        host: "host-2d50b4.example",
        accept: "uuqWQd/HmgjQOusWnTAHszJRdXM=",
    },
    AcceptedCase {
        id: "us005.hs.0005",
        request: b"GET /socket/7646f8da HTTP/1.1\r\nhost: host-49e263.example\r\nupgrade: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\nsec-websocket-key: qgwmbNU3c74Mss3OSOX86w==\r\nSEC-WEBSOCKET-VERSION: 13\r\n\r\n",
        target: "/socket/7646f8da",
        host: "host-49e263.example",
        accept: "0DpjBmMlKH2/656/MjJUAA8jbvA=",
    },
];

struct RejectedCase {
    id: &'static str,
    request: &'static [u8],
    expected: HandshakeFailure,
}

struct LimitRejectedCase {
    id: &'static str,
    request: &'static [u8],
    limits: (u64, u64, u64),
    expected: FailureKind,
}

const FROZEN_REJECTED: &[RejectedCase] = &[
    RejectedCase {
        id: "us005.hs.0009",
        request: b"POST /socket/5b3f37e9 HTTP/1.1\r\nHost: host-0ad129.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: rdf/Vdz7u194QyUq8UqjnQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MethodNotGet,
    },
    RejectedCase {
        id: "us005.hs.0010",
        request: b"PATCH /socket/93696543 HTTP/1.1\r\nHost: host-49479a.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: nnXLojOVE/H+2puIu7oPMg==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MethodNotGet,
    },
    RejectedCase {
        id: "us005.hs.0011",
        request: b"GET /socket/57bc6398 HTTP/1.0\r\nHost: host-0ac690.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: A5XD2FQHBBdNKLhgcpy0Jg==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::HttpVersionNot11,
    },
    RejectedCase {
        id: "us005.hs.0012",
        request: b"GET /socket/0bc85662 HTTP/0.9\r\nHost: host-e9dd68.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: q/0btOMI93rVrwC/MD1rZg==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::HttpVersionNot11,
    },
    RejectedCase {
        id: "us005.hs.0013",
        request: b"GET /socket/bc222588 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: XUYk1mXXA9OhuxuQUQ+wzA==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MissingHost,
    },
    RejectedCase {
        id: "us005.hs.0014",
        request: b"GET /socket/493c1331 HTTP/1.1\r\nHost: host-cbb0f4.example\r\nConnection: Upgrade\r\nSec-WebSocket-Key: SCPi02IOLd+GSS/91L6fFg==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MissingUpgrade,
    },
    RejectedCase {
        id: "us005.hs.0015",
        request: b"GET /socket/16b3421d HTTP/1.1\r\nHost: host-5f4c66.example\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Key: rBW+QoYgml7QcJFiZys0MA==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidUpgrade,
    },
    RejectedCase {
        id: "us005.hs.0016",
        request: b"GET /socket/51bbaf33 HTTP/1.1\r\nHost: host-8b3eec.example\r\nUpgrade: websocket\r\nSec-WebSocket-Key: tHCAJHSgOWYS4ZfxXQOCkQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MissingConnection,
    },
    RejectedCase {
        id: "us005.hs.0017",
        request: b"GET /socket/c4a69599 HTTP/1.1\r\nHost: host-f2b643.example\r\nUpgrade: websocket\r\nConnection: close\r\nSec-WebSocket-Key: ZD4kYPEBWd+3QlGrev6kEA==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidConnection,
    },
    RejectedCase {
        id: "us005.hs.0018",
        request: b"GET /socket/c1084034 HTTP/1.1\r\nHost: host-b33e93.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MissingKey,
    },
    RejectedCase {
        id: "us005.hs.0019",
        request: b"GET /socket/cf05ae18 HTTP/1.1\r\nHost: host-cdfd9f.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: !!definitely-not-base64!!\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidKeyEncoding,
    },
    RejectedCase {
        id: "us005.hs.0020",
        request: b"GET /socket/7711e644 HTTP/1.1\r\nHost: host-0dd581.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAB==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidKeyEncoding,
    },
    RejectedCase {
        id: "us005.hs.0021",
        request: b"GET /socket/5a54954b HTTP/1.1\r\nHost: host-4215f6.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: SAuhh/j8UeHIPI/gvZGV\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidKeyLength { decoded: 15 },
    },
    RejectedCase {
        id: "us005.hs.0022",
        request: b"GET /socket/071471f2 HTTP/1.1\r\nHost: host-9a0170.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: +HeopVrRQFMFI1vriQI0efI=\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidKeyLength { decoded: 17 },
    },
    RejectedCase {
        id: "us005.hs.0023",
        request: b"GET /socket/6a4520a0 HTTP/1.1\r\nHost: host-81b1be.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 4bpjwF/qdXcVYK7UOziKCw==\r\n\r\n",
        expected: HandshakeFailure::MissingVersion,
    },
    RejectedCase {
        id: "us005.hs.0024",
        request: b"GET /socket/c5972a17 HTTP/1.1\r\nHost: host-78cd54.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: DzW2kVDFD5P3xyMek8D5lg==\r\nSec-WebSocket-Version: 8\r\n\r\n",
        expected: HandshakeFailure::UnsupportedVersion,
    },
    RejectedCase {
        id: "us005.hs.0025",
        request: b"GET /socket/e8e5f7b0 HTTP/1.1\r\nHost: host-cc27af.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: KtBVA9xsiffKpX5BnyoidQ==\r\nSec-WebSocket-Version: 25\r\n\r\n",
        expected: HandshakeFailure::UnsupportedVersion,
    },
    RejectedCase {
        id: "us005.hs.0026",
        request: b"GET /socket/2159306b HTTP/1.1\r\nHost: host-8de687.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 9jVJgJuZ9DG3DXBCSFr5jQ==\r\nSec-WebSocket-Version: thirteen\r\n\r\n",
        expected: HandshakeFailure::UnsupportedVersion,
    },
    RejectedCase {
        id: "us005.hs.0027",
        request: b"GET /socket/8818b25c HTTP/1.1\r\nHost: host-42696a.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: O5iC0fKQ8ZOGGnj6378RzA==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: tUtJ1SeJVEMjVnbjq+Rrww==\r\n\r\n",
        expected: HandshakeFailure::DuplicateHeader,
    },
    RejectedCase {
        id: "us005.hs.0028",
        request: b"GET /socket/e6e838b2 HTTP/1.1\r\nHost: host-6dbc3c.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: otGd1aCMl/5OcPa6PUn94Q==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::DuplicateHeader,
    },
    RejectedCase {
        id: "us005.hs.0029",
        request: b"GET /socket/b96895cb HTTP/1.1\r\nHost: host-e3ecfc.example\r\nHo st: value\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: mjpm6WeARCpV3weGy/bUMQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidHeaderName,
    },
    RejectedCase {
        id: "us005.hs.0030",
        request: b"GET /socket/bd716c09 HTTP/1.1\r\nHost: host-8e3dd5.example\r\nBad\"Name: value\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: y2KUD8utTRfionlFWtAE8w==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::InvalidHeaderName,
    },
    RejectedCase {
        id: "us005.hs.0031",
        request: b"GET/socket/2a16c8efHTTP/1.1\r\nHost: host-630f83.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: WILob3gr75EnRjqPeKzQgw==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MalformedRequestLine,
    },
    RejectedCase {
        id: "us005.hs.0032",
        request: b"GET /socket/de62ba26 HTTP/1.1 EXTRA\r\nHost: host-0ef998.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: H33u6p8DNf7HyUKabncFUw==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::MalformedRequestLine,
    },
    RejectedCase {
        id: "us005.hs.0033",
        request: b"GET /socket/260ca67e HTTP/1.1\r\nHost: host-102897.example\r\nUpgrade: websocket\r\n folded\r\nConnection: Upgrade\r\nSec-WebSocket-Key: RAM4MWM7kAaTxQksCbFVTQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::ObsoleteLineFolding,
    },
    RejectedCase {
        id: "us005.hs.0034",
        request: b"GET /socket/698e008f HTTP/1.1\r\nHost: host-0747ec.example\r\nUpgrade: websocket\nConnection: Upgrade\r\nSec-WebSocket-Key: OcYAoJS7KZefnro/h5wtdQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        expected: HandshakeFailure::BareLineEnding,
    },
];

const FROZEN_LIMIT_REJECTED: &[LimitRejectedCase] = &[
    LimitRejectedCase {
        id: "us005.hs.0046",
        request: b"GET /socket/876dfbbb HTTP/1.1\r\nHost: host-d43e71.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: /7OJGY5kekmjxqFeaXJHNA==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        limits: (172, 32, 512),
        expected: FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeBytes,
            attempted: 173,
            maximum: 172,
        },
    },
    LimitRejectedCase {
        id: "us005.hs.0047",
        request: b"GET /socket/b37cab12 HTTP/1.1\r\nHost: host-2e56d8.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: cx0GmW1gIo11UF+Iy6laEg==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        limits: (4096, 2, 512),
        expected: FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderCount,
            attempted: 3,
            maximum: 2,
        },
    },
    LimitRejectedCase {
        id: "us005.hs.0048",
        request: b"GET /socket/cae58096 HTTP/1.1\r\nHost: host-ec7e68.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 0zXKEJtnv0uzTt/59lt2hw==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        limits: (4096, 32, 8),
        expected: FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: 9,
            maximum: 8,
        },
    },
];

const FROZEN_INCOMPLETE: &[(&str, &[u8])] = &[
    ("us005.hs.0042", b""),
    ("us005.hs.0043", b"GET "),
    (
        "us005.hs.0044",
        b"GET /socket/de986365 HTTP/1.1\r\nHost: host-3492ce.example\r\nUpgrade: websocket\r\nConnecti",
    ),
    (
        "us005.hs.0045",
        b"GET /socket/bc5d2f48 HTTP/1.1\r\nHost: host-940e8d.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 8EN68pA9fcRVZshqZSTqIg==\r\nSec-WebSocket-Version: 13\r\n",
    ),
];

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

fn assert_rejected(request: &[u8], expected: HandshakeFailure, context: &str) {
    let mut core = server();
    assert_fatal_handshake(&mut core, request, &expected, context);
}

fn assert_rejected_result(
    result: &websocket_core::StepResult,
    expected: &HandshakeFailure,
    context: &str,
) {
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

fn assert_rejected_at_every_split(request: &[u8], expected: HandshakeFailure, context: &str) {
    for split in 0..=request.len() {
        let mut core = server();
        let first = core.step(CoreInput::Transport(TransportBytes::new(&request[..split])));
        let split_context = format!("{context} split {split}");
        if first.failure().is_some() {
            assert_rejected_result(&first, &expected, &split_context);
            continue;
        }
        assert_eq!(
            first.state(),
            ConnectionState::Connecting,
            "{split_context}"
        );
        assert_eq!(first.outputs().len(), 0, "{split_context}");
        let second = core.step(CoreInput::Transport(TransportBytes::new(&request[split..])));
        assert_rejected_result(&second, &expected, &split_context);
    }
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
    assert_eq!(
        later.failure().map(|failure| &failure.kind),
        Some(&FailureKind::ProtocolSliceUnavailable {
            owner_story: ProtocolStory::FrameCoding,
        })
    );
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
        CoreInput::TransportEof,
        CoreInput::Command(LocalCommand::SendText("ignored".into())),
    ];
    let expected_kinds = [
        InputKind::TransportBytes,
        InputKind::TransportEof,
        InputKind::LocalCommand,
    ];
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
