// Generated-style executable projection of the immutable US-005 client-request corpus.
// Keep these bytes, configs, IDs, and typed outcomes byte-for-byte bound by the Go verifier.

struct AcceptedCase {
    id: &'static str,
    request: &'static [u8],
    target: &'static str,
    host: &'static str,
    accept: &'static str,
}

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

const FROZEN_REJECTED: &[RejectedCase] = &[
    RejectedCase { id: "us005.hs.0009", request: b"POST /socket/5b3f37e9 HTTP/1.1\r\nHost: host-0ad129.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: rdf/Vdz7u194QyUq8UqjnQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MethodNotGet },
    RejectedCase { id: "us005.hs.0010", request: b"PATCH /socket/93696543 HTTP/1.1\r\nHost: host-49479a.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: nnXLojOVE/H+2puIu7oPMg==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MethodNotGet },
    RejectedCase { id: "us005.hs.0011", request: b"GET /socket/57bc6398 HTTP/1.0\r\nHost: host-0ac690.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: A5XD2FQHBBdNKLhgcpy0Jg==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::HttpVersionNot11 },
    RejectedCase { id: "us005.hs.0012", request: b"GET /socket/0bc85662 HTTP/0.9\r\nHost: host-e9dd68.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: q/0btOMI93rVrwC/MD1rZg==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::HttpVersionNot11 },
    RejectedCase { id: "us005.hs.0013", request: b"GET /socket/bc222588 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: XUYk1mXXA9OhuxuQUQ+wzA==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MissingHost },
    RejectedCase { id: "us005.hs.0014", request: b"GET /socket/493c1331 HTTP/1.1\r\nHost: host-cbb0f4.example\r\nConnection: Upgrade\r\nSec-WebSocket-Key: SCPi02IOLd+GSS/91L6fFg==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MissingUpgrade },
    RejectedCase { id: "us005.hs.0015", request: b"GET /socket/16b3421d HTTP/1.1\r\nHost: host-5f4c66.example\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Key: rBW+QoYgml7QcJFiZys0MA==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidUpgrade },
    RejectedCase { id: "us005.hs.0016", request: b"GET /socket/51bbaf33 HTTP/1.1\r\nHost: host-8b3eec.example\r\nUpgrade: websocket\r\nSec-WebSocket-Key: tHCAJHSgOWYS4ZfxXQOCkQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MissingConnection },
    RejectedCase { id: "us005.hs.0017", request: b"GET /socket/c4a69599 HTTP/1.1\r\nHost: host-f2b643.example\r\nUpgrade: websocket\r\nConnection: close\r\nSec-WebSocket-Key: ZD4kYPEBWd+3QlGrev6kEA==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidConnection },
    RejectedCase { id: "us005.hs.0018", request: b"GET /socket/c1084034 HTTP/1.1\r\nHost: host-b33e93.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MissingKey },
    RejectedCase { id: "us005.hs.0019", request: b"GET /socket/cf05ae18 HTTP/1.1\r\nHost: host-cdfd9f.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: !!definitely-not-base64!!\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidKeyEncoding },
    RejectedCase { id: "us005.hs.0020", request: b"GET /socket/7711e644 HTTP/1.1\r\nHost: host-0dd581.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAB==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidKeyEncoding },
    RejectedCase { id: "us005.hs.0021", request: b"GET /socket/5a54954b HTTP/1.1\r\nHost: host-4215f6.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: SAuhh/j8UeHIPI/gvZGV\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidKeyLength { decoded: 15 } },
    RejectedCase { id: "us005.hs.0022", request: b"GET /socket/071471f2 HTTP/1.1\r\nHost: host-9a0170.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: +HeopVrRQFMFI1vriQI0efI=\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidKeyLength { decoded: 17 } },
    RejectedCase { id: "us005.hs.0023", request: b"GET /socket/6a4520a0 HTTP/1.1\r\nHost: host-81b1be.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 4bpjwF/qdXcVYK7UOziKCw==\r\n\r\n", expected: HandshakeFailure::MissingVersion },
    RejectedCase { id: "us005.hs.0024", request: b"GET /socket/c5972a17 HTTP/1.1\r\nHost: host-78cd54.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: DzW2kVDFD5P3xyMek8D5lg==\r\nSec-WebSocket-Version: 8\r\n\r\n", expected: HandshakeFailure::UnsupportedVersion },
    RejectedCase { id: "us005.hs.0025", request: b"GET /socket/e8e5f7b0 HTTP/1.1\r\nHost: host-cc27af.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: KtBVA9xsiffKpX5BnyoidQ==\r\nSec-WebSocket-Version: 25\r\n\r\n", expected: HandshakeFailure::UnsupportedVersion },
    RejectedCase { id: "us005.hs.0026", request: b"GET /socket/2159306b HTTP/1.1\r\nHost: host-8de687.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 9jVJgJuZ9DG3DXBCSFr5jQ==\r\nSec-WebSocket-Version: thirteen\r\n\r\n", expected: HandshakeFailure::UnsupportedVersion },
    RejectedCase { id: "us005.hs.0027", request: b"GET /socket/8818b25c HTTP/1.1\r\nHost: host-42696a.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: O5iC0fKQ8ZOGGnj6378RzA==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: tUtJ1SeJVEMjVnbjq+Rrww==\r\n\r\n", expected: HandshakeFailure::DuplicateHeader },
    RejectedCase { id: "us005.hs.0028", request: b"GET /socket/e6e838b2 HTTP/1.1\r\nHost: host-6dbc3c.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: otGd1aCMl/5OcPa6PUn94Q==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::DuplicateHeader },
    RejectedCase { id: "us005.hs.0029", request: b"GET /socket/b96895cb HTTP/1.1\r\nHost: host-e3ecfc.example\r\nHo st: value\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: mjpm6WeARCpV3weGy/bUMQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidHeaderName },
    RejectedCase { id: "us005.hs.0030", request: b"GET /socket/bd716c09 HTTP/1.1\r\nHost: host-8e3dd5.example\r\nBad\"Name: value\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: y2KUD8utTRfionlFWtAE8w==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::InvalidHeaderName },
    RejectedCase { id: "us005.hs.0031", request: b"GET/socket/2a16c8efHTTP/1.1\r\nHost: host-630f83.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: WILob3gr75EnRjqPeKzQgw==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MalformedRequestLine },
    RejectedCase { id: "us005.hs.0032", request: b"GET /socket/de62ba26 HTTP/1.1 EXTRA\r\nHost: host-0ef998.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: H33u6p8DNf7HyUKabncFUw==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::MalformedRequestLine },
    RejectedCase { id: "us005.hs.0033", request: b"GET /socket/260ca67e HTTP/1.1\r\nHost: host-102897.example\r\nUpgrade: websocket\r\n folded\r\nConnection: Upgrade\r\nSec-WebSocket-Key: RAM4MWM7kAaTxQksCbFVTQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::ObsoleteLineFolding },
    RejectedCase { id: "us005.hs.0034", request: b"GET /socket/698e008f HTTP/1.1\r\nHost: host-0747ec.example\r\nUpgrade: websocket\nConnection: Upgrade\r\nSec-WebSocket-Key: OcYAoJS7KZefnro/h5wtdQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", expected: HandshakeFailure::BareLineEnding },
];

const FROZEN_LIMIT_REJECTED: &[LimitRejectedCase] = &[
    LimitRejectedCase { id: "us005.hs.0046", request: b"GET /socket/876dfbbb HTTP/1.1\r\nHost: host-d43e71.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: /7OJGY5kekmjxqFeaXJHNA==\r\nSec-WebSocket-Version: 13\r\n\r\n", limits: (172, 32, 512), expected: FailureKind::LimitExceeded { limit: LimitKind::HandshakeBytes, attempted: 173, maximum: 172 } },
    LimitRejectedCase { id: "us005.hs.0047", request: b"GET /socket/b37cab12 HTTP/1.1\r\nHost: host-2e56d8.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: cx0GmW1gIo11UF+Iy6laEg==\r\nSec-WebSocket-Version: 13\r\n\r\n", limits: (4096, 2, 512), expected: FailureKind::LimitExceeded { limit: LimitKind::HandshakeHeaderCount, attempted: 3, maximum: 2 } },
    LimitRejectedCase { id: "us005.hs.0048", request: b"GET /socket/cae58096 HTTP/1.1\r\nHost: host-ec7e68.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 0zXKEJtnv0uzTt/59lt2hw==\r\nSec-WebSocket-Version: 13\r\n\r\n", limits: (4096, 32, 8), expected: FailureKind::LimitExceeded { limit: LimitKind::HandshakeHeaderLineBytes, attempted: 9, maximum: 8 } },
];

const FROZEN_INCOMPLETE: &[(&str, &[u8])] = &[
    ("us005.hs.0042", b""),
    ("us005.hs.0043", b"GET "),
    ("us005.hs.0044", b"GET /socket/de986365 HTTP/1.1\r\nHost: host-3492ce.example\r\nUpgrade: websocket\r\nConnecti"),
    ("us005.hs.0045", b"GET /socket/bc5d2f48 HTTP/1.1\r\nHost: host-940e8d.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 8EN68pA9fcRVZshqZSTqIg==\r\nSec-WebSocket-Version: 13\r\n"),
];
