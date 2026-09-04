//! US-009 AC3 tests: explicit limits, checked conversions, deterministic
//! defaults; zero, boundary, and oversized values for every limit.
//!
//! The limit table's oracle-tier ceilings come from java-oracle/README.md
//! ("A request cannot relax the 1 MiB line/input/buffer ceilings, the
//! 1,024-action ceiling, 4,096-frame ceiling, or 4 MiB output ceiling");
//! handshake defaults come from corpora/handshake/cases.jsonl config
//! (4096 / 32 / 512); queue capacities are port-side constants (the bounded
//! ownership boundary of AC4).

use ws_core::config::{ConfigError, ConfigErrorKind, ConnectionConfig, LimitField};

/// Apply `value` to the builder field named by `field`.
fn set(
    builder: ws_core::config::ConnectionConfigBuilder,
    field: LimitField,
    value: u64,
) -> ws_core::config::ConnectionConfigBuilder {
    match field {
        LimitField::MaxHandshakeBytes => builder.max_handshake_bytes(value),
        LimitField::MaxHeaderCount => builder.max_header_count(value),
        LimitField::MaxHeaderLineBytes => builder.max_header_line_bytes(value),
        LimitField::MaxFramePayloadBytes => builder.max_frame_payload_bytes(value),
        LimitField::MaxMessageBytes => builder.max_message_bytes(value),
        LimitField::MaxBufferedBytes => builder.max_buffered_bytes(value),
        LimitField::MaxInputBytes => builder.max_input_bytes(value),
        LimitField::MaxActions => builder.max_actions(value),
        LimitField::MaxFrames => builder.max_frames(value),
        LimitField::MaxOutputBytes => builder.max_output_bytes(value),
        LimitField::EventQueueCapacity => builder.event_queue_capacity(value),
        LimitField::CommandQueueCapacity => builder.command_queue_capacity(value),
        LimitField::WriteQueueCapacity => builder.write_queue_capacity(value),
    }
}

/// Read the built config's value for `field`.
fn get(config: &ConnectionConfig, field: LimitField) -> u64 {
    match field {
        LimitField::MaxHandshakeBytes => config.max_handshake_bytes() as u64,
        LimitField::MaxHeaderCount => config.max_header_count() as u64,
        LimitField::MaxHeaderLineBytes => config.max_header_line_bytes() as u64,
        LimitField::MaxFramePayloadBytes => config.max_frame_payload_bytes() as u64,
        LimitField::MaxMessageBytes => config.max_message_bytes() as u64,
        LimitField::MaxBufferedBytes => config.max_buffered_bytes() as u64,
        LimitField::MaxInputBytes => config.max_input_bytes() as u64,
        LimitField::MaxActions => config.max_actions(),
        LimitField::MaxFrames => config.max_frames(),
        LimitField::MaxOutputBytes => config.max_output_bytes() as u64,
        LimitField::EventQueueCapacity => config.event_queue_capacity() as u64,
        LimitField::CommandQueueCapacity => config.command_queue_capacity() as u64,
        LimitField::WriteQueueCapacity => config.write_queue_capacity() as u64,
    }
}

#[test]
fn default_table_is_pinned_exactly() {
    // Deterministic defaults (US-009 design draft section 4): identical on
    // every construction, byte-for-byte.
    let config = ConnectionConfig::default();
    assert_eq!(config.max_handshake_bytes(), 4096);
    assert_eq!(config.max_header_count(), 32);
    assert_eq!(config.max_header_line_bytes(), 512);
    assert_eq!(config.max_frame_payload_bytes(), 65_536);
    assert_eq!(config.max_message_bytes(), 65_536);
    assert_eq!(config.max_buffered_bytes(), 65_536);
    assert_eq!(config.max_input_bytes(), 65_536);
    assert_eq!(config.max_actions(), 64);
    assert_eq!(config.max_frames(), 64);
    assert_eq!(config.max_output_bytes(), 4_194_304);
    assert_eq!(config.event_queue_capacity(), 64);
    assert_eq!(config.command_queue_capacity(), 64);
    assert_eq!(config.write_queue_capacity(), 64);
    assert_eq!(config.mask_key_seed(), 0);
    // The builder with no setters reproduces the same table.
    let built = ConnectionConfig::builder()
        .build()
        .expect("default builder must produce the pinned default table");
    assert_eq!(built, config);
}

#[test]
fn limit_field_table_is_pinned() {
    // The limit metadata table drives every boundary test below; pin it so a
    // silent min/ceiling drift is a test failure, not a surprise.
    use LimitField as F;
    let expect: [(F, u64, u64, u64); 13] = [
        (F::MaxHandshakeBytes, 1, 4096, 1_048_576),
        (F::MaxHeaderCount, 1, 32, 1024),
        (F::MaxHeaderLineBytes, 1, 512, 65_536),
        (F::MaxFramePayloadBytes, 1, 65_536, 1_048_576),
        (F::MaxMessageBytes, 1, 65_536, 1_048_576),
        (F::MaxBufferedBytes, 1, 65_536, 1_048_576),
        (F::MaxInputBytes, 1, 65_536, 1_048_576),
        (F::MaxActions, 0, 64, 1024),
        (F::MaxFrames, 1, 64, 4096),
        (F::MaxOutputBytes, 512, 4_194_304, 4_194_304),
        // Ceiling raised for US-012 multi-frame decoding: one byte input
        // can complete the whole remaining frame budget, so single-drain
        // owners need EVENT_SLOTS_PER_FRAME * (max_frames + 1) + 1 slots
        // (8195 at the max_frames ceiling).
        (F::EventQueueCapacity, 4, 64, 16_384),
        (F::CommandQueueCapacity, 1, 64, 4096),
        (F::WriteQueueCapacity, 1, 64, 4096),
    ];
    assert_eq!(LimitField::ALL.len(), expect.len());
    for (field, minimum, default, ceiling) in expect {
        assert_eq!(field.minimum(), minimum, "{field:?} minimum");
        assert_eq!(field.default_value(), default, "{field:?} default");
        assert_eq!(field.ceiling(), ceiling, "{field:?} ceiling");
        assert!(LimitField::ALL.contains(&field));
    }
}

#[test]
fn zero_is_rejected_exactly_where_the_minimum_is_positive() {
    for field in LimitField::ALL {
        let result = set(ConnectionConfig::builder(), field, 0).build();
        if field.minimum() == 0 {
            // max_actions: the corpus schema minimum is 0 (a scenario may
            // forbid all actions), so zero must build.
            let config = result.unwrap_or_else(|err| {
                panic!("{field:?} = 0 must be accepted (schema minimum 0): {err}")
            });
            assert_eq!(get(&config, field), 0);
        } else {
            let err = result.expect_err(&format!("{field:?} = 0 must be rejected"));
            assert_eq!(
                err,
                ConfigError {
                    field,
                    value: 0,
                    kind: ConfigErrorKind::BelowMinimum {
                        minimum: field.minimum()
                    },
                }
            );
        }
    }
}

#[test]
fn boundary_values_build_and_are_readable_back() {
    for field in LimitField::ALL {
        for value in [field.minimum(), field.ceiling()] {
            let config = set(ConnectionConfig::builder(), field, value)
                .build()
                .unwrap_or_else(|err| panic!("{field:?} = {value} must build: {err}"));
            assert_eq!(get(&config, field), value, "{field:?} round-trip");
        }
        if field.minimum() > 0 {
            let below = field.minimum() - 1;
            assert!(
                set(ConnectionConfig::builder(), field, below)
                    .build()
                    .is_err(),
                "{field:?} = {below} (minimum-1) must be rejected"
            );
        }
    }
}

#[test]
fn oversized_values_are_rejected_with_the_ceiling_named() {
    for field in LimitField::ALL {
        for value in [field.ceiling() + 1, u64::MAX] {
            let err = set(ConnectionConfig::builder(), field, value)
                .build()
                .expect_err(&format!("{field:?} = {value} must be rejected"));
            assert_eq!(
                err,
                ConfigError {
                    field,
                    value,
                    kind: ConfigErrorKind::AboveCeiling {
                        ceiling: field.ceiling()
                    },
                }
            );
        }
    }
}

#[test]
fn config_error_display_is_deterministic() {
    let err = ConnectionConfig::builder()
        .max_input_bytes(0)
        .build()
        .expect_err("zero max_input_bytes must fail");
    assert_eq!(
        err.to_string(),
        "max_input_bytes = 0 is below the minimum 1"
    );
    let err = ConnectionConfig::builder()
        .max_actions(1025)
        .build()
        .expect_err("over-ceiling max_actions must fail");
    assert_eq!(
        err.to_string(),
        "max_actions = 1025 is above the ceiling 1024"
    );
}

#[test]
fn mask_key_seed_is_configuration_not_a_limit() {
    // The injected deterministic mask-key seed (design draft section 1.4,
    // quirk Q28: mask keys are never observable) accepts any u64.
    let config = ConnectionConfig::builder()
        .mask_key_seed(u64::MAX)
        .build()
        .expect("any seed is valid");
    assert_eq!(config.mask_key_seed(), u64::MAX);
}

#[test]
fn config_is_immutable_after_build() {
    // ConnectionConfig exposes no mutating API; this is a compile-shape
    // guarantee. Cloning yields an equal value (immutability + value
    // semantics for the AC2 constructor).
    let config = ConnectionConfig::default();
    let clone = config.clone();
    assert_eq!(config, clone);
}
