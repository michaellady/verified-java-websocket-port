//! Strict one-record neutral differential transport.
//!
//! This module decodes only the versioned process envelope. All WebSocket
//! behavior is delegated to `websocket-driver` and `websocket-core`.

use std::io::{Read, Write};

use websocket_core::{
    BehaviorProfile, ClientRequestDescriptor, CloseFailure, ConnectionConfig, ConnectionLimits,
    ConnectionState, FailureKind, FragmentFailure, FragmentKind, FrameDirection, FrameFailure,
    LimitKind, LocalCommand, QueueKind, Role, SemanticEvent, TransportBytes, TypedProtocolFailure,
    Utf8Failure,
};
use websocket_driver::{
    ClosedObservationInput, CommandDisposition, ConnectionOwner, DriverInput, DriverOutput,
    EnqueueError, InputDisposition, connection_driver,
};

const MAX_RECORD_BYTES: usize = 4_194_304;
const MAX_STEPS: usize = 64;
const MAX_TURNS: usize = 4_096;
const CLIENT_CLOSE: &[u8] = b"\x88\x82\x01\x02\x03\x04\x02\xea";
const SERVER_CLOSE: &[u8] = b"\x88\x02\x03\xe8";
const CLIENT_PEER_CLOSE_MASK_KEY: [u8; 4] = [1, 2, 3, 4];
const ABNORMAL_EOF_REASON: &str = "transport EOF before close handshake completed";

/// Opaque fail-closed neutral-transport rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeutralError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitialState {
    Open,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Limits {
    max_actions: u64,
    max_buffered: u64,
    max_frames: u64,
    max_input: u64,
    max_output: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyedPayload {
    mask_key: Option<[u8; 4]>,
    payload: Box<[u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Step {
    Bytes(Box<[u8]>),
    Eof,
    Text(KeyedPayload),
    Binary(KeyedPayload),
    Fragment {
        kind: FragmentKind,
        final_fragment: bool,
        keyed: KeyedPayload,
    },
    Ping(KeyedPayload),
    Pong(KeyedPayload),
    Close {
        mask_key: Option<[u8; 4]>,
        code: Option<u16>,
        reason: Box<str>,
    },
}

impl Step {
    const fn input_tag(&self) -> u8 {
        match self {
            Self::Bytes(_) => 1,
            Self::Eof => 2,
            Self::Text(_) => 0x10,
            Self::Binary(_) => 0x11,
            Self::Fragment { .. } => 0x12,
            Self::Ping(_) => 0x13,
            Self::Pong(_) => 0x14,
            Self::Close { .. } => 0x15,
        }
    }

    const fn is_action(&self) -> bool {
        !matches!(self, Self::Bytes(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Request {
    scenario_id: String,
    role: Role,
    initial_state: InitialState,
    limits: Limits,
    steps: Vec<Step>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Accounting {
    pre: ConnectionState,
    post: ConnectionState,
    consumed: u64,
    wire_buffered: u64,
    message_buffered: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CloseRecord {
    code: Option<u16>,
    reason: String,
    clean: bool,
    origin: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Observation {
    Event(u8, Vec<u8>),
    Frame {
        direction: u8,
        fin: bool,
        opcode: u8,
        masked: bool,
        payload: Box<[u8]>,
        wire_length: u64,
    },
    Transition(ConnectionState, ConnectionState),
    Close(CloseRecord),
    Error {
        terminal: bool,
        class: &'static str,
    },
    Transport {
        direction: u8,
        bytes: Box<[u8]>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StepResponse {
    index: u16,
    input_tag: u8,
    accounting: Accounting,
    observations: Vec<Observation>,
}

#[derive(Debug)]
struct Session {
    handle: websocket_driver::CommandHandle,
    owner: ConnectionOwner,
    state: ConnectionState,
    core_sequence: u64,
    scenario_close: Option<CloseRecord>,
}

/// Runs exactly one bounded `NDRV1` request and emits exactly one `NOBS1` response.
pub fn run_neutral(mut input: impl Read, mut output: impl Write) -> Result<(), NeutralError> {
    run_neutral_with_profile(&mut input, &mut output, BehaviorProfile::Rfc6455Strict)
}

/// Runs one bounded neutral request under an explicitly selected behavior profile.
///
/// The strict profile remains the default differential and conformance surface.
/// Callers must opt into Java-WebSocket compatibility when measuring source-port
/// behavioral parity.
pub fn run_neutral_with_profile(
    mut input: impl Read,
    mut output: impl Write,
    behavior_profile: BehaviorProfile,
) -> Result<(), NeutralError> {
    let request = read_request(&mut input)?;
    let config = config_for(request.limits, behavior_profile)?;
    let (mut session, bootstrap) = bootstrap(request.role, request.initial_state, config)?;
    let mut responses = Vec::new();
    responses
        .try_reserve_exact(request.steps.len())
        .map_err(|_| NeutralError)?;
    let mut action_count = 0_u64;
    let mut input_count = 0_u64;
    let mut frame_count = 0_u64;
    let mut output_count = 0_u64;
    let mut terminal_close = None;

    for (index, step) in request.steps.iter().enumerate() {
        let mut intake_failure = None;
        if step.is_action() {
            action_count = action_count.checked_add(1).ok_or(NeutralError)?;
            if action_count > request.limits.max_actions {
                intake_failure = Some("ACTION_LIMIT_EXCEEDED");
            }
        }
        if let Step::Bytes(bytes) = step {
            let attempted = input_count
                .checked_add(u64::try_from(bytes.len()).map_err(|_| NeutralError)?)
                .ok_or(NeutralError)?;
            if attempted > request.limits.max_input {
                intake_failure = Some("INPUT_LIMIT_EXCEEDED");
            } else {
                input_count = attempted;
            }
        }
        if let Some(class) = intake_failure {
            responses.push(limit_step_response(
                &session,
                u16::try_from(index).map_err(|_| NeutralError)?,
                step,
                class,
            )?);
            break;
        }
        let mut response = drive_scenario_step(
            &mut session,
            u16::try_from(index).map_err(|_| NeutralError)?,
            step,
            request.initial_state,
            request.role,
            behavior_profile,
        )?;
        let mut limited_observations = Vec::new();
        let mut step_limit = None;
        for observation in response.observations {
            match observation {
                Observation::Frame { .. } => {
                    let attempted = frame_count.checked_add(1).ok_or(NeutralError)?;
                    if attempted > request.limits.max_frames {
                        step_limit = Some("FRAME_LIMIT_EXCEEDED");
                        continue;
                    }
                    frame_count = attempted;
                }
                Observation::Transport {
                    direction: 2,
                    ref bytes,
                } => {
                    let attempted = output_count
                        .checked_add(u64::try_from(bytes.len()).map_err(|_| NeutralError)?)
                        .ok_or(NeutralError)?;
                    if attempted > request.limits.max_output {
                        step_limit = Some("OUTPUT_LIMIT_EXCEEDED");
                        continue;
                    }
                    output_count = attempted;
                }
                Observation::Close(ref close) => terminal_close = Some(close.clone()),
                _ => {}
            }
            limited_observations.push(observation);
        }
        if let Some(class) = step_limit {
            limited_observations.retain(|observation| {
                !matches!(
                    observation,
                    Observation::Event(_, _) | Observation::Error { .. }
                )
            });
            limited_observations.push(Observation::Error {
                terminal: false,
                class,
            });
            response.observations = limited_observations;
            session.state = response.accounting.post;
            responses.push(response);
            break;
        }
        response.observations = limited_observations;
        session.state = response.accounting.post;
        responses.push(response);
    }

    let body = encode_response(
        &request,
        &bootstrap,
        &responses,
        session.state,
        terminal_close,
    )?;
    let length = u32::try_from(body.len()).map_err(|_| NeutralError)?;
    output
        .write_all(&length.to_be_bytes())
        .map_err(|_| NeutralError)?;
    output.write_all(&body).map_err(|_| NeutralError)?;
    output.flush().map_err(|_| NeutralError)
}

fn read_request(input: &mut impl Read) -> Result<Request, NeutralError> {
    let mut bytes = Vec::new();
    input
        .take(u64::try_from(MAX_RECORD_BYTES + 5).map_err(|_| NeutralError)?)
        .read_to_end(&mut bytes)
        .map_err(|_| NeutralError)?;
    if bytes.len() < 4 || bytes.len() > MAX_RECORD_BYTES + 4 {
        return Err(NeutralError);
    }
    let declared = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| NeutralError)?) as usize;
    if declared > MAX_RECORD_BYTES || declared != bytes.len() - 4 {
        return Err(NeutralError);
    }
    decode_request(&bytes[4..])
}

fn decode_request(body: &[u8]) -> Result<Request, NeutralError> {
    if !body.starts_with(b"NDRV1") {
        return Err(NeutralError);
    }
    let fields = decode_tlvs(&body[5..], &[1, 2, 3, 4, 5])?;
    let scenario = fields[0];
    if scenario.is_empty()
        || scenario.len() > 128
        || !scenario
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
    {
        return Err(NeutralError);
    }
    let role = match fields[1] {
        [1] => Role::Client,
        [2] => Role::Server,
        _ => return Err(NeutralError),
    };
    let initial_state = match fields[2] {
        [1] => InitialState::Open,
        [2] => InitialState::Closing,
        [3] => InitialState::Closed,
        _ => return Err(NeutralError),
    };
    if fields[3].len() != 40 {
        return Err(NeutralError);
    }
    let mut limits_cursor = Cursor::new(fields[3]);
    let limits = Limits {
        max_actions: limits_cursor.u64()?,
        max_buffered: limits_cursor.u64()?,
        max_frames: limits_cursor.u64()?,
        max_input: limits_cursor.u64()?,
        max_output: limits_cursor.u64()?,
    };
    if limits.max_actions == 0
        || limits.max_actions > MAX_STEPS as u64
        || limits.max_buffered == 0
        || limits.max_buffered > 1_048_576
        || limits.max_frames == 0
        || limits.max_frames > 4_096
        || limits.max_input == 0
        || limits.max_input > MAX_RECORD_BYTES as u64
        || limits.max_output == 0
        || limits.max_output > MAX_RECORD_BYTES as u64
        || !limits_cursor.is_empty()
    {
        return Err(NeutralError);
    }
    let steps = decode_steps(fields[4], role)?;
    Ok(Request {
        scenario_id: String::from_utf8(scenario.to_vec()).map_err(|_| NeutralError)?,
        role,
        initial_state,
        limits,
        steps,
    })
}

fn decode_tlvs<'a>(bytes: &'a [u8], required: &[u8]) -> Result<Vec<&'a [u8]>, NeutralError> {
    let mut cursor = Cursor::new(bytes);
    let mut values = Vec::new();
    values
        .try_reserve_exact(required.len())
        .map_err(|_| NeutralError)?;
    for expected in required {
        if cursor.u8()? != *expected {
            return Err(NeutralError);
        }
        let length = usize::try_from(cursor.u32()?).map_err(|_| NeutralError)?;
        values.push(cursor.take(length)?);
    }
    if !cursor.is_empty() {
        return Err(NeutralError);
    }
    Ok(values)
}

fn decode_steps(bytes: &[u8], role: Role) -> Result<Vec<Step>, NeutralError> {
    let mut cursor = Cursor::new(bytes);
    let count = usize::from(cursor.u16()?);
    if count > MAX_STEPS {
        return Err(NeutralError);
    }
    let mut steps = Vec::new();
    steps.try_reserve_exact(count).map_err(|_| NeutralError)?;
    for _ in 0..count {
        let length = usize::try_from(cursor.u32()?).map_err(|_| NeutralError)?;
        let record = cursor.take(length)?;
        steps.push(decode_step(record, role)?);
    }
    if !cursor.is_empty() {
        return Err(NeutralError);
    }
    Ok(steps)
}

fn decode_step(bytes: &[u8], role: Role) -> Result<Step, NeutralError> {
    let mut cursor = Cursor::new(bytes);
    let tag = cursor.u8()?;
    match tag {
        1 => Ok(Step::Bytes(cursor.take_rest().to_vec().into_boxed_slice())),
        2 if cursor.is_empty() => Ok(Step::Eof),
        0x10 => Ok(Step::Text(decode_keyed(cursor, role, true)?)),
        0x11 => Ok(Step::Binary(decode_keyed(cursor, role, false)?)),
        0x12 => {
            let kind = match cursor.u8()? {
                1 => FragmentKind::Text,
                2 => FragmentKind::Binary,
                _ => return Err(NeutralError),
            };
            let final_fragment = decode_bool(cursor.u8()?)?;
            Ok(Step::Fragment {
                kind,
                final_fragment,
                keyed: decode_keyed(cursor, role, false)?,
            })
        }
        0x13 => Ok(Step::Ping(decode_keyed(cursor, role, false)?)),
        0x14 => Ok(Step::Pong(decode_keyed(cursor, role, false)?)),
        0x15 => {
            let mask_key = decode_key(&mut cursor, role)?;
            let code = match cursor.u8()? {
                0 => None,
                1 => Some(cursor.u16()?),
                _ => return Err(NeutralError),
            };
            let reason = core::str::from_utf8(cursor.take_rest())
                .map_err(|_| NeutralError)?
                .to_owned()
                .into_boxed_str();
            Ok(Step::Close {
                mask_key,
                code,
                reason,
            })
        }
        _ => Err(NeutralError),
    }
}

fn decode_keyed(
    mut cursor: Cursor<'_>,
    role: Role,
    utf8: bool,
) -> Result<KeyedPayload, NeutralError> {
    let mask_key = decode_key(&mut cursor, role)?;
    let payload = cursor.take_rest();
    if utf8 {
        core::str::from_utf8(payload).map_err(|_| NeutralError)?;
    }
    Ok(KeyedPayload {
        mask_key,
        payload: payload.to_vec().into_boxed_slice(),
    })
}

fn decode_key(cursor: &mut Cursor<'_>, role: Role) -> Result<Option<[u8; 4]>, NeutralError> {
    let key = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.take(4)?.try_into().map_err(|_| NeutralError)?),
        _ => return Err(NeutralError),
    };
    if (role == Role::Client) != key.is_some() {
        return Err(NeutralError);
    }
    Ok(key)
}

fn config_for(
    limits: Limits,
    behavior_profile: BehaviorProfile,
) -> Result<ConnectionConfig, NeutralError> {
    ConnectionConfig::try_from(ConnectionLimits {
        frame_bytes: limits.max_buffered,
        message_bytes: limits.max_buffered,
        total_buffered_bytes: limits.max_buffered,
        ..ConnectionLimits::default()
    })
    .map(|config| config.with_behavior_profile(behavior_profile))
    .map_err(|_| NeutralError)
}

fn bootstrap(
    role: Role,
    initial_state: InitialState,
    config: ConnectionConfig,
) -> Result<(Session, Vec<Observation>), NeutralError> {
    let (canonical_request, canonical_response) = handshake_material(config.clone())?;
    let (handle, owner) = connection_driver(config, role);
    let mut session = Session {
        handle,
        owner,
        state: ConnectionState::Connecting,
        core_sequence: 0,
        scenario_close: None,
    };
    let mut transcript = Vec::new();
    match role {
        Role::Client => {
            let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com")
                .map_err(|_| NeutralError)?;
            let _ = drive_command(
                &mut session,
                LocalCommand::StartClientHandshake {
                    descriptor,
                    nonce: *b"the sample nonce",
                },
                &mut transcript,
                true,
            )?;
            transcript.push(Observation::Transport {
                direction: 1,
                bytes: canonical_response.clone().into_boxed_slice(),
            });
            let _ = drive_input(
                &mut session,
                NeutralDriverInput::Inbound(&canonical_response),
                &mut transcript,
                true,
                false,
            )?;
        }
        Role::Server => {
            transcript.push(Observation::Transport {
                direction: 1,
                bytes: canonical_request.clone().into_boxed_slice(),
            });
            let _ = drive_input(
                &mut session,
                NeutralDriverInput::Inbound(&canonical_request),
                &mut transcript,
                true,
                false,
            )?;
        }
    }
    if session.owner.state() != ConnectionState::Open {
        return Err(NeutralError);
    }
    session.state = ConnectionState::Open;
    if matches!(initial_state, InitialState::Closing | InitialState::Closed) {
        let _ = drive_command(
            &mut session,
            LocalCommand::Close {
                code: Some(1000),
                reason: "".into(),
                mask_key: (role == Role::Client).then_some([1, 2, 3, 4]),
            },
            &mut transcript,
            true,
        )?;
        if session.owner.state() != ConnectionState::Closing {
            return Err(NeutralError);
        }
        session.state = ConnectionState::Closing;
    }
    if initial_state == InitialState::Closed {
        let peer_close = match role {
            Role::Client => SERVER_CLOSE,
            Role::Server => CLIENT_CLOSE,
        };
        transcript.push(Observation::Transport {
            direction: 1,
            bytes: peer_close.to_vec().into_boxed_slice(),
        });
        let _ = drive_input(
            &mut session,
            NeutralDriverInput::Inbound(peer_close),
            &mut transcript,
            true,
            false,
        )?;
        if session.owner.state() != ConnectionState::Closed {
            return Err(NeutralError);
        }
        session.state = ConnectionState::Closed;
    }
    Ok((session, transcript))
}

fn handshake_material(config: ConnectionConfig) -> Result<(Vec<u8>, Vec<u8>), NeutralError> {
    let (client_handle, client_owner) = connection_driver(config.clone(), Role::Client);
    let mut client = Session {
        handle: client_handle,
        owner: client_owner,
        state: ConnectionState::Connecting,
        core_sequence: 0,
        scenario_close: None,
    };
    let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com")
        .map_err(|_| NeutralError)?;
    let mut client_observations = Vec::new();
    let _ = drive_command(
        &mut client,
        LocalCommand::StartClientHandshake {
            descriptor,
            nonce: *b"the sample nonce",
        },
        &mut client_observations,
        true,
    )?;
    let request = first_outbound_transport(&client_observations)?;

    let (server_handle, server_owner) = connection_driver(config, Role::Server);
    let mut server = Session {
        handle: server_handle,
        owner: server_owner,
        state: ConnectionState::Connecting,
        core_sequence: 0,
        scenario_close: None,
    };
    let mut server_observations = Vec::new();
    let _ = drive_input(
        &mut server,
        NeutralDriverInput::Inbound(&request),
        &mut server_observations,
        true,
        false,
    )?;
    let response = first_outbound_transport(&server_observations)?;
    Ok((request, response))
}

fn first_outbound_transport(observations: &[Observation]) -> Result<Vec<u8>, NeutralError> {
    observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Transport {
                direction: 2,
                bytes,
            } => Some(bytes.to_vec()),
            _ => None,
        })
        .ok_or(NeutralError)
}

fn drive_scenario_step(
    session: &mut Session,
    index: u16,
    step: &Step,
    _initial_state: InitialState,
    role: Role,
    behavior_profile: BehaviorProfile,
) -> Result<StepResponse, NeutralError> {
    let pre = session.owner.state();
    let mut observations = Vec::new();
    let accounting = if pre == ConnectionState::Closed {
        let result = match step {
            Step::Bytes(bytes) => session
                .owner
                .observe_closed(ClosedObservationInput::Inbound(TransportBytes::new(bytes))),
            Step::Eof => session
                .owner
                .observe_closed(ClosedObservationInput::TransportEof),
            _ => None,
        }
        .ok_or(NeutralError)?;
        let accounting = capture_latest_core(session, &mut observations)?.ok_or(NeutralError)?;
        if let Some(failure) = result.failure {
            observations.push(error_observation(&failure));
        }
        accounting
    } else {
        match step {
            Step::Bytes(bytes) => drive_input(
                session,
                NeutralDriverInput::Inbound(bytes),
                &mut observations,
                false,
                false,
            )?,
            Step::Eof => drive_input(
                session,
                NeutralDriverInput::Eof,
                &mut observations,
                false,
                false,
            )?,
            _ => drive_command(session, command_for(step)?, &mut observations, false)?,
        }
    };

    acknowledge_peer_close(role, session, &mut observations, behavior_profile)?;

    if let Step::Close { code, reason, .. } = step
        && !observations
            .iter()
            .any(|observation| matches!(observation, Observation::Error { .. }))
    {
        append_close_observations(
            CloseRecord {
                code: *code,
                reason: reason.to_string(),
                clean: false,
                origin: 1,
            },
            &mut observations,
        )?;
    }
    if matches!(step, Step::Eof) {
        project_eof(pre, session.scenario_close.as_ref(), &mut observations)?;
    }
    if let Some(close) = observations
        .iter()
        .rev()
        .find_map(|observation| match observation {
            Observation::Close(close) => Some(close.clone()),
            _ => None,
        })
    {
        session.scenario_close = Some(close);
    }

    Ok(StepResponse {
        index,
        input_tag: step.input_tag(),
        accounting: Accounting {
            pre,
            post: session.owner.state(),
            ..accounting
        },
        observations,
    })
}

fn acknowledge_peer_close(
    role: Role,
    session: &mut Session,
    observations: &mut Vec<Observation>,
    behavior_profile: BehaviorProfile,
) -> Result<(), NeutralError> {
    if role != Role::Client || session.owner.state() != ConnectionState::Closing {
        return Ok(());
    }
    let Some(close) = observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Close(close) if close.origin == 2 => Some(close.clone()),
            _ => None,
        })
    else {
        return Ok(());
    };
    let (code, reason) = if behavior_profile == BehaviorProfile::JavaWebSocketV1_6_0 {
        (Some(1000), String::new())
    } else {
        (close.code, close.reason)
    };
    let _ = drive_command(
        session,
        LocalCommand::Close {
            code,
            reason: reason.into_boxed_str(),
            mask_key: Some(CLIENT_PEER_CLOSE_MASK_KEY),
        },
        observations,
        false,
    )?;
    Ok(())
}

fn limit_step_response(
    session: &Session,
    index: u16,
    step: &Step,
    class: &'static str,
) -> Result<StepResponse, NeutralError> {
    let state = session.owner.state();
    let (wire_buffered, message_buffered) =
        session
            .owner
            .last_core_observation()
            .map_or((0, 0), |observation| {
                let accounting = observation.accounting();
                (
                    u64::try_from(accounting.wire_buffered_bytes).unwrap_or(u64::MAX),
                    u64::try_from(accounting.message_buffered_bytes).unwrap_or(u64::MAX),
                )
            });
    if wire_buffered == u64::MAX || message_buffered == u64::MAX {
        return Err(NeutralError);
    }
    Ok(StepResponse {
        index,
        input_tag: step.input_tag(),
        accounting: Accounting {
            pre: state,
            post: state,
            consumed: 0,
            wire_buffered,
            message_buffered,
        },
        observations: vec![Observation::Error {
            terminal: false,
            class,
        }],
    })
}

fn project_eof(
    pre: ConnectionState,
    prior_close: Option<&CloseRecord>,
    observations: &mut Vec<Observation>,
) -> Result<(), NeutralError> {
    let projected = observations.iter().any(|observation| {
        matches!(
            observation,
            Observation::Error {
                class: "CLOSE_UNEXPECTED_EOF_OPEN"
                    | "CLOSE_EOF_BEFORE_PEER"
                    | "CLOSE_EOF_BEFORE_ACK"
                    | "CLOSE_EOF_BEFORE_FLUSH",
                ..
            }
        )
    });
    if !projected {
        return Ok(());
    }
    observations.retain(|observation| {
        !matches!(
            observation,
            Observation::Error {
                class: "CLOSE_UNEXPECTED_EOF_OPEN"
                    | "CLOSE_EOF_BEFORE_PEER"
                    | "CLOSE_EOF_BEFORE_ACK"
                    | "CLOSE_EOF_BEFORE_FLUSH",
                ..
            }
        )
    });
    let mut close = if pre == ConnectionState::Closing {
        prior_close.cloned().unwrap_or(CloseRecord {
            code: Some(1006),
            reason: ABNORMAL_EOF_REASON.to_owned(),
            clean: false,
            origin: 5,
        })
    } else {
        CloseRecord {
            code: Some(1006),
            reason: ABNORMAL_EOF_REASON.to_owned(),
            clean: false,
            origin: 5,
        }
    };
    close.clean = false;
    close.origin = 5;
    append_close_observations(close, observations)
}

fn command_for(step: &Step) -> Result<LocalCommand, NeutralError> {
    Ok(match step {
        Step::Text(keyed) => LocalCommand::SendText {
            payload: core::str::from_utf8(&keyed.payload)
                .map_err(|_| NeutralError)?
                .to_owned()
                .into_boxed_str(),
            mask_key: keyed.mask_key,
        },
        Step::Binary(keyed) => LocalCommand::SendBinary {
            payload: keyed.payload.clone(),
            mask_key: keyed.mask_key,
        },
        Step::Fragment {
            kind,
            final_fragment,
            keyed,
        } => LocalCommand::SendFragment {
            kind: *kind,
            final_fragment: *final_fragment,
            payload: keyed.payload.clone(),
            mask_key: keyed.mask_key,
        },
        Step::Ping(keyed) => LocalCommand::SendPing {
            payload: keyed.payload.clone(),
            mask_key: keyed.mask_key,
        },
        Step::Pong(keyed) => LocalCommand::SendPong {
            payload: keyed.payload.clone(),
            mask_key: keyed.mask_key,
        },
        Step::Close {
            mask_key,
            code,
            reason,
        } => LocalCommand::Close {
            code: *code,
            reason: reason.clone(),
            mask_key: *mask_key,
        },
        Step::Bytes(_) | Step::Eof => return Err(NeutralError),
    })
}

fn drive_command(
    session: &mut Session,
    command: LocalCommand,
    observations: &mut Vec<Observation>,
    bootstrap: bool,
) -> Result<Accounting, NeutralError> {
    session
        .handle
        .try_enqueue(command)
        .map_err(|_: EnqueueError| NeutralError)?;
    drive_input(
        session,
        NeutralDriverInput::Wake,
        observations,
        bootstrap,
        true,
    )
}

#[derive(Clone, Copy)]
enum NeutralDriverInput<'a> {
    Wake,
    Inbound(&'a [u8]),
    Eof,
    WriteProgress(usize),
}

fn drive_input(
    session: &mut Session,
    initial: NeutralDriverInput<'_>,
    observations: &mut Vec<Observation>,
    bootstrap: bool,
    require_command: bool,
) -> Result<Accounting, NeutralError> {
    let mut next = initial;
    let mut accepted = matches!(initial, NeutralDriverInput::Wake);
    let mut command_done = false;
    let mut primary_accounting = None;
    for _ in 0..MAX_TURNS {
        let submitting_initial = same_input(next, initial);
        let owned = poll_owned(&mut session.owner, next)?;
        let deferred = matches!(owned.input, InputDisposition::Deferred(_));
        if !deferred {
            accepted = true;
        }
        let core_accounting = capture_latest_core(session, observations)?;
        if primary_accounting.is_none()
            && ((require_command && owned.command.is_some())
                || (!require_command && submitting_initial && !deferred))
        {
            primary_accounting = core_accounting;
        }
        if let Some(command) = owned.command {
            match command {
                CommandDisposition::Applied(_) => command_done = true,
                CommandDisposition::Rejected { .. } => {
                    command_done = true;
                }
                CommandDisposition::TerminalRejected(_) | CommandDisposition::ProducersDropped => {
                    return Err(NeutralError);
                }
            }
        }
        next = match owned.output {
            OwnedOutput::Write(bytes) => {
                observations.push(Observation::Transport {
                    direction: 2,
                    bytes: bytes.clone().into_boxed_slice(),
                });
                NeutralDriverInput::WriteProgress(bytes.len())
            }
            OwnedOutput::Event(event) => {
                append_event_observations(event, observations)?;
                if deferred {
                    initial
                } else {
                    NeutralDriverInput::Wake
                }
            }
            OwnedOutput::StateChanged(state) => {
                let from = session.state;
                session.state = state;
                observations.push(Observation::Transition(from, state));
                if deferred {
                    initial
                } else {
                    NeutralDriverInput::Wake
                }
            }
            OwnedOutput::Failure(failure) => {
                observations.push(error_observation(&failure));
                NeutralDriverInput::Wake
            }
            OwnedOutput::Terminal => {
                session.state = ConnectionState::Closed;
                NeutralDriverInput::Wake
            }
            OwnedOutput::Idle if deferred => initial,
            OwnedOutput::Idle if accepted && (!require_command || command_done) => {
                return primary_accounting.ok_or(NeutralError);
            }
            OwnedOutput::Idle => initial,
        };
        if bootstrap
            && matches!(next, NeutralDriverInput::Wake)
            && session.owner.state() == ConnectionState::Closed
        {
            return primary_accounting.ok_or(NeutralError);
        }
    }
    Err(NeutralError)
}

fn same_input(left: NeutralDriverInput<'_>, right: NeutralDriverInput<'_>) -> bool {
    match (left, right) {
        (NeutralDriverInput::Wake, NeutralDriverInput::Wake)
        | (NeutralDriverInput::Eof, NeutralDriverInput::Eof) => true,
        (NeutralDriverInput::Inbound(left), NeutralDriverInput::Inbound(right)) => {
            core::ptr::eq(left.as_ptr(), right.as_ptr()) && left.len() == right.len()
        }
        _ => false,
    }
}

impl<'a> NeutralDriverInput<'a> {
    fn as_driver(self) -> DriverInput<'a> {
        match self {
            Self::Wake => DriverInput::Wake,
            Self::Inbound(bytes) => DriverInput::Inbound(TransportBytes::new(bytes)),
            Self::Eof => DriverInput::TransportEof,
            Self::WriteProgress(bytes) => DriverInput::WriteProgress { bytes },
        }
    }
}

#[derive(Debug)]
enum OwnedOutput {
    Idle,
    Write(Vec<u8>),
    Event(SemanticEvent),
    StateChanged(ConnectionState),
    Failure(TypedProtocolFailure),
    Terminal,
}

struct OwnedPoll {
    input: InputDisposition,
    command: Option<CommandDisposition>,
    output: OwnedOutput,
}

fn poll_owned(
    owner: &mut ConnectionOwner,
    input: NeutralDriverInput<'_>,
) -> Result<OwnedPoll, NeutralError> {
    let result = owner.poll(input.as_driver());
    let output = match result.output {
        DriverOutput::Idle => OwnedOutput::Idle,
        DriverOutput::Write(bytes) => OwnedOutput::Write(bytes.to_vec()),
        DriverOutput::Event(event) => OwnedOutput::Event(event),
        DriverOutput::StateChanged(state) => OwnedOutput::StateChanged(state),
        DriverOutput::Failure(failure) => OwnedOutput::Failure(failure),
        DriverOutput::Terminal(_) => OwnedOutput::Terminal,
    };
    Ok(OwnedPoll {
        input: result.input,
        command: result.command,
        output,
    })
}

fn capture_latest_core(
    session: &mut Session,
    observations: &mut Vec<Observation>,
) -> Result<Option<Accounting>, NeutralError> {
    let Some((sequence, core)) = session.owner.last_core_step() else {
        return Ok(None);
    };
    if sequence == session.core_sequence {
        return Ok(None);
    }
    session.core_sequence = sequence;
    for frame in core.frames() {
        observations.push(Observation::Frame {
            direction: match frame.direction() {
                FrameDirection::Inbound => 1,
                FrameDirection::Outbound => 2,
            },
            fin: frame.fin(),
            opcode: frame.opcode() as u8,
            masked: frame.masked(),
            payload: frame.payload().to_vec().into_boxed_slice(),
            wire_length: u64::try_from(frame.wire_length()).map_err(|_| NeutralError)?,
        });
    }
    let accounting = core.accounting();
    if accounting.pre_state != accounting.post_state
        && accounting.post_state == ConnectionState::Closed
    {
        observations.push(Observation::Transition(
            accounting.pre_state,
            accounting.post_state,
        ));
        session.state = accounting.post_state;
    }
    Ok(Some(Accounting {
        pre: accounting.pre_state,
        post: accounting.post_state,
        consumed: u64::try_from(accounting.bytes_consumed).map_err(|_| NeutralError)?,
        wire_buffered: u64::try_from(accounting.wire_buffered_bytes).map_err(|_| NeutralError)?,
        message_buffered: u64::try_from(accounting.message_buffered_bytes)
            .map_err(|_| NeutralError)?,
    }))
}

fn append_event_observations(
    event: SemanticEvent,
    observations: &mut Vec<Observation>,
) -> Result<(), NeutralError> {
    match event {
        SemanticEvent::ClientHandshakeOpened { .. } => {
            observations.push(Observation::Event(6, Vec::new()));
        }
        SemanticEvent::ServerHandshakeOpened { .. } => {
            observations.push(Observation::Event(7, Vec::new()));
        }
        SemanticEvent::FrameReceived { .. } => {}
        SemanticEvent::Text { message } => {
            observations.push(payload_event(1, message.as_str().as_bytes()));
        }
        SemanticEvent::Binary { message } => {
            observations.push(payload_event(2, message.as_slice()));
        }
        SemanticEvent::Ping { payload } => {
            observations.push(payload_event(3, payload.as_slice()));
        }
        SemanticEvent::Pong { payload } => {
            observations.push(payload_event(4, payload.as_slice()));
        }
        SemanticEvent::CloseReceived {
            close,
            initiator: _,
        } => {
            let record = CloseRecord {
                code: close.code(),
                reason: close.reason().to_owned(),
                clean: true,
                origin: 2,
            };
            append_close_observations(record, observations)?;
        }
        _ => {}
    }
    Ok(())
}

fn append_close_observations(
    close: CloseRecord,
    observations: &mut Vec<Observation>,
) -> Result<(), NeutralError> {
    let mut body = Vec::new();
    encode_close(&close, &mut body)?;
    observations.push(Observation::Event(5, body));
    observations.push(Observation::Close(close));
    Ok(())
}

fn payload_event(tag: u8, payload: &[u8]) -> Observation {
    let mut value = Vec::with_capacity(4 + payload.len());
    value.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    value.extend_from_slice(payload);
    Observation::Event(tag, value)
}

fn error_observation(failure: &TypedProtocolFailure) -> Observation {
    Observation::Error {
        terminal: failure.state_after == ConnectionState::Closed,
        class: failure_class(&failure.kind),
    }
}

fn failure_class(failure: &FailureKind) -> &'static str {
    match failure {
        FailureKind::ProtocolSliceUnavailable { .. } => "PROTOCOL_SLICE_UNAVAILABLE",
        FailureKind::Handshake(_) => "HANDSHAKE",
        FailureKind::Frame(failure) => match failure {
            FrameFailure::ReservedBits => "FRAME_RESERVED_BITS",
            FrameFailure::ReservedOpcode { .. } => "FRAME_RESERVED_OPCODE",
            FrameFailure::FragmentedControl { .. } => "FRAME_FRAGMENTED_CONTROL",
            FrameFailure::ControlPayloadTooLarge { .. } => "FRAME_CONTROL_PAYLOAD_TOO_LARGE",
            FrameFailure::NonCanonicalLength16 { .. } => "FRAME_NONCANONICAL_LENGTH16",
            FrameFailure::NonCanonicalLength64 { .. } => "FRAME_NONCANONICAL_LENGTH64",
            FrameFailure::PayloadLengthHighBitSet => "FRAME_LENGTH_HIGH_BIT",
            FrameFailure::IncorrectMasking { .. } => "FRAME_INCORRECT_MASKING",
            FrameFailure::LengthDoesNotFitPlatform { .. } => "FRAME_LENGTH_PLATFORM",
            FrameFailure::ArithmeticOverflow => "FRAME_ARITHMETIC_OVERFLOW",
            FrameFailure::AllocationFailed => "FRAME_ALLOCATION_FAILED",
            FrameFailure::UnexpectedEof => "FRAME_UNEXPECTED_EOF",
            FrameFailure::MissingMaskKey => "FRAME_MISSING_MASK_KEY",
            FrameFailure::UnexpectedMaskKey => "FRAME_UNEXPECTED_MASK_KEY",
            _ => "FRAME_UNKNOWN",
        },
        FailureKind::Utf8(failure) => utf8_class(failure),
        FailureKind::Fragment(failure) => match failure {
            FragmentFailure::ContinuationWithoutMessage => "FRAGMENT_CONTINUATION_WITHOUT_MESSAGE",
            FragmentFailure::DataFrameWhileFragmented { .. } => "FRAGMENT_DATA_WHILE_ACTIVE",
            FragmentFailure::UnexpectedEof { .. } => "FRAGMENT_UNEXPECTED_EOF",
            _ => "FRAGMENT_UNKNOWN",
        },
        FailureKind::Close(failure) => match failure {
            CloseFailure::PayloadLengthOne => "CLOSE_PAYLOAD_LENGTH_ONE",
            CloseFailure::ReasonWithoutCode => "CLOSE_REASON_WITHOUT_CODE",
            CloseFailure::InvalidCode { .. } => "CLOSE_INVALID_CODE",
            CloseFailure::InvalidReason(failure) => utf8_class(failure),
            CloseFailure::DuplicateLocalClose => "CLOSE_DUPLICATE_LOCAL",
            CloseFailure::DuplicatePeerClose => "CLOSE_DUPLICATE_PEER",
            CloseFailure::AcknowledgementMismatch => "CLOSE_ACK_MISMATCH",
            CloseFailure::DataAfterClose { .. } => "CLOSE_DATA_AFTER_CLOSE",
            CloseFailure::TrailingBytesAfterClose => "CLOSE_TRAILING_BYTES",
            CloseFailure::UnexpectedEofOpen => "CLOSE_UNEXPECTED_EOF_OPEN",
            CloseFailure::EofBeforePeerClose => "CLOSE_EOF_BEFORE_PEER",
            CloseFailure::EofBeforeAcknowledgement => "CLOSE_EOF_BEFORE_ACK",
            CloseFailure::EofBeforeCloseWriteFlushed => "CLOSE_EOF_BEFORE_FLUSH",
            _ => "CLOSE_UNKNOWN",
        },
        FailureKind::LimitExceeded { limit, .. } => match limit {
            LimitKind::HandshakeBytes => "LIMIT_HANDSHAKE_BYTES",
            LimitKind::HandshakeHeaderCount => "LIMIT_HANDSHAKE_HEADER_COUNT",
            LimitKind::HandshakeHeaderLineBytes => "LIMIT_HANDSHAKE_LINE_BYTES",
            LimitKind::FrameBytes => "LIMIT_FRAME_BYTES",
            LimitKind::MessageBytes => "LIMIT_MESSAGE_BYTES",
            LimitKind::TotalBufferedBytes => "LIMIT_TOTAL_BUFFERED_BYTES",
            LimitKind::EventQueueEntries => "LIMIT_EVENT_ENTRIES",
            LimitKind::CommandQueueEntries => "LIMIT_COMMAND_ENTRIES",
            LimitKind::WriteQueueEntries => "LIMIT_WRITE_ENTRIES",
        },
        FailureKind::Backpressure(queue) => match queue {
            QueueKind::Event => "BACKPRESSURE_EVENT",
            QueueKind::Write => "BACKPRESSURE_WRITE",
            _ => "BACKPRESSURE_COMMAND",
        },
        FailureKind::InvalidState { .. } => "INVALID_STATE",
    }
}

fn utf8_class(failure: &Utf8Failure) -> &'static str {
    match failure {
        Utf8Failure::UnexpectedContinuation { .. } => "UTF8_UNEXPECTED_CONTINUATION",
        Utf8Failure::InvalidLeadingByte { .. } => "UTF8_INVALID_LEADING_BYTE",
        Utf8Failure::InvalidContinuation { .. } => "UTF8_INVALID_CONTINUATION",
        Utf8Failure::OverlongEncoding { .. } => "UTF8_OVERLONG",
        Utf8Failure::SurrogateCodePoint { .. } => "UTF8_SURROGATE",
        Utf8Failure::CodePointOutOfRange { .. } => "UTF8_OUT_OF_RANGE",
        Utf8Failure::TruncatedSequence { .. } => "UTF8_TRUNCATED",
        _ => "UTF8_UNKNOWN",
    }
}

fn encode_response(
    request: &Request,
    bootstrap: &[Observation],
    steps: &[StepResponse],
    final_state: ConnectionState,
    terminal_close: Option<CloseRecord>,
) -> Result<Vec<u8>, NeutralError> {
    let mut body = b"NOBS1".to_vec();
    put_tlv(1, request.scenario_id.as_bytes(), &mut body)?;
    put_tlv(2, &[role_byte(request.role)], &mut body)?;
    put_tlv(3, &[initial_byte(request.initial_state)], &mut body)?;
    let mut bootstrap_value = vec![
        role_byte(request.role),
        0,
        state_byte(request.initial_state.into_state()),
    ];
    put_observation_list(bootstrap, &mut bootstrap_value)?;
    put_tlv(4, &bootstrap_value, &mut body)?;
    let mut step_value = Vec::new();
    step_value.extend_from_slice(
        &u16::try_from(steps.len())
            .map_err(|_| NeutralError)?
            .to_be_bytes(),
    );
    for step in steps {
        let record = encode_step_response(step)?;
        step_value.extend_from_slice(
            &u32::try_from(record.len())
                .map_err(|_| NeutralError)?
                .to_be_bytes(),
        );
        step_value.extend_from_slice(&record);
    }
    put_tlv(5, &step_value, &mut body)?;
    put_tlv(6, &[state_byte(final_state)], &mut body)?;
    let mut close_value = Vec::new();
    match terminal_close {
        None => close_value.push(0),
        Some(close) => {
            close_value.push(1);
            encode_close(&close, &mut close_value)?;
        }
    }
    put_tlv(7, &close_value, &mut body)?;
    if body.len() > MAX_RECORD_BYTES {
        return Err(NeutralError);
    }
    Ok(body)
}

impl InitialState {
    const fn into_state(self) -> ConnectionState {
        match self {
            Self::Open => ConnectionState::Open,
            Self::Closing => ConnectionState::Closing,
            Self::Closed => ConnectionState::Closed,
        }
    }
}

fn encode_step_response(step: &StepResponse) -> Result<Vec<u8>, NeutralError> {
    let mut value = Vec::new();
    value.extend_from_slice(&step.index.to_be_bytes());
    value.push(step.input_tag);
    value.push(state_byte(step.accounting.pre));
    value.push(state_byte(step.accounting.post));
    value.extend_from_slice(&step.accounting.consumed.to_be_bytes());
    value.extend_from_slice(&step.accounting.wire_buffered.to_be_bytes());
    value.extend_from_slice(&step.accounting.message_buffered.to_be_bytes());
    put_observation_list(&step.observations, &mut value)?;
    Ok(value)
}

fn put_observation_list(
    observations: &[Observation],
    output: &mut Vec<u8>,
) -> Result<(), NeutralError> {
    output.extend_from_slice(
        &u16::try_from(observations.len())
            .map_err(|_| NeutralError)?
            .to_be_bytes(),
    );
    for observation in observations {
        let record = encode_observation(observation)?;
        output.extend_from_slice(
            &u32::try_from(record.len())
                .map_err(|_| NeutralError)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&record);
    }
    Ok(())
}

fn encode_observation(observation: &Observation) -> Result<Vec<u8>, NeutralError> {
    let mut value = Vec::new();
    match observation {
        Observation::Event(kind, payload) => {
            value.extend_from_slice(&[1, *kind]);
            value.extend_from_slice(payload);
        }
        Observation::Frame {
            direction,
            fin,
            opcode,
            masked,
            payload,
            wire_length,
        } => {
            value.extend_from_slice(&[2, *direction, u8::from(*fin), *opcode, u8::from(*masked)]);
            value.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| NeutralError)?
                    .to_be_bytes(),
            );
            value.extend_from_slice(payload);
            value.extend_from_slice(&wire_length.to_be_bytes());
        }
        Observation::Transition(from, to) => {
            value.extend_from_slice(&[3, state_byte(*from), state_byte(*to)]);
        }
        Observation::Close(close) => {
            value.push(4);
            encode_close(close, &mut value)?;
        }
        Observation::Error { terminal, class } => {
            value.extend_from_slice(&[5, u8::from(*terminal)]);
            value.extend_from_slice(
                &u16::try_from(class.len())
                    .map_err(|_| NeutralError)?
                    .to_be_bytes(),
            );
            value.extend_from_slice(class.as_bytes());
        }
        Observation::Transport { direction, bytes } => {
            value.extend_from_slice(&[6, *direction]);
            value.extend_from_slice(
                &u32::try_from(bytes.len())
                    .map_err(|_| NeutralError)?
                    .to_be_bytes(),
            );
            value.extend_from_slice(bytes);
        }
    }
    Ok(value)
}

fn encode_close(close: &CloseRecord, output: &mut Vec<u8>) -> Result<(), NeutralError> {
    match close.code {
        None => output.push(0),
        Some(code) => {
            output.push(1);
            output.extend_from_slice(&code.to_be_bytes());
        }
    }
    output.extend_from_slice(
        &u32::try_from(close.reason.len())
            .map_err(|_| NeutralError)?
            .to_be_bytes(),
    );
    output.extend_from_slice(close.reason.as_bytes());
    output.push(u8::from(close.clean));
    output.push(close.origin);
    Ok(())
}

fn put_tlv(tag: u8, value: &[u8], output: &mut Vec<u8>) -> Result<(), NeutralError> {
    output.push(tag);
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| NeutralError)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

const fn role_byte(role: Role) -> u8 {
    match role {
        Role::Client => 1,
        Role::Server => 2,
    }
}

const fn initial_byte(state: InitialState) -> u8 {
    match state {
        InitialState::Open => 1,
        InitialState::Closing => 2,
        InitialState::Closed => 3,
    }
}

const fn state_byte(state: ConnectionState) -> u8 {
    match state {
        ConnectionState::Connecting => 0,
        ConnectionState::Open => 1,
        ConnectionState::Closing => 2,
        ConnectionState::Closed => 3,
    }
}

fn decode_bool(value: u8) -> Result<bool, NeutralError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(NeutralError),
    }
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], NeutralError> {
        if length > self.remaining.len() {
            return Err(NeutralError);
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }

    fn take_rest(&mut self) -> &'a [u8] {
        let value = self.remaining;
        self.remaining = &[];
        value
    }

    fn u8(&mut self) -> Result<u8, NeutralError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, NeutralError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| NeutralError)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, NeutralError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| NeutralError)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, NeutralError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| NeutralError)?,
        ))
    }
}
