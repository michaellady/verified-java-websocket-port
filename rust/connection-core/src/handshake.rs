//! Private opening-handshake implementation.

mod client;
mod crypto;
mod http;

pub(crate) use client::{ClientHandshake, ClientLimitExceeded, ClientResponse};
pub use client::{ClientRequestDescriptor, ClientRequestDescriptorError};
