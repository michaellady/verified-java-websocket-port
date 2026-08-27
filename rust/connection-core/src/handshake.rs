//! Private opening-handshake implementation.

mod client;
mod crypto;
mod http;

pub(crate) use client::ClientHandshake;
pub use client::{ClientRequestDescriptor, ClientRequestDescriptorError};
