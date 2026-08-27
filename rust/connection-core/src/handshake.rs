//! Private opening-handshake implementation.

mod client;
mod crypto;
mod http;
mod server;

pub(crate) use client::{ClientHandshake, ClientLimitExceeded, ClientResponse};
pub use client::{ClientRequestDescriptor, ClientRequestDescriptorError};
pub use server::ServerRequestDescriptor;
pub(crate) use server::{ServerHandshake, ServerRequest};
