use std::mem::MaybeUninit;
use std::sync::Arc;

use socket2::Socket;
use tokio::io::unix::AsyncFd;

use crate::error::Result;

/// Clonable async socket wrapper with convenience methods for performing async send/recv
/// operations.
#[derive(Clone, Debug)]
pub struct AsyncSocket {
    inner: Arc<AsyncFd<Socket>>,
}

impl AsyncSocket {
    pub fn new(s: Socket) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(AsyncFd::new(s)?),
        })
    }

    /// Populate given MaybeUninit buffer asynchronously.
    pub async fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
        loop {
            log::trace!("waiting for receiver to be readable");
            let mut guard = self.inner.readable().await?;
            log::trace!("receiver is readable");

            match guard.try_io(|receiver| receiver.get_ref().recv(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Send referenced buffer asynchronously.
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;

            match guard.try_io(|sender| sender.get_ref().send(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}
