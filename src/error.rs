
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    GenericStringError(String),

    #[error("{0:?}")]
    StdIoError(#[from] std::io::Error),

    #[error("{0:?}")]
    CsvError(#[from] csv::Error),

    #[error("{0:?}")]
    RtnetlinkError(#[from] rtnetlink::Error),

    #[error("{0:?}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("failed to send output on output handler channel")]
    OutputHandlerChannelClosed,
}
