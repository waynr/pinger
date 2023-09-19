
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
    AsyncChannelRecvError(#[from] async_channel::RecvError),

    #[error("{0:?}")]
    AsyncChannelTryRecvError(#[from] async_channel::TryRecvError),

    #[error("{0:?}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("{0:?}")]
    AsyncChannelTargetParamsSendError(#[from] async_channel::SendError<super::prober::TargetParams>),

    #[error("{0:?}")]
    StdMpscTryRecvError(#[from] std::sync::mpsc::TryRecvError),

    #[error("failed to send output on output handler channel")]
    OutputHandlerChannelClosed,
}
