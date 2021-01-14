use crate::{TxListStage, TxStage};

pub const DEFAULT_TX_STAGES_NONE: &[TxStage] = &[];
pub const DEFAULT_TX_STAGES_DET: &[TxStage] = &[
    TxStage::FlipReenter,
    TxStage::MutateCaller,
    TxStage::MutateBlockAdvance,
    TxStage::MutateTransactionReturns,
    TxStage::MutateTransactionReturns,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    TxStage::MutateTransactionInput,
    // it is important that the last value in this array occurs only once, since we use this as a
    // marker on when to move on to the next transaction index.
    TxStage::FlipCallValue,
];

use TxListStage::*;
pub const DEFAULT_STAGES_NONE: &[TxListStage] = &[];
pub const DEFAULT_STAGES_EMPTY: &[TxListStage] = &[TxListStage::AddTransaction];
pub const DEFAULT_STAGES_VERY_SMALL: &[TxListStage] = &[
    ObtainCmpTrace,
    GiveSomeInitialEther,
    MutateBlockHeader,
    MutateBlockHeader,
    MutateBlockHeader,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    MutateAllTx,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueueMulti,
    SpliceTxFromQueueMulti,
    SpliceTxFromQueueMulti,
    SpliceTxFromQueueMulti,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    ShuffleTransactions,
    ShuffleTransactions,
    ShuffleTransactions,
    AddReturnMocks,
    AddReturnMocks,
    AddReturnMocks,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
];
pub const DEFAULT_STAGES_SMALL: &[TxListStage] = &[
    ObtainCmpTrace,
    GiveSomeInitialEther,
    MutateBlockHeader,
    MutateBlockHeader,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    ShuffleTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    DeduplicateByFunctionSig,
    DropOneFunction,
    DropOneFunction,
    DropOneFunction,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateAllTx,
    MutateAllTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    AddReturnMocks,
    AddReturnMocks,
    AddReturnMocks,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
];
pub const DEFAULT_STAGES_LARGE: &[TxListStage] = &[
    ObtainCmpTrace,
    GiveSomeInitialEther,
    MutateBlockHeader,
    MutateBlockHeader,
    MutateBlockHeader,
    MutateBlockHeader,
    MutateBlockHeader,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    OnlyMutateManyTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateSingleTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    MutateLastTx,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueue,
    SpliceTxFromQueueMulti,
    SpliceTxFromQueueMulti,
    SpliceTxFromQueueMulti,
    SpliceTxFromQueueMulti,
    SpliceTxFromQueueMulti,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    SpliceTxListFromQueue,
    ShuffleTransactions,
    ShuffleTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    SwapTransactions,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    AddTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    InsertTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceLastTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    ReplaceRandomTransaction,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DuplicateWithReentrancy,
    DeduplicateByFunctionSig,
    DropOneFunction,
    DropOneFunction,
    DropOneFunction,
    DropOneFunction,
    DropOneFunction,
    AddReturnMocks,
    DropRandomTransaction,
    DropRandomTransaction,
    DropRandomTransaction,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateValuesInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    PropagateSenderInTransactions,
    StackedHavocMany,
    StackedHavocMany,
    StackedHavocMany,
    StackedHavocMany,
    StackedHavocMany,
    StackedHavocMany,
    StackedHavocMany,
];
