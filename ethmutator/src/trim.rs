// Copyright 2021 Michael Rodler
// This file is part of ethmutator.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::types::*;
use std::rc::Rc;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum BlockHeaderStage {
    Number(u64),
    Difficulty(u64),
    GasLimit(u64),
    TimeStamp(u64),
    InitialEther(u64),
}

impl BlockHeaderStage {
    fn n_reduce(n: u64) -> u64 {
        if n > 100_000 {
            100_000
        } else if n > 10_000 {
            10_000
        } else if n > 10 {
            10
        } else if n > 5 {
            5
        } else if n > 2 {
            2
        } else if n > 1 {
            1
        } else {
            0
        }
    }

    pub fn reduce(&self) -> Self {
        use BlockHeaderStage::*;
        match *self {
            Number(n) => Number(Self::n_reduce(n)),
            Difficulty(n) => Difficulty(Self::n_reduce(n)),
            GasLimit(n) => GasLimit(Self::n_reduce(n)),
            TimeStamp(n) => TimeStamp(Self::n_reduce(n)),
            InitialEther(n) => InitialEther(if n > crate::ONE_ETHER_SHIFT {
                crate::ONE_ETHER_SHIFT
            } else {
                Self::n_reduce(n)
            }),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum TransactionHeaderStage {
    CallValue(u64),
    BlockAdvance(u8),
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum FuzzcaseTrimmerStage {
    Start,
    /// Delete the Transaction at the given index
    Transactions(usize),
    /// Delete the Transaction but add call value to the global initial ether
    TransactionWithValue(usize),
    TransactionHeader(usize, TransactionHeaderStage),
    /// delete the whole
    Returns(usize, usize),
    ReturnData(usize, usize, usize),
    Reenter(usize, usize, usize),
    Inputs(usize, usize),
    // TODO: minimize also the transaction call value field
    //TransactionValue(usize),
    Sender(usize, u8),
    Receiver(usize, u8),
    BlockHeader(BlockHeaderStage),
    Done,
}

#[derive(Clone, Debug)]
pub struct FuzzcaseTrimmer {
    previous: FuzzCase,
    current: FuzzCase,
    previous_stage: FuzzcaseTrimmerStage,
    stage: FuzzcaseTrimmerStage,
    expected_steps: usize,
    performed_steps: usize,
}

impl FuzzcaseTrimmer {
    pub fn from(fc: FuzzCase) -> FuzzcaseTrimmer {
        let mut steps: usize = 5; // for all the block headers

        for tx in fc.txs.iter() {
            steps += 1; // for trying to remove the TX

            if tx.input.len() > 36 {
                steps += 2;
            } else if tx.input.len() > 4 {
                steps += 1;
            }

            if tx.header.call_value > 0 {
                steps += 1;
            }

            for retdef in tx.returns.iter() {
                steps += 1; // for trying to remove the return mock

                if retdef.header.reenter != 0 {
                    steps += 1; // for trying to remove the reentrancy
                }
            }
        }

        if fc.txs.len() > 0 {
            FuzzcaseTrimmer {
                previous: fc.clone(),
                current: fc,
                stage: FuzzcaseTrimmerStage::Start,
                previous_stage: FuzzcaseTrimmerStage::Start,
                expected_steps: steps,
                performed_steps: 0,
            }
        } else {
            FuzzcaseTrimmer {
                previous: fc.clone(),
                current: fc,
                stage: FuzzcaseTrimmerStage::Done,
                previous_stage: FuzzcaseTrimmerStage::Done,
                expected_steps: 0,
                performed_steps: 0,
            }
        }
    }

    pub fn steps_bound(&self) -> usize {
        self.expected_steps
    }

    /// Implementation of the trimming state machine. We always start back to front, higher to lower
    /// values, larger effects to smaller effects, i.e., we first try to remove the last transaction
    /// before attempting to minimize the call values. If we can remove a transaction as a whole we
    /// don't need to minimize its call value -> less executions needed.
    fn get_next_stage(&self, stage: FuzzcaseTrimmerStage) -> FuzzcaseTrimmerStage {
        use FuzzcaseTrimmerStage::*;
        if self.current.txs.is_empty() {
            return Done;
        }
        let mut stage = stage;
        // 'main:
        loop {
            let txs_len = self.current.txs.len();
            stage = match stage {
                Start => return Transactions(txs_len - 1),
                Transactions(0) => TransactionWithValue(txs_len),
                Transactions(i) if i > txs_len => {
                    return Transactions(txs_len - 1);
                }
                Transactions(i) => {
                    return Transactions(i - 1);
                }
                TransactionWithValue(0) => {
                    TransactionHeader(txs_len, TransactionHeaderStage::BlockAdvance(0))
                }
                TransactionWithValue(i) if i > txs_len => TransactionWithValue(txs_len),
                TransactionWithValue(i) => {
                    debug_assert_ne!(txs_len, 0);
                    let idx = i - 1;
                    let cv = self.current.txs[idx].header.call_value;
                    let nstage = TransactionWithValue(idx);
                    if cv > 0 {
                        // we have some call_value, so we execute the trim stage
                        return nstage;
                    } else {
                        // otherwise loop around 'main and go to the next stage
                        nstage
                    }
                }
                TransactionHeader(i, stage) => match stage {
                    TransactionHeaderStage::CallValue(0) => {
                        // handle block_advance for the same tx index `i`
                        let ba = self.current.txs[i].header.block_advance;
                        TransactionHeader(i, TransactionHeaderStage::BlockAdvance(ba))
                    }
                    TransactionHeaderStage::CallValue(cv) => {
                        let new_cv = if cv > crate::ONE_ETHER_WEI {
                            crate::ONE_ETHER_WEI
                        } else if cv > 100_000 {
                            100_000
                        } else if cv > 100 {
                            100
                        } else if cv > 1 {
                            1
                        } else {
                            0
                        };
                        let stage = TransactionHeader(i, TransactionHeaderStage::CallValue(new_cv));
                        // execute the stage if it changes something; otherwise loop around and
                        // go to the next stage.
                        if self.current.txs[i].header.call_value != new_cv {
                            return stage;
                        } else {
                            stage
                        }
                    }
                    TransactionHeaderStage::BlockAdvance(0) => {
                        if i > 0 {
                            // move on to next TX
                            let cv = self.current.txs[i - 1].header.call_value;
                            TransactionHeader(i - 1, TransactionHeaderStage::CallValue(cv))
                        } else {
                            // i == 0
                            // arrived at the first TX index and a block_advance of 0 -> move on to returns
                            debug_assert!(txs_len > 0);
                            Returns(txs_len, 0)
                        }
                    }
                    TransactionHeaderStage::BlockAdvance(ba) => {
                        let ba: u8 = if ba > 128 {
                            128
                        } else if ba > 10 {
                            10
                        } else if ba > 5 {
                            5
                        } else if ba > 2 {
                            2
                        } else if ba > 1 {
                            1
                        } else {
                            0
                        };
                        let stage = TransactionHeader(i, TransactionHeaderStage::BlockAdvance(ba));
                        if self.current.txs[i].header.block_advance != ba {
                            return stage;
                        } else {
                            stage
                        }
                    }
                },
                Returns(0, 0) => {
                    // go to next type of stage
                    ReturnData(self.current.txs.len(), 0, 0)
                }
                Returns(i, 0) => {
                    // j == 0; i > 0
                    let mut i = i;
                    while i > 0 {
                        i -= 1;
                        let retlen = self.current.txs[i].returns.len();
                        if retlen > 0 {
                            // found a transaction with returns -> execute trim
                            return Returns(i, retlen - 1);
                        }
                    }
                    Returns(0, 0)
                }
                Returns(i, j) => {
                    debug_assert_ne!(j, 0);
                    // execute trim for next return
                    return Returns(i, j - 1);
                }
                ReturnData(0, 0, 0) => {
                    // ReturnData(0,0,0) => Reenter Stage
                    debug_assert!(txs_len > 0);
                    // we pass tx_len here, intentionally not a valid tx index, s.t., the
                    // Reenter search begins with the last transaction.
                    Reenter(txs_len, 0, 0)
                }
                ReturnData(i, 0, 0) => {
                    // i > 0; j == 0; l == 0
                    // find the next valid returndata stage; i.e., a transaction with
                    // some returns that have returndata
                    let tx_idx = i - 1;
                    let retlen = self.current.txs[tx_idx].returns.len();
                    if retlen > 0 {
                        let ret_idx = retlen - 1;
                        let retdatalen = self.current.txs[tx_idx].returns[ret_idx].data.len();
                        ReturnData(tx_idx, ret_idx, retdatalen)
                    } else {
                        ReturnData(tx_idx, 0, 0)
                    }
                }
                ReturnData(i, j, 0) => {
                    // l == 0; j > 0;
                    let l = self.current.txs[i].returns[j - 1].data.len();
                    ReturnData(i, j - 1, l)
                }
                ReturnData(i, j, l) => {
                    // l > 0
                    let new_l = if l > (u16::MAX as usize) {
                        (u16::MAX as usize) / 2
                    } else if l > 256 {
                        l / 2
                    } else if l > 32 {
                        if (l % 32) != 0 {
                            // get the next multiple of 32 (div rounds down)
                            32 * (l / 32)
                        } else {
                            l - 32
                        }
                    } else {
                        0
                    };
                    debug_assert!(new_l < l);
                    return ReturnData(i, j, new_l);
                }
                Reenter(0, 0, 0) => Inputs(txs_len, 0),
                Reenter(i, 0, 0) => {
                    // i > 0; j == 0; r == 0
                    let tx_idx = i - 1;
                    let retlen = self.current.txs[tx_idx].returns.len();
                    if retlen > 0 {
                        let r =
                            self.current.txs[tx_idx].returns[retlen - 1].header.reenter as usize;
                        let max_reenter = txs_len - tx_idx - 1;
                        if r > max_reenter {
                            return Reenter(tx_idx, retlen - 1, max_reenter);
                        } else {
                            Reenter(tx_idx, retlen - 1, r)
                        }
                    } else {
                        Reenter(tx_idx, 0, 0)
                    }
                }
                Reenter(i, j, 0) => {
                    // i > 0; j > 0; r == 0
                    // take the current reenter value
                    let r = self.current.txs[i].returns[j - 1].header.reenter as usize;
                    Reenter(i, j - 1, r)
                }
                Reenter(i, j, r) => {
                    // we try to reduce the number of reentrant transactions, but we bound the
                    // number of reentrant transactions by the number of actually available
                    // transactions.
                    let new_r = std::cmp::min(
                        if r > 10 {
                            10
                        } else if r > 5 {
                            5
                        } else if r > 2 {
                            2
                        } else if r > 1 {
                            1
                        } else {
                            0
                        },
                        self.current.txs.len() - i - 1,
                    );
                    debug_assert!(new_r < r);
                    return Reenter(i, j, new_r);
                }
                Inputs(0, 0) => Sender(txs_len, 0),
                Inputs(i, 0) => {
                    let l = self.current.txs[i - 1].input.len();
                    Inputs(i - 1, l)
                }
                Inputs(i, l) => {
                    let new_l = if l > (u16::MAX as usize) {
                        (u16::MAX as usize) / 2
                    } else if l > 256 {
                        l / 2
                    } else if l > 32 {
                        let p_l = l - 4;
                        if (p_l % 32) != 0 {
                            // get the next multiple of 32 (div rounds down); + 4 bytes signature
                            (32 * (p_l / 32)) + 4
                        } else {
                            l - 32
                        }
                    } else if l > 4 {
                        4
                    } else {
                        0
                    };
                    return Inputs(i, new_l);
                }
                Sender(0, 0) => Receiver(txs_len, 0),
                Sender(tx_idx, 0) => {
                    let next_tx = tx_idx - 1;
                    let next_sender = std::cmp::min(
                        self.current.txs[next_tx].header.get_sender_select(),
                        crate::HARNESS_MAX_SENDER,
                    );
                    return Sender(next_tx, next_sender);
                }
                Sender(tx_idx, sender_select) => {
                    return Sender(tx_idx, sender_select - 1);
                }
                Receiver(0, 0) => {
                    let bnum = self.current.header.number;
                    return BlockHeader(BlockHeaderStage::Number(bnum));
                }
                Receiver(tx_idx, 0) => {
                    let next_tx = tx_idx - 1;
                    let next_receiver = std::cmp::min(
                        self.current.txs[next_tx].header.get_receiver_select(),
                        crate::HARNESS_MAX_RECEIVER,
                    );
                    return Receiver(next_tx, next_receiver);
                }
                Receiver(tx_idx, recv_select) => {
                    return Receiver(tx_idx, recv_select - 1);
                }
                BlockHeader(stage) => {
                    let reduced_stage = stage.reduce();
                    // check if value is already reduced to the min
                    if reduced_stage == stage {
                        use BlockHeaderStage::*;
                        match reduced_stage {
                            Number(_) => BlockHeader(Difficulty(self.current.header.difficulty)),
                            Difficulty(_) => BlockHeader(GasLimit(self.current.header.gas_limit)),
                            GasLimit(_) => BlockHeader(TimeStamp(self.current.header.timestamp)),
                            TimeStamp(_) => {
                                BlockHeader(InitialEther(self.current.header.initial_ether))
                            }
                            InitialEther(_) => Done,
                        }
                    } else {
                        return BlockHeader(reduced_stage);
                    }
                }
                Done => return Done,
            }
        }
    }

    pub fn next_stage(&mut self) {
        let s = self.stage;
        self.stage = self.get_next_stage(s);
    }

    pub fn next(&mut self) -> Option<FuzzCase> {
        self.previous = self.current.clone();
        self.previous_stage = self.stage;
        self.next_stage();
        match self.stage {
            FuzzcaseTrimmerStage::Transactions(i) => {
                debug_assert!(i < self.current.txs.len());
                self.current.txs.remove(i);
            }
            FuzzcaseTrimmerStage::TransactionWithValue(i) => {
                debug_assert!(
                    self.current.txs.len() > i && self.current.txs[i].header.call_value > 0
                );
                let init_ether = self.current.header.initial_ether;
                let tx_ether = self.current.txs[i].header.call_value;
                self.current.header.initial_ether = crate::call_value_add(init_ether, tx_ether);
            }
            FuzzcaseTrimmerStage::TransactionHeader(i, stage) => {
                debug_assert!(self.current.txs.len() > i);
                match stage {
                    TransactionHeaderStage::CallValue(cv) => {
                        self.current.txs[i].header.call_value = cv;
                    }
                    TransactionHeaderStage::BlockAdvance(ba) => {
                        self.current.txs[i].header.block_advance = ba;
                    }
                }
            }
            FuzzcaseTrimmerStage::Returns(i, j) => {
                debug_assert!(self.current.txs[i].returns.len() > j);
                self.current.txs[i].returns.remove(j);
                self.current.txs[i].header.return_count -= 1;
            }
            FuzzcaseTrimmerStage::ReturnData(i, j, l) => {
                debug_assert!(self.current.txs[i].returns[j].data.len() > l);
                Rc::make_mut(&mut self.current.txs[i].returns[j].data).truncate(l);
                self.current.txs[i].returns[j].header.data_length =
                    self.current.txs[i].returns[j].data.len() as u16;
            }
            FuzzcaseTrimmerStage::Reenter(i, j, r) => {
                self.current.txs[i].returns[j].header.reenter = r as u8;
            }
            FuzzcaseTrimmerStage::Inputs(i, l) => {
                debug_assert!(self.current.txs[i].input.len() > l);
                Rc::make_mut(&mut self.current.txs[i].input).truncate(l);
                self.current.txs[i].header.length = self.current.txs[i].input.len() as u16;
            }
            FuzzcaseTrimmerStage::Sender(i, s) => {
                self.current.txs[i].header.sender_select = s;
            }
            FuzzcaseTrimmerStage::Receiver(i, s) => {
                self.current.txs[i].header.receiver_select = s;
            }
            FuzzcaseTrimmerStage::BlockHeader(stage) => match stage {
                BlockHeaderStage::Difficulty(n) => self.current.header.difficulty = n,
                BlockHeaderStage::GasLimit(n) => self.current.header.gas_limit = n,
                BlockHeaderStage::InitialEther(n) => self.current.header.initial_ether = n,
                BlockHeaderStage::TimeStamp(n) => self.current.header.timestamp = n,
                BlockHeaderStage::Number(n) => self.current.header.number = n,
            },
            FuzzcaseTrimmerStage::Done => return None,
            FuzzcaseTrimmerStage::Start => {
                unreachable!();
            }
        };
        self.performed_steps += 1;
        Some(self.current.clone())
    }

    pub fn rollback(&mut self) {
        self.current = self.previous.clone();
        self.stage = self.get_next_stage(self.previous_stage);
    }

    pub fn steps(&self) -> (usize, usize) {
        (self.expected_steps, self.performed_steps)
    }

    pub fn is_done(&self) -> bool {
        self.stage == FuzzcaseTrimmerStage::Done
    }

    pub fn get_current(&self) -> FuzzCase {
        self.current.clone()
    }

    pub fn current_stage(&self) -> FuzzcaseTrimmerStage {
        self.stage
    }
}
