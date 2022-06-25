import { constants, ethers } from 'ethers'
import { serialize, Transaction } from '@ethersproject/transactions'
import { Provider } from '@ethersproject/abstract-provider'
import { getContractInterface } from '@eth-optimism/contracts'
import {
  SequencerBatch,
  toRpcHexString,
  toHexString,
} from '@eth-optimism/core-utils'

import {
  Keys,
  IndexedEntry,
  BatchTransactionEntry,
  DecodedBatchTransaction,
  BatchEntry,
  EnqueueLinkEntry,
} from './db'

export type EventParsingFunction = (
  event: ethers.Event,
  provider: Provider,
  l2ChainId: number
) => Promise<IndexedEntry[]>

export const parseTransactionEnqueued: EventParsingFunction = async (event) => {
  return [
    {
      key: Keys.ENQUEUE_TRANSACTION,
      index: event.args._queueIndex.toNumber(),
      target: event.args._target,
      data: event.args._data,
      gasLimit: event.args._gasLimit.toString(),
      origin: event.args._l1TxOrigin,
      blockNumber: ethers.BigNumber.from(event.blockNumber).toNumber(),
      timestamp: event.args._timestamp.toNumber(),
      ctcIndex: null,
    },
  ]
}

export const parseTransactionBatchAppended: EventParsingFunction = async (
  event,
  provider,
  l2ChainId
) => {
  const transaction = await provider.getTransaction(event.transactionHash)
  const decoded: SequencerBatch = (SequencerBatch as any).fromHex(
    transaction.data
  )

  // TransactionBatchAppended should be followed by SequencerBatchAppended, which we need so
  // we can access the starting queue index field. There are stateful ways to remove this
  // event query by looking things up in the database, but that introduces even more
  // dependencies and means events can't easily be processed in parallel.
  const receipt = await provider.getTransactionReceipt(event.transactionHash)
  const event2 = getContractInterface('CanonicalTransactionChain').parseLog(
    receipt.logs.find((log) => {
      return log.logIndex === event.logIndex + 1
    })
  )

  // Decode batch into entries.
  let enqCount = 0
  let txnCount = 0
  const txnEntries: BatchTransactionEntry[] = []
  const enqEntries: EnqueueLinkEntry[] = []
  for (const context of decoded.contexts) {
    for (let i = 0; i < context.numSequencedTransactions; i++) {
      const tx = decoded.transactions[txnCount].toTransaction()

      txnEntries.push({
        key: Keys.BATCHED_TRANSACTION,
        index: event.args._prevTotalElements.add(txnEntries.length).toNumber(),
        batchIndex: event.args._batchIndex.toNumber(),
        blockNumber: context.blockNumber,
        timestamp: context.timestamp,
        gasLimit: '0',
        target: constants.AddressZero,
        origin: null,
        value: toRpcHexString(tx.value),
        data: serialize(
          {
            nonce: tx.nonce,
            gasPrice: tx.gasPrice,
            gasLimit: tx.gasLimit,
            to: tx.to,
            value: tx.value,
            data: tx.data,
          },
          {
            v: tx.v,
            r: tx.r,
            s: tx.s,
          }
        ),
        queueOrigin: 'sequencer',
        queueIndex: null,
        decoded: decodeBatchTransaction(tx, l2ChainId),
      })

      txnCount++
    }

    for (let i = 0; i < context.numSubsequentQueueTransactions; i++) {
      const chainIndex = event.args._prevTotalElements
        .add(txnEntries.length)
        .toNumber()
      const queueIndex = event2.args._startingQueueIndex
        .add(enqCount)
        .toNumber()

      txnEntries.push({
        key: Keys.BATCHED_TRANSACTION,
        index: chainIndex,
        batchIndex: event.args._batchIndex.toNumber(),
        blockNumber: 0,
        timestamp: context.timestamp,
        gasLimit: '0',
        target: constants.AddressZero,
        origin: constants.AddressZero,
        value: '0x0',
        data: '0x',
        queueOrigin: 'l1',
        queueIndex,
        decoded: null,
      })

      enqEntries.push({
        key: Keys.ENQUEUE_LINK,
        index: queueIndex,
        chainIndex,
      })

      enqCount++
    }
  }

  const batchEntry: BatchEntry = {
    key: Keys.BATCH,
    index: event.args._batchIndex.toNumber(),
    prevTotalElements: event.args._prevTotalElements.toNumber(),
    size: event.args._batchSize.toNumber(),
  }

  return [...txnEntries, ...enqEntries, batchEntry]
}

export const decodeBatchTransaction = (
  tx: Transaction,
  l2ChainId: number
): DecodedBatchTransaction => {
  return {
    nonce: ethers.BigNumber.from(tx.nonce).toString(),
    gasPrice: ethers.BigNumber.from(tx.gasPrice).toString(),
    gasLimit: ethers.BigNumber.from(tx.gasLimit).toString(),
    value: toRpcHexString(tx.value),
    target: tx.to ? toHexString(tx.to) : null,
    data: toHexString(tx.data),
    sig: {
      v: parseSignatureVParam(tx.v, l2ChainId),
      r: toHexString(tx.r),
      s: toHexString(tx.s),
    },
  }
}

export const parseSignatureVParam = (
  v: number | ethers.BigNumber | string,
  chainId: number
): number => {
  v = ethers.BigNumber.from(v).toNumber()

  // Handle unprotected transactions
  if (v === 27 || v === 28) {
    return v
  }

  // Handle EIP155 transactions
  return v - 2 * chainId - 35
}
