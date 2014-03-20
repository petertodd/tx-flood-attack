#!/usr/bin/python3

# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import logging
import pickle
import struct
import sys
import os
import time

import bitcoin
import bitcoin.rpc
from bitcoin.core import (x, lx, b2x, b2lx, str_money_value,
                          COutPoint, CTxIn, CTxOut, CTransaction,
                          Hash, Hash160)
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_CHECKMULTISIG
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

bitcoin.SelectParams('testnet')

class Wallet:
    """Simple little deterministic wallet

    Here because python-bitcoinlib doesn't have one yet.

    WARNING: this code sucks

    keypairs           - dict of scriptPubKey:CBitcoinSecret
    txouts_by_block    - dict of block_hash:set of (COutPoint, CTxOut)
    seed_birthday      - unix time of when the seed was created
    known_block_hashes - list of known block hashes to detect reorgs
    """

    def __init__(self, hex_seed, filename, seed_birthday=None):
        self.filename = filename
        self.seed = x(hex_seed)
        if len(self.seed) != 32:
            raise ValueError('seed not 32 bytes')

        self.keypairs = {}
        self.txouts_by_block = {}
        if seed_birthday is None:
            seed_birthday = time.time() - 24*60*60 # one day
        self.seed_birthday = seed_birthday

        self.known_blocks = []

    def __getstate__(self):
        state = self.__dict__.copy()

        # convert secret keys to bytes - they can't be pickled directly
        for pubkey, seckey in self.keypairs.items():
            self.keypairs[pubkey] = seckey.to_secret_bytes()

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
            n = len(self.keypairs)

        secret_bytes = Hash(self.seed + struct.pack('>L', n))
        secret_key = CBitcoinSecret.from_secret_bytes(secret_bytes)

        # 1-of-1 CHECKMULTISIG scriptPubKey's
        scriptPubKey = CScript([1, secret_key.pub, 1, OP_CHECKMULTISIG])

        self.keypairs[scriptPubKey] = secret_key

        return scriptPubKey

    def make_paytopubkeyhash(self, n = None):
        if n is None:
            n = len(self.keypairs)

        secret_bytes = Hash(self.seed + struct.pack('>L', n))
        secret_key = CBitcoinSecret.from_secret_bytes(secret_bytes)

        # pay-to-pubkeyhash
        scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(secret_key.pub), OP_EQUALVERIFY, OP_CHECKSIG])

        self.keypairs[scriptPubKey] = secret_key

        return scriptPubKey

    def scan_block(self, block):
        """Scan a new block for txouts to us"""
        block_hash = block.get_hash()
        num_found = 0
        for tx in block.vtx:
            for (i, txout) in enumerate(tx.vout):
                if txout.scriptPubKey in self.keypairs:
                    outpoint = COutPoint(tx.get_hash(), i)
                    block_txout_set = self.txouts_by_block.setdefault(block_hash, set())
                    block_txout_set.add((outpoint, txout))

                    logging.debug('Found txout: %r -> %r' % (outpoint, txout))
                    num_found += 1
        return num_found

    def find_confirmed_txouts(self, rpc, starting_height=2**32):
        """Find new confirmed transaction outputs"""

        # Detect reorgs first
        if self.known_blocks:
            while len(self.known_blocks) > starting_height \
                  or self.known_blocks[-1] != rpc.getblockhash(len(self.known_blocks)-1):

                reorged_block_hash = self.known_blocks.pop()

                # Top block hash not longer valid, remove it and all related txouts
                if reorged_block_hash in self.txouts_by_block:
                    logging.info('Block %s no longer exists, removing %d transactions' %
                            (b2lx(reorged_block_hash), len(txouts_by_block[reorged_block_hash])))
                    del txouts_by_block[reorged_block_hash]

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
        while len(self.known_blocks) < rpc.getblockcount():
            new_block_hash = rpc.getblockhash(len(self.known_blocks))
            new_block = rpc.getblock(new_block_hash)

            num_found = self.scan_block(new_block)
            logging.info('New block %s at height %d; found %d txouts' %
                         (b2lx(new_block_hash), len(self.known_blocks)-1, num_found))

            self.known_blocks.append(new_block_hash)


    def sign_txout(self, tx, n):
        pass


def init_command(args):
    wallet = Wallet(args.seed, args.wallet)
    wallet.save()


def scan_command(args):
    args.wallet.find_confirmed_txouts(args.rpc, args.starting_height)
    args.wallet.save()
    logging.info('Done: have %d total txouts' % len(args.wallet.txouts_by_block))

def getnewaddress_command(args):
    fund_addr = CBitcoinAddress.from_scriptPubKey(args.wallet.make_paytopubkeyhash())
    args.wallet.save()
    print('Pay to %s to fund your wallet' % fund_addr)

def attack_command(args):
    print(args)

parser = argparse.ArgumentParser()
parser.add_argument('--wallet', action='store',
    default='wallet.dat',
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
parser_attack.set_defaults(func=attack_command)

args = parser.parse_args()

args.rpc = bitcoin.rpc.Proxy()

logging.root.setLevel(logging.DEBUG)

if os.path.exists(args.wallet):
    args.wallet = Wallet.load(args.wallet)

args.func(args)
