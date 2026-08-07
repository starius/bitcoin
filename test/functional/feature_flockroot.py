#!/usr/bin/env python3
"""End-to-end prototype test for witness-v2 Flockroot block authorization."""

import json
from pathlib import Path
import subprocess
import sys
import time

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import (
    TaggedHash,
    compute_xonly_pubkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    ser_string,
)
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_2,
    OP_RETURN,
    OP_TRUE,
    SIGHASH_DEFAULT,
    TaprootSignatureHash,
)
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


PROOF_MAGIC = b"FLOCKRT\x00"
PROOF_VERSION = 0
TARGET_BLOCK_WEIGHT = 3_950_000
FILLER_CHUNK_SIZE = 8_000


def pq_root(public_key, path=()):
    root = TaggedHash("Flockroot/PQLeaf", bytes([0]) + public_key)
    for sibling in path:
        root = TaggedHash("Flockroot/PQBranch", b"".join(sorted([root, sibling])))
    return root


def derive_flockroot_key(internal_secret, public_key, pq_path=(), script_root=None):
    internal_key = compute_xonly_pubkey(internal_secret)[0]
    hybrid_tweak = TaggedHash(
        "Flockroot/HybridTweak", internal_key + pq_root(public_key, pq_path)
    )
    hybrid_secret = tweak_add_privkey(internal_secret, hybrid_tweak)
    assert hybrid_secret is not None
    hybrid_key = compute_xonly_pubkey(hybrid_secret)[0]
    tap_tweak = TaggedHash("TapTweak", hybrid_key + (script_root or b""))
    output_secret = tweak_add_privkey(hybrid_secret, tap_tweak)
    assert output_secret is not None
    output_key, output_negated = compute_xonly_pubkey(output_secret)
    return internal_key, hybrid_key, output_secret, output_key, output_negated


class FlockrootTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def add_options(self, parser):
        parser.add_argument("--flockroot-cli", required=True)
        parser.add_argument("--shrincs-dir", required=True)
        parser.add_argument("--artifact-dir", required=True)
        parser.add_argument("--flockroot-spends", default=16, type=int)

    def make_block(self, transactions, fees, proof=None, duplicate_proof=False, fill=False):
        node = self.nodes[0]
        height = node.getblockcount() + 1
        tip = int(node.getbestblockhash(), 16)
        block_time = node.getblock(node.getbestblockhash())["time"] + 1
        coinbase = create_coinbase(height, fees=fees)
        for tx in transactions:
            witness = tx.wit.vtxinwit[0].scriptWitness
            if witness.stack and len(witness.stack[0]) in (64, 65):
                witness.stack = [witness.stack[0]]

        if proof is not None:
            carrier = PROOF_MAGIC + bytes([PROOF_VERSION]) + proof
            coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, carrier])))
            if duplicate_proof:
                coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, carrier])))

        block = create_block(tip, coinbase, ntime=block_time, txlist=transactions)
        if fill:
            filler_index = 0
            # Leave room for the witness commitment and serialization boundary effects.
            while block.get_weight() + 4 * (FILLER_CHUNK_SIZE + 32) < TARGET_BLOCK_WEIGHT:
                payload = b"FILL" + filler_index.to_bytes(4, "little") + bytes(FILLER_CHUNK_SIZE - 8)
                coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, payload])))
                filler_index += 1
                block = create_block(tip, coinbase, ntime=block_time, txlist=transactions)

        add_witness_commitment(block)
        assert block.get_weight() <= 4_000_000
        solve_start = time.perf_counter()
        block.solve()
        return block, time.perf_counter() - solve_start

    def run_test(self):
        node0, node1 = self.nodes
        wallet = MiniWallet(node0)
        artifact_dir = Path(self.options.artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)

        sys.path.insert(0, self.options.shrincs_dir)
        from shrincs import FXMSS_SHAPE_BALANCED, shrincs_keygen, shrincs_sign

        spend_count = self.options.flockroot_spends
        assert 0 < spend_count <= 64
        tree_depth = max(1, (spend_count - 1).bit_length())
        shrincs_secret, shrincs_public = shrincs_keygen(
            bytes(range(48)), bytes([FXMSS_SHAPE_BALANCED, tree_depth])
        )
        key_records = []
        for index in range(spend_count):
            internal_secret = (index + 1).to_bytes(32, "big")
            internal_key, hybrid_key, output_secret, output_key, _ = derive_flockroot_key(
                internal_secret, shrincs_public
            )
            key_records.append({
                "internal_secret": internal_secret,
                "internal_key": internal_key,
                "hybrid_key": hybrid_key,
                "output_secret": output_secret,
                "output_key": output_key,
                "script_pubkey": CScript([OP_2, output_key]),
                "address": encode_segwit_address("bcrt", 2, output_key),
            })
        flockroot_address = key_records[0]["address"]

        leaf_script = CScript([OP_TRUE])
        script_root = TaggedHash(
            "TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT]) + ser_string(leaf_script)
        )
        script_internal_secret = (spend_count + 1).to_bytes(32, "big")
        script_internal_key, script_hybrid_key, script_output_secret, script_output_key, script_output_negated = (
            derive_flockroot_key(script_internal_secret, shrincs_public, script_root=script_root)
        )
        flockroot_script_tree = CScript([OP_2, script_output_key])
        flockroot_script_address = encode_segwit_address("bcrt", 2, script_output_key)

        funding = wallet.create_self_transfer_multi(num_outputs=spend_count + 1, fee_per_output=2_000)
        funding_tx = funding["tx"]
        for output, key_record in zip(funding_tx.vout[:spend_count], key_records):
            output.scriptPubKey = key_record["script_pubkey"]
        funding_tx.vout[spend_count].scriptPubKey = flockroot_script_tree
        funding_txid = node0.sendrawtransaction(funding_tx.serialize().hex())
        assert_equal(funding_txid, funding_tx.txid_hex)
        self.generate(wallet, 1)

        transactions = []
        authorizations = []
        fee_per_spend = 1_000
        for index in range(spend_count):
            key_record = key_records[index]
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, index))]
            tx.vout = [CTxOut(funding_tx.vout[index].nValue - fee_per_spend, CScript([OP_TRUE]))]
            sighash = TaprootSignatureHash(
                tx, [funding_tx.vout[index]], SIGHASH_DEFAULT, input_index=0
            )
            signature = sign_schnorr(key_record["output_secret"], sighash)
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [signature]
            transactions.append(tx)

            shrincs_signature = shrincs_sign(sighash, shrincs_secret, index, None)
            assert shrincs_signature is not None
            authorizations.append({
                "output_key": key_record["output_key"].hex(),
                "internal_key": key_record["internal_key"].hex(),
                "public_key": {
                    "pk_seed": shrincs_public[0:16].hex(),
                    "sl_root": shrincs_public[16:32].hex(),
                    "sf_root": shrincs_public[32:48].hex(),
                },
                "pq_path": [],
                "script_root": None,
                "message": sighash.hex(),
                "signature": {"bytes": shrincs_signature.hex()},
            })

        script_tx = CTransaction()
        script_tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, spend_count))]
        script_tx.vout = [CTxOut(
            funding_tx.vout[spend_count].nValue - fee_per_spend,
            CScript([OP_TRUE]),
        )]
        script_tx.wit.vtxinwit = [CTxInWitness()]
        script_tx.wit.vtxinwit[0].scriptWitness.stack = [
            bytes(leaf_script),
            bytes([LEAF_VERSION_TAPSCRIPT | script_output_negated]) + script_hybrid_key,
        ]
        transactions.append(script_tx)

        authorizations_path = artifact_dir / "authorizations.json"
        proof_path = artifact_dir / "flockroot-proof.bin"
        authorizations_path.write_text(json.dumps(authorizations, indent=2) + "\n")
        prove_start = time.perf_counter()
        subprocess.run(
            [
                self.options.flockroot_cli,
                "prove-block",
                "--authorizations",
                str(authorizations_path),
                "--output",
                str(proof_path),
            ],
            check=True,
        )
        prove_seconds = time.perf_counter() - prove_start
        proof = proof_path.read_bytes()

        workload_block, workload_solve_seconds = self.make_block(
            transactions, (spend_count + 1) * fee_per_spend, proof=proof
        )

        self.disconnect_nodes(0, 1)

        missing_block, _ = self.make_block(
            transactions, (spend_count + 1) * fee_per_spend, proof=None
        )
        assert_equal(node0.submitblock(missing_block.serialize().hex()), "bad-flockroot-proof")

        tampered = bytearray(proof)
        tampered[len(tampered) // 2] ^= 1
        tampered_block, _ = self.make_block(
            transactions, (spend_count + 1) * fee_per_spend, proof=bytes(tampered)
        )
        assert_equal(node0.submitblock(tampered_block.serialize().hex()), "bad-flockroot-proof")

        if spend_count > 1:
            duplicate_block, _ = self.make_block(
                transactions,
                (spend_count + 1) * fee_per_spend,
                proof=proof,
                duplicate_proof=True,
            )
            assert_equal(node0.submitblock(duplicate_block.serialize().hex()), "bad-flockroot-proof")

        block, solve_seconds = self.make_block(
            transactions, (spend_count + 1) * fee_per_spend, proof=proof, fill=True
        )
        validation_start = time.perf_counter()
        assert_equal(node0.submitblock(block.serialize().hex()), None)
        validation_seconds = time.perf_counter() - validation_start

        second_validation_start = time.perf_counter()
        assert_equal(node1.submitblock(block.serialize().hex()), None)
        second_validation_seconds = time.perf_counter() - second_validation_start

        (artifact_dir / "funding-transaction.hex").write_text(funding_tx.serialize().hex() + "\n")
        (artifact_dir / "spending-transactions.json").write_text(
            json.dumps([tx.serialize().hex() for tx in transactions], indent=2) + "\n"
        )
        (artifact_dir / "flockroot-block.hex").write_text(block.serialize().hex() + "\n")
        (artifact_dir / "keys.json").write_text(json.dumps({
            "key_spends": [{
                "ec_internal_secret": record["internal_secret"].hex(),
                "ec_internal_key": record["internal_key"].hex(),
                "ec_output_secret": record["output_secret"].hex(),
                "ec_output_key": record["output_key"].hex(),
                "ec_hybrid_key": record["hybrid_key"].hex(),
                "script_pubkey": record["script_pubkey"].hex(),
                "address": record["address"],
            } for record in key_records],
            "script_path_internal_secret": script_internal_secret.hex(),
            "script_path_internal_key": script_internal_key.hex(),
            "script_path_output_secret": script_output_secret.hex(),
            "script_path_output_key": script_output_key.hex(),
            "script_path_hybrid_key": script_hybrid_key.hex(),
            "shrincs_secret": shrincs_secret.hex(),
            "shrincs_public": shrincs_public.hex(),
            "script_pubkey": key_records[0]["script_pubkey"].hex(),
            "address": key_records[0]["address"],
            "script_path_address": flockroot_script_address,
            "script_path_script_pubkey": flockroot_script_tree.hex(),
        }, indent=2) + "\n")
        metrics = {
            "name": "Flockroot",
            "key_path_spends": spend_count,
            "script_path_spends": 1,
            "total_flockroot_spends": spend_count + 1,
            "proof_bytes": len(proof),
            "proof_coinbase_payload_bytes": len(PROOF_MAGIC) + 1 + len(proof),
            "workload_block_bytes": len(workload_block.serialize()),
            "workload_block_weight": workload_block.get_weight(),
            "workload_solve_seconds": workload_solve_seconds,
            "block_bytes": len(block.serialize()),
            "block_weight": block.get_weight(),
            "prove_seconds": prove_seconds,
            "solve_seconds": solve_seconds,
            "mine_including_prove_seconds": prove_seconds + solve_seconds,
            "validation_node0_seconds": validation_seconds,
            "validation_node1_seconds": second_validation_seconds,
            "block_hash": block.hash_hex,
            "funding_txid": funding_txid,
            "address": flockroot_address,
            "spending_txids": [tx.txid_hex for tx in transactions],
        }
        (artifact_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
        self.log.info("Flockroot metrics: %s", json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    FlockrootTest(__file__).main()
