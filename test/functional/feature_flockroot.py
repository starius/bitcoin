#!/usr/bin/env python3
"""End-to-end prototype test for witness-v2 Flockroot block authorization."""

import copy
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
    ORDER,
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
    taproot_construct,
)
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


PROOF_MAGIC = b"FLOCKRT\x00"
PROOF_VERSION = 1
TARGET_BLOCK_WEIGHT = 3_950_000
FILLER_CHUNK_SIZE = 8_000
NORMAL_TAPROOT_SPENDS_PER_MODE = 8


def pq_leaf(public_key):
    return TaggedHash("Flockroot/PQLeaf", bytes([0]) + public_key)


def taproot_tree_root(leaf, path=()):
    root = leaf
    for sibling in path:
        root = TaggedHash("TapBranch", b"".join(sorted([root, sibling])))
    return root


def derive_flockroot_key(internal_secret, public_key, tap_path=()):
    internal_key = compute_xonly_pubkey(internal_secret)[0]
    tree_root = taproot_tree_root(pq_leaf(public_key), tap_path)
    tap_tweak = TaggedHash("TapTweak", internal_key + tree_root)
    output_secret = tweak_add_privkey(internal_secret, tap_tweak)
    assert output_secret is not None
    output_key, output_negated = compute_xonly_pubkey(output_secret)
    tweak_scalar = int.from_bytes(tap_tweak, "big")
    signed_tweak = (
        (ORDER - tweak_scalar) % ORDER if output_negated else tweak_scalar
    ).to_bytes(32, "big")
    return internal_key, tap_tweak, signed_tweak, output_secret, output_key, output_negated


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
        block_transactions = copy.deepcopy(transactions)

        if proof is not None:
            carrier = PROOF_MAGIC + bytes([PROOF_VERSION]) + proof
            carriers_needed = 2 if duplicate_proof else 1
            carriers_added = 0
            for tx in block_transactions:
                for txin_witness in tx.wit.vtxinwit:
                    witness = txin_witness.scriptWitness
                    if len(witness.stack) == 1 and len(witness.stack[0]) in (96, 97):
                        witness.stack.append(carrier)
                        carriers_added += 1
                        if carriers_added == carriers_needed:
                            break
                if carriers_added == carriers_needed:
                    break
            assert_equal(carriers_added, carriers_needed)

        block = create_block(tip, coinbase, ntime=block_time, txlist=block_transactions)
        if fill:
            filler_index = 0
            # Leave room for the witness commitment and serialization boundary effects.
            while block.get_weight() + 4 * (FILLER_CHUNK_SIZE + 32) < TARGET_BLOCK_WEIGHT:
                payload = b"FILL" + filler_index.to_bytes(4, "little") + bytes(FILLER_CHUNK_SIZE - 8)
                coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, payload])))
                filler_index += 1
                block = create_block(tip, coinbase, ntime=block_time, txlist=block_transactions)

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
        assert 0 < spend_count <= 256
        tree_depth = max(1, (spend_count - 1).bit_length())
        shrincs_secret, shrincs_public = shrincs_keygen(
            bytes(range(48)), bytes([FXMSS_SHAPE_BALANCED, tree_depth])
        )
        key_records = []
        next_internal_secret = 1
        for index in range(spend_count):
            internal_secret = next_internal_secret.to_bytes(32, "big")
            tap_path = [
                TaggedHash("Flockroot/TestSibling", index.to_bytes(4, "big") + level.to_bytes(1, "big"))
                for level in range(index % 5)
            ]
            derived = derive_flockroot_key(internal_secret, shrincs_public, tap_path)
            (
                internal_key,
                tap_tweak,
                signed_tweak,
                output_secret,
                output_key,
                output_negated,
            ) = derived
            next_internal_secret = int.from_bytes(internal_secret, "big") + 1
            key_records.append({
                "internal_secret": internal_secret,
                "internal_key": internal_key,
                "tap_tweak": tap_tweak,
                "signed_tweak": signed_tweak,
                "output_secret": output_secret,
                "output_key": output_key,
                "output_negated": output_negated,
                "tap_path": tap_path,
                "script_pubkey": CScript([OP_2, output_key]),
                "address": encode_segwit_address("bcrt", 2, output_key),
            })
        assert_equal(len({record["address"] for record in key_records}), spend_count)
        flockroot_address = key_records[0]["address"]

        leaf_script = CScript([OP_TRUE])
        script_root = TaggedHash(
            "TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT]) + ser_string(leaf_script)
        )
        other_script = CScript([OP_RETURN])
        other_leaf = TaggedHash(
            "TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT]) + ser_string(other_script)
        )
        pq_node = TaggedHash("TapBranch", b"".join(sorted([pq_leaf(shrincs_public), other_leaf])))
        script_tap_path = [other_leaf, script_root]
        script_internal_secret = next_internal_secret.to_bytes(32, "big")
        script_derived = derive_flockroot_key(
            script_internal_secret, shrincs_public, script_tap_path
        )
        (
            script_internal_key,
            script_tap_tweak,
            _,
            script_output_secret,
            script_output_key,
            script_output_negated,
        ) = script_derived
        flockroot_script_tree = CScript([OP_2, script_output_key])
        flockroot_script_address = encode_segwit_address("bcrt", 2, script_output_key)

        normal_key_secret = next_internal_secret.to_bytes(32, "big")
        next_internal_secret += 1
        normal_key_internal = compute_xonly_pubkey(normal_key_secret)[0]
        normal_key_taproot = taproot_construct(normal_key_internal)
        normal_key_output_secret = tweak_add_privkey(normal_key_secret, normal_key_taproot.tweak)

        normal_script_secret = next_internal_secret.to_bytes(32, "big")
        normal_script_internal = compute_xonly_pubkey(normal_script_secret)[0]
        normal_script = CScript([OP_TRUE])
        normal_script_taproot = taproot_construct(
            normal_script_internal,
            [("normal", normal_script)],
        )
        normal_leaf = normal_script_taproot.leaves["normal"]
        normal_control = (
            bytes([normal_leaf.version | normal_script_taproot.negflag])
            + normal_script_taproot.internal_pubkey
            + normal_leaf.merklebranch
        )

        ordinary_count = 2 * NORMAL_TAPROOT_SPENDS_PER_MODE
        funding = wallet.create_self_transfer_multi(
            num_outputs=spend_count + 1 + ordinary_count,
            fee_per_output=2_000,
        )
        funding_tx = funding["tx"]
        for output, key_record in zip(funding_tx.vout[:spend_count], key_records):
            output.scriptPubKey = key_record["script_pubkey"]
        funding_tx.vout[spend_count].scriptPubKey = flockroot_script_tree
        normal_key_start = spend_count + 1
        normal_script_start = normal_key_start + NORMAL_TAPROOT_SPENDS_PER_MODE
        for index in range(normal_key_start, normal_script_start):
            funding_tx.vout[index].scriptPubKey = normal_key_taproot.scriptPubKey
        for index in range(normal_script_start, normal_script_start + NORMAL_TAPROOT_SPENDS_PER_MODE):
            funding_tx.vout[index].scriptPubKey = normal_script_taproot.scriptPubKey
        funding_txid = node0.sendrawtransaction(funding_tx.serialize().hex())
        assert_equal(funding_txid, funding_tx.txid_hex)
        self.generate(wallet, 1)

        transactions = []
        authorizations = []
        fee_per_spend = 1_000

        def append_authorization(index, sighash):
            key_record = key_records[index]
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
                "tap_path": [sibling.hex() for sibling in key_record["tap_path"]],
                "message": sighash.hex(),
                "signature": {"bytes": shrincs_signature.hex()},
            })

        for index in range(spend_count):
            key_record = key_records[index]
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, index))]
            tx.vout = [CTxOut(funding_tx.vout[index].nValue - fee_per_spend, CScript([OP_TRUE]))]
            sighash = TaprootSignatureHash(
                tx, [funding_tx.vout[index]], SIGHASH_DEFAULT, input_index=0
            )
            signature = sign_schnorr(key_record["output_secret"], sighash)
            assert_equal(len(signature), 64)
            payload = signature + key_record["signed_tweak"]
            assert_equal(len(payload), 96)
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [payload]
            transactions.append(tx)
            append_authorization(index, sighash)

        script_tx = CTransaction()
        script_tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, spend_count))]
        script_tx.vout = [CTxOut(
            funding_tx.vout[spend_count].nValue - fee_per_spend,
            CScript([OP_TRUE]),
        )]
        script_tx.wit.vtxinwit = [CTxInWitness()]
        script_tx.wit.vtxinwit[0].scriptWitness.stack = [
            bytes(leaf_script),
            bytes([LEAF_VERSION_TAPSCRIPT | script_output_negated])
            + script_internal_key
            + pq_node,
        ]
        assert_equal(
            [len(element) for element in script_tx.wit.vtxinwit[0].scriptWitness.stack],
            [1, 65],
        )
        transactions.append(script_tx)

        for output_index in range(normal_key_start, normal_script_start):
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, output_index))]
            tx.vout = [CTxOut(
                funding_tx.vout[output_index].nValue - fee_per_spend,
                CScript([OP_TRUE]),
            )]
            sighash = TaprootSignatureHash(
                tx, [funding_tx.vout[output_index]], SIGHASH_DEFAULT, input_index=0
            )
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [
                sign_schnorr(normal_key_output_secret, sighash)
            ]
            transactions.append(tx)

        for output_index in range(
            normal_script_start,
            normal_script_start + NORMAL_TAPROOT_SPENDS_PER_MODE,
        ):
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, output_index))]
            tx.vout = [CTxOut(
                funding_tx.vout[output_index].nValue - fee_per_spend,
                CScript([OP_TRUE]),
            )]
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [
                bytes(normal_script),
                normal_control,
            ]
            transactions.append(tx)

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
        total_fees = (
            spend_count + 1 + 2 * NORMAL_TAPROOT_SPENDS_PER_MODE
        ) * fee_per_spend

        workload_block, workload_solve_seconds = self.make_block(
            transactions, total_fees, proof=proof
        )

        self.disconnect_nodes(0, 1)

        missing_block, _ = self.make_block(
            transactions, total_fees, proof=None
        )
        assert_equal(node0.submitblock(missing_block.serialize().hex()), "bad-flockroot-proof")

        tampered = bytearray(proof)
        tampered[len(tampered) // 2] ^= 1
        tampered_block, _ = self.make_block(
            transactions, total_fees, proof=bytes(tampered)
        )
        assert_equal(node0.submitblock(tampered_block.serialize().hex()), "bad-flockroot-proof")

        if spend_count > 1:
            duplicate_block, _ = self.make_block(
                transactions,
                total_fees,
                proof=proof,
                duplicate_proof=True,
            )
            assert_equal(node0.submitblock(duplicate_block.serialize().hex()), "bad-flockroot-spend")

        for mutation_offset in (0, 64):
            changed_transactions = copy.deepcopy(transactions)
            witness = changed_transactions[0].wit.vtxinwit[0].scriptWitness
            witness.stack[0] = (
                witness.stack[0][:mutation_offset]
                + bytes([witness.stack[0][mutation_offset] ^ 1])
                + witness.stack[0][mutation_offset + 1:]
            )
            changed_block, _ = self.make_block(
                changed_transactions, total_fees, proof=proof
            )
            assert_equal(node0.submitblock(changed_block.serialize().hex()), "bad-flockroot-proof")

        block, solve_seconds = self.make_block(
            transactions, total_fees, proof=proof, fill=True
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
                "tap_tweak": record["tap_tweak"].hex(),
                "signed_tweak": record["signed_tweak"].hex(),
                "script_pubkey": record["script_pubkey"].hex(),
                "address": record["address"],
            } for record in key_records],
            "script_path_internal_secret": script_internal_secret.hex(),
            "script_path_internal_key": script_internal_key.hex(),
            "script_path_output_secret": script_output_secret.hex(),
            "script_path_output_key": script_output_key.hex(),
            "script_path_tap_tweak": script_tap_tweak.hex(),
            "shrincs_secret": shrincs_secret.hex(),
            "shrincs_public": shrincs_public.hex(),
            "script_pubkey": key_records[0]["script_pubkey"].hex(),
            "address": key_records[0]["address"],
            "script_path_address": flockroot_script_address,
            "script_path_script_pubkey": flockroot_script_tree.hex(),
        }, indent=2) + "\n")
        proof_carrier = PROOF_MAGIC + bytes([PROOF_VERSION]) + proof
        proof_witness_element_bytes = len(ser_string(proof_carrier))
        carrier_witness = block.vtx[1].wit.vtxinwit[0].scriptWitness.stack
        assert_equal([len(element) for element in carrier_witness], [96, len(proof_carrier)])
        (artifact_dir / "proof-carrier-witness.json").write_text(json.dumps([
            {
                "bytes": len(element),
                "hex": element.hex(),
                "meaning": "BIP-340 signature || signed TapTweak"
                if index == 0 else "discounted block-level Flock proof carrier",
            }
            for index, element in enumerate(carrier_witness)
        ], indent=2) + "\n")
        metrics = {
            "name": "Flockroot explicit tweaks",
            "key_path_spends": spend_count,
            "unique_flockroot_addresses": len({record["address"] for record in key_records}),
            "key_spend_payload_bytes_each": 96,
            "key_spend_payload_bytes_total": 96 * spend_count,
            "stateful_pq_spends": spend_count,
            "stateless_pq_spends": 0,
            "script_path_spends": 1,
            "ordinary_taproot_key_spends": NORMAL_TAPROOT_SPENDS_PER_MODE,
            "ordinary_taproot_script_spends": NORMAL_TAPROOT_SPENDS_PER_MODE,
            "total_flockroot_spends": spend_count + 1,
            "proof_bytes": len(proof),
            "proof_carrier_bytes": len(proof_carrier),
            "proof_discounted_witness_bytes": proof_witness_element_bytes,
            "proof_discounted_weight": proof_witness_element_bytes,
            "proof_if_base_weight": 4 * proof_witness_element_bytes,
            "workload_block_bytes": len(workload_block.serialize()),
            "workload_block_weight": workload_block.get_weight(),
            "explicit_key_transactions_weight": sum(
                tx.get_weight() for tx in transactions[:spend_count]
            ),
            "workload_solve_seconds": workload_solve_seconds,
            "block_bytes": len(block.serialize()),
            "block_weight": block.get_weight(),
            "filler_weight": block.get_weight() - workload_block.get_weight(),
            "workload_weight_percent": 100 * workload_block.get_weight() / block.get_weight(),
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
