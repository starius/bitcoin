// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <flockroot_validation.h>

#include <coins.h>
#include <consensus/flockroot.h>
#include <flockroot.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace flockroot {
namespace {

static constexpr uint32_t MAX_PROOF_SIZE{4'000'000};

void WriteLE32(std::vector<unsigned char>& out, uint32_t value)
{
    out.push_back(value & 0xff);
    out.push_back((value >> 8) & 0xff);
    out.push_back((value >> 16) & 0xff);
    out.push_back((value >> 24) & 0xff);
}

bool IsFlockrootOutput(const CScript& script, std::vector<unsigned char>& program)
{
    int version;
    return script.IsWitnessProgram(version, program) &&
           version == WITNESS_VERSION && program.size() == WITNESS_PROGRAM_SIZE;
}

bool ExtractCarrier(const std::vector<unsigned char>& carrier,
                    std::vector<unsigned char>& proof,
                    bool& proof_found,
                    std::string& error)
{
    if (proof_found) {
        error = "multiple Flockroot coinbase proof carriers";
        return false;
    }
    if (carrier.size() < PROOF_HEADER_SIZE) {
        error = "truncated Flockroot proof carrier";
        return false;
    }
    if (carrier[PROOF_MAGIC.size()] != PROOF_VERSION) {
        error = "unsupported Flockroot proof carrier version";
        return false;
    }
    if (carrier.size() - PROOF_HEADER_SIZE > MAX_PROOF_SIZE) {
        error = "Flockroot proof exceeds size limit";
        return false;
    }
    proof.assign(carrier.begin() + PROOF_HEADER_SIZE, carrier.end());
    proof_found = true;
    return true;
}

} // namespace

bool ExtractCoinbaseProof(const CTransaction& coinbase,
                          std::vector<unsigned char>& proof,
                          bool& proof_found,
                          std::string& error)
{
    if (!coinbase.IsCoinBase()) {
        error = "Flockroot proof source is not coinbase";
        return false;
    }
    for (const CTxOut& output : coinbase.vout) {
        const CScript& script{output.scriptPubKey};
        if (script.empty() || script.front() != OP_RETURN) continue;
        auto cursor{script.begin()};
        opcodetype opcode;
        std::vector<unsigned char> carrier;
        if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN) continue;
        if (!script.GetOp(cursor, opcode, carrier) || opcode > OP_PUSHDATA4 || cursor != script.end()) continue;
        if (!HasProofMagic(carrier)) continue;
        if (!ExtractCarrier(carrier, proof, proof_found, error)) return false;
    }
    return true;
}

bool CollectTransactionStatements(const CTransaction& tx,
                                  const CCoinsViewCache& inputs,
                                  PrecomputedTransactionData& txdata,
                                  std::vector<Statement>& statements,
                                  std::string& error)
{
    std::vector<std::pair<size_t, std::vector<unsigned char>>> flockroot_inputs;
    for (size_t input_index = 0; input_index < tx.vin.size(); ++input_index) {
        const Coin& coin{inputs.AccessCoin(tx.vin[input_index].prevout)};
        std::vector<unsigned char> program;
        if (!IsFlockrootOutput(coin.out.scriptPubKey, program)) continue;
        const CScriptWitness& witness{tx.vin[input_index].scriptWitness};
        if (witness.stack.size() == 1) {
            flockroot_inputs.emplace_back(input_index, std::move(program));
        }
    }
    if (flockroot_inputs.empty()) return true;

    if (!txdata.m_spent_outputs_ready) {
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(tx.vin.size());
        for (const CTxIn& input : tx.vin) {
            spent_outputs.push_back(inputs.AccessCoin(input.prevout).out);
        }
        txdata.Init(tx, std::move(spent_outputs), /*force=*/true);
    }

    for (const auto& [input_index, program] : flockroot_inputs) {
        const CScriptWitness& witness{tx.vin[input_index].scriptWitness};
        if (witness.stack.size() != 1 ||
            (witness.stack[0].size() != 64 && witness.stack[0].size() != 65)) {
            error = "invalid Flockroot key-spend witness";
            return false;
        }
        uint8_t hash_type{SIGHASH_DEFAULT};
        if (witness.stack[0].size() == 65) {
            hash_type = witness.stack[0].back();
            if (hash_type == SIGHASH_DEFAULT) {
                error = "invalid Flockroot Schnorr sighash byte";
                return false;
            }
        }
        ScriptExecutionData execdata;
        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        uint256 sighash;
        if (!SignatureHashSchnorr(sighash, execdata, tx, input_index, hash_type,
                                  SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL)) {
            error = "failed to compute Flockroot Schnorr sighash";
            return false;
        }
        Statement& statement{statements.emplace_back()};
        std::copy(program.begin(), program.end(), statement.output_key.begin());
        statement.sighash = sighash;
        std::copy_n(witness.stack[0].begin(), statement.signature.size(), statement.signature.begin());
    }
    return true;
}

bool VerifyBlockProof(const std::vector<Statement>& statements,
                      const std::vector<unsigned char>& proof,
                      bool proof_found,
                      std::string& error)
{
    if (statements.empty()) {
        if (proof_found) error = "Flockroot proof present without Flockroot spends";
        return !proof_found;
    }
    if (!proof_found) {
        error = "missing Flockroot block proof";
        return false;
    }
    if (statements.size() > std::numeric_limits<uint32_t>::max()) {
        error = "too many Flockroot statements";
        return false;
    }

    std::vector<unsigned char> encoded;
    encoded.reserve(4 + statements.size() * 128);
    WriteLE32(encoded, statements.size());
    for (const Statement& statement : statements) {
        encoded.insert(encoded.end(), statement.output_key.begin(), statement.output_key.end());
        encoded.insert(encoded.end(), statement.sighash.begin(), statement.sighash.end());
        encoded.insert(encoded.end(), statement.signature.begin(), statement.signature.end());
    }
    if (!flockroot_verify_block(encoded.data(), encoded.size(), proof.data(), proof.size())) {
        error = "invalid Flockroot block proof";
        return false;
    }
    return true;
}

} // namespace flockroot
