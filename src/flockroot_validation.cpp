// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <flockroot_validation.h>

#include <coins.h>
#include <flockroot.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace flockroot {
namespace {

static constexpr std::array<unsigned char, 8> PROOF_MAGIC{'F', 'L', 'O', 'C', 'K', 'R', 'T', 0};
static constexpr unsigned char PROOF_VERSION{0};
static constexpr size_t PROOF_HEADER_SIZE{PROOF_MAGIC.size() + 1 + 4 + 4 + 4};
static constexpr uint32_t MAX_PROOF_CHUNKS{1024};
static constexpr uint32_t MAX_PROOF_SIZE{4'000'000};

uint32_t ReadLE32(std::span<const unsigned char> bytes)
{
    return uint32_t{bytes[0]} |
           (uint32_t{bytes[1]} << 8) |
           (uint32_t{bytes[2]} << 16) |
           (uint32_t{bytes[3]} << 24);
}

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

bool ExtractProof(const CTransaction& coinbase,
                  std::vector<unsigned char>& proof,
                  bool& found,
                  std::string& error)
{
    found = false;
    std::optional<uint32_t> chunk_count;
    std::optional<uint32_t> total_size;
    std::vector<std::optional<std::vector<unsigned char>>> chunks;

    for (const CTxOut& output : coinbase.vout) {
        const CScript& script{output.scriptPubKey};
        CScript::const_iterator pc{script.begin()};
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) continue;
        if (!script.GetOp(pc, opcode, data) || opcode > OP_PUSHDATA4 || pc != script.end()) continue;
        if (data.size() < PROOF_MAGIC.size() ||
            !std::equal(PROOF_MAGIC.begin(), PROOF_MAGIC.end(), data.begin())) {
            continue;
        }
        found = true;
        if (data.size() < PROOF_HEADER_SIZE) {
            error = "truncated Flockroot proof chunk";
            return false;
        }
        if (data[PROOF_MAGIC.size()] != PROOF_VERSION) {
            error = "unsupported Flockroot proof carrier version";
            return false;
        }
        const size_t fields{PROOF_MAGIC.size() + 1};
        const uint32_t index{ReadLE32(std::span{data}.subspan(fields, 4))};
        const uint32_t count{ReadLE32(std::span{data}.subspan(fields + 4, 4))};
        const uint32_t size{ReadLE32(std::span{data}.subspan(fields + 8, 4))};
        if (count == 0 || count > MAX_PROOF_CHUNKS || index >= count || size > MAX_PROOF_SIZE) {
            error = "invalid Flockroot proof chunk metadata";
            return false;
        }
        if (!chunk_count) {
            chunk_count = count;
            total_size = size;
            chunks.resize(count);
        } else if (*chunk_count != count || *total_size != size) {
            error = "inconsistent Flockroot proof chunk metadata";
            return false;
        }
        if (chunks[index]) {
            error = "duplicate Flockroot proof chunk";
            return false;
        }
        chunks[index] = std::vector<unsigned char>(data.begin() + PROOF_HEADER_SIZE, data.end());
    }

    if (!found) return true;
    proof.clear();
    proof.reserve(*total_size);
    for (const auto& chunk : chunks) {
        if (!chunk) {
            error = "missing Flockroot proof chunk";
            return false;
        }
        proof.insert(proof.end(), chunk->begin(), chunk->end());
    }
    if (proof.size() != *total_size) {
        error = "Flockroot proof size mismatch";
        return false;
    }
    return true;
}

} // namespace

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
        if (IsFlockrootOutput(coin.out.scriptPubKey, program)) {
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
            error = "Flockroot key spend requires one 64- or 65-byte Schnorr signature";
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
    }
    return true;
}

bool VerifyBlockProof(const CBlock& block,
                      const std::vector<Statement>& statements,
                      std::string& error)
{
    std::vector<unsigned char> proof;
    bool found{false};
    if (!ExtractProof(*block.vtx[0], proof, found, error)) return false;
    if (statements.empty()) {
        if (found) error = "Flockroot proof present without Flockroot spends";
        return !found;
    }
    if (!found) {
        error = "missing Flockroot block proof";
        return false;
    }
    if (statements.size() > std::numeric_limits<uint32_t>::max()) {
        error = "too many Flockroot statements";
        return false;
    }

    std::vector<unsigned char> encoded;
    encoded.reserve(4 + statements.size() * 64);
    WriteLE32(encoded, statements.size());
    for (const Statement& statement : statements) {
        encoded.insert(encoded.end(), statement.output_key.begin(), statement.output_key.end());
        encoded.insert(encoded.end(), statement.sighash.begin(), statement.sighash.end());
    }
    if (!flockroot_verify_block(encoded.data(), encoded.size(), proof.data(), proof.size())) {
        error = "invalid Flockroot block proof";
        return false;
    }
    return true;
}

} // namespace flockroot
