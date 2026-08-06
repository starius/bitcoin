// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FLOCKROOT_VALIDATION_H
#define BITCOIN_FLOCKROOT_VALIDATION_H

#include <uint256.h>

#include <array>
#include <string>
#include <vector>

class CBlock;
class CCoinsViewCache;
class CTransaction;
struct PrecomputedTransactionData;

namespace flockroot {

static constexpr int WITNESS_VERSION{2};
static constexpr size_t WITNESS_PROGRAM_SIZE{32};

struct Statement {
    std::array<unsigned char, WITNESS_PROGRAM_SIZE> output_key;
    uint256 sighash;
};

bool CollectTransactionStatements(const CTransaction& tx,
                                  const CCoinsViewCache& inputs,
                                  PrecomputedTransactionData& txdata,
                                  std::vector<Statement>& statements,
                                  std::string& error);

bool VerifyBlockProof(const CBlock& block,
                      const std::vector<Statement>& statements,
                      std::string& error);

} // namespace flockroot

#endif // BITCOIN_FLOCKROOT_VALIDATION_H
