// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CONSENSUS_FLOCKROOT_H
#define BITCOIN_CONSENSUS_FLOCKROOT_H

#include <script/script.h>

#include <algorithm>
#include <array>
#include <vector>

namespace flockroot {

inline constexpr std::array<unsigned char, 8> PROOF_MAGIC{'F', 'L', 'O', 'C', 'K', 'R', 'T', 0};
inline constexpr unsigned char PROOF_VERSION{0};
inline constexpr size_t PROOF_HEADER_SIZE{PROOF_MAGIC.size() + 1};

inline bool HasProofMagic(const std::vector<unsigned char>& carrier)
{
    return carrier.size() >= PROOF_MAGIC.size() &&
           std::equal(PROOF_MAGIC.begin(), PROOF_MAGIC.end(), carrier.begin());
}

inline bool IsProofCarrier(const CScriptWitness& witness)
{
    if (witness.stack.size() != 2) return false;
    const auto& carrier{witness.stack[1]};
    return carrier.size() >= PROOF_HEADER_SIZE &&
           HasProofMagic(carrier) &&
           carrier[PROOF_MAGIC.size()] == PROOF_VERSION;
}

} // namespace flockroot

#endif // BITCOIN_CONSENSUS_FLOCKROOT_H
