// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CONSENSUS_FLOCKROOT_H
#define BITCOIN_CONSENSUS_FLOCKROOT_H

#include <algorithm>
#include <array>
#include <vector>

namespace flockroot {

inline constexpr std::array<unsigned char, 8> PROOF_MAGIC{'F', 'L', 'O', 'C', 'K', 'R', 'T', 0};
inline constexpr unsigned char PROOF_VERSION{1};
inline constexpr size_t PROOF_HEADER_SIZE{PROOF_MAGIC.size() + 1};
inline constexpr unsigned char FULL_CISA_MARKER{0x04};
inline constexpr unsigned char HALF_CISA_MARKER{0x05};
inline constexpr unsigned char CISA_NEGATED_BIT{0x80};

inline bool IsCisaMarker(unsigned char marker)
{
    marker &= ~CISA_NEGATED_BIT;
    return marker == FULL_CISA_MARKER || marker == HALF_CISA_MARKER;
}

inline bool HasProofMagic(const std::vector<unsigned char>& carrier)
{
    return carrier.size() >= PROOF_MAGIC.size() &&
           std::equal(PROOF_MAGIC.begin(), PROOF_MAGIC.end(), carrier.begin());
}

} // namespace flockroot

#endif // BITCOIN_CONSENSUS_FLOCKROOT_H
