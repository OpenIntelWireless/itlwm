// Length checks for a received EAPOL-Key frame, kept apart so the host tests run the same code.
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ItlEAPOL {
// packetLength: bytes actually received. bodyLength: the frame's Packet Body Length field, so the
// declared frame is 4 + bodyLength bytes. keyDataLength: the Key Data Length field. headerSize: the
// fixed EAPOL-Key header, Key Data excluded. maxTotal: the most the receive path accepts.
//
// The declared frame must hold the whole fixed header before anything is subtracted from it.
// Without that check, a short declared body wrapped the Key Data bound and let any length through.
inline bool keyLengthsValid(size_t packetLength, uint16_t bodyLength, uint16_t keyDataLength,
                            size_t headerSize, size_t maxTotal)
{
    const size_t total = 4 + size_t(bodyLength);
    if (total < headerSize || total > packetLength || total > maxTotal)
        return false;
    return keyDataLength <= total - headerSize;
}
}
