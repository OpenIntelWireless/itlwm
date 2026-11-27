#ifndef ItlCountedCopy_hpp
#define ItlCountedCopy_hpp

// Bounds for copies whose length comes from a count stored beside a fixed-size field (an SSID, a rate
// list) or from a packet's own offset and length. Kept free of kernel types so the host tests
// (tests/counted_copy.cpp) build the same code the kext runs.
//
// Audit P-S01: getSSID treated the 32-byte, unterminated SSID field as a C string. ST06/ST01: rate
// lists copied with the wrong count. P-A03/D02: a packet's offset and length were trusted.

#include <stddef.h>
#include <stdint.h>

namespace ItlCopy {

// How many bytes may be copied: the stored count, never negative, never more than either buffer holds.
inline size_t countedLength(long storedCount, size_t sourceCapacity, size_t destinationCapacity) {
    if (storedCount <= 0)
        return 0;
    size_t n = size_t(storedCount);
    if (n > sourceCapacity)
        n = sourceCapacity;
    if (n > destinationCapacity)
        n = destinationCapacity;
    return n;
}

// Copies the counted bytes and returns how many were copied.
template <typename D, typename S>
inline size_t copyCounted(D *destination, size_t destinationCapacity, const S *source, size_t sourceCapacity,
                          long storedCount) {
    const size_t n = countedLength(storedCount, sourceCapacity, destinationCapacity);
    if (!destination || !source)
        return 0;
    for (size_t i = 0; i < n; ++i)
        destination[i] = D(source[i]);
    return n;
}

// Whether [offset, offset + length) lies inside a buffer of bufferSize bytes, without overflow.
inline bool frameInBuffer(uint32_t offset, uint32_t length, uint32_t bufferSize) {
    return offset <= bufferSize && length <= bufferSize - offset;
}

} // namespace ItlCopy

#endif
