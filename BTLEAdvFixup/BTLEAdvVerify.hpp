// Keeps APFS's integrity check working on bluetoothd's patched pages, kept free of kernel types for host tests.
//
// bluetoothd is a compressed file on the sealed system volume. BlueToolFixup and this kext patch its code pages in
// the shared file cache as they're validated. When macOS later reloads a page of a compressed block whose other
// pages are still in memory, decmpfs decompresses only the missing pages and has APFS check the hash of the whole
// block, the patched pages included. That check fails ("Verification failed with error 94"), the reload is refused,
// and bluetoothd dies with SIGBUS (#62). Each patched page's original bytes are kept here, and the check is given a
// copy of the block with those bytes put back. The pages in memory keep their patches.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
namespace BTLEAdv {
static constexpr size_t kVerifyPage = 4096;
struct PatchedPage {
    uint64_t offset;                  // file offset of the page
    uint8_t original[kVerifyPage];    // before any kext patched it
    uint8_t patched[kVerifyPage];     // as the patches left it
};
// bluetoothd 26.7.1 has six patched pages (four BlueToolFixup, two this kext).
static constexpr size_t kMaxPatchedPages = 12;
struct PatchedPages {
    PatchedPage page[kMaxPatchedPages];
    size_t count;
    uint32_t full;                    // pages not recorded for lack of room
};

// Records a page that the validation hooks changed. A page seen again (reloaded after it was dropped) replaces its
// record. Returns false when nothing changed or there's no room.
inline bool recordPatchedPage(PatchedPages &pages, uint64_t offset, const uint8_t *before, const uint8_t *after) {
    if (!before || !after || (offset % kVerifyPage) || !memcmp(before, after, kVerifyPage))
        return false;
    size_t i = 0;
    while (i < pages.count && pages.page[i].offset != offset)
        i++;
    if (i == pages.count) {
        if (pages.count == kMaxPatchedPages) {
            pages.full++;
            return false;
        }
        pages.count++;
    }
    pages.page[i].offset = offset;
    memcpy(pages.page[i].original, before, kVerifyPage);
    memcpy(pages.page[i].patched, after, kVerifyPage);
    return true;
}

// The part of a recorded page inside [foffset, foffset + size): where it starts in the buffer, where in the page,
// and how long. False when they don't overlap.
struct Overlap { size_t bufferStart, pageStart, length; };
inline bool overlapOf(const PatchedPage &p, uint64_t foffset, size_t size, Overlap &o) {
    const uint64_t start = p.offset > foffset ? p.offset : foffset;
    const uint64_t pageEnd = p.offset + kVerifyPage, bufferEnd = foffset + size;
    const uint64_t end = pageEnd < bufferEnd ? pageEnd : bufferEnd;
    if (!size || start >= end)
        return false;
    o = {size_t(start - foffset), size_t(start - p.offset), size_t(end - start)};
    return true;
}

// True when the buffer holds some recorded page as its patches left it, so the check needs the original bytes.
// A page that's the original already (decompressed just now), or neither, is left alone.
inline bool holdsPatchedBytes(const PatchedPages &pages, uint64_t foffset, const uint8_t *buf, size_t size) {
    if (!buf)
        return false;
    for (size_t i = 0; i < pages.count; i++) {
        Overlap o;
        const PatchedPage &p = pages.page[i];
        if (overlapOf(p, foffset, size, o) && memcmp(p.original + o.pageStart, p.patched + o.pageStart, o.length) &&
            !memcmp(buf + o.bufferStart, p.patched + o.pageStart, o.length))
            return true;
    }
    return false;
}

// The recorded page at `offset` when `data` holds it exactly as the patches left it, else null. macOS can validate a
// page it already has in memory again (#62, the "Code Signature Invalid" kills): the patched bytes then don't match
// the code signature and bluetoothd is killed. Validation has to see the original bytes instead.
inline const PatchedPage *patchedPageAt(const PatchedPages &pages, uint64_t offset, const uint8_t *data) {
    if (!data)
        return nullptr;
    for (size_t i = 0; i < pages.count; i++) {
        const PatchedPage &p = pages.page[i];
        if (p.offset == offset && memcmp(p.original, p.patched, kVerifyPage) && !memcmp(data, p.patched, kVerifyPage))
            return &p;
    }
    return nullptr;
}

// In a copy of the buffer, puts back the original bytes of every recorded page found with its patches.
// Returns how many pages it put back.
inline size_t restoreOriginalBytes(const PatchedPages &pages, uint64_t foffset, uint8_t *copy, size_t size) {
    size_t restored = 0;
    if (!copy)
        return 0;
    for (size_t i = 0; i < pages.count; i++) {
        Overlap o;
        const PatchedPage &p = pages.page[i];
        if (overlapOf(p, foffset, size, o) && memcmp(p.original + o.pageStart, p.patched + o.pageStart, o.length) &&
            !memcmp(copy + o.bufferStart, p.patched + o.pageStart, o.length)) {
            memcpy(copy + o.bufferStart, p.original + o.pageStart, o.length);
            restored++;
        }
    }
    return restored;
}
}
