#ifndef ItlScanCursor_hpp
#define ItlScanCursor_hpp

// The station scan-result cursor (getSCAN_RESULT, Sonoma kext). macOS reads the scan list one result
// per request, and the node tree can change between two requests: cache expiry, the end of a scan and
// state changes free nodes. So no node pointer is kept across requests (audit ST02). The tree is ordered
// by MAC address (ieee80211_node_cmp); the cursor is the last address returned, and the next result is
// the first node above it. Kept free of kernel types so tests/scan_cursor.cpp runs the same code.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace ItlScan {

struct Cursor {
    uint8_t mac[6];
    bool started;    // a list is being read and mac is the last address returned
    bool wrapping;   // the last result of the list was returned; the next request ends the list
};

// What the next request returns: a node, or the end of the list (with nullptr). first() and next(n) walk
// the tree in address order; address(n) is a node's 6-byte address.
template <typename Node, typename First, typename Next, typename Address>
Node *nextResult(Cursor &c, First first, Next next, Address address) {
    if (c.started) {
        for (Node *n = first(); n; n = next(n))
            if (memcmp(address(n), c.mac, sizeof(c.mac)) > 0)
                return n;
        // Everything after the cursor went away: the list ends here.
        c.started = false;
        c.wrapping = false;
        return nullptr;
    }
    if (c.wrapping) {
        c.wrapping = false;
        return nullptr;
    }
    return first();
}

// Records that n was returned. isLast: no node follows it in the tree right now.
inline void noteReturned(Cursor &c, const uint8_t *nodeAddress, bool isLast) {
    memcpy(c.mac, nodeAddress, sizeof(c.mac));
    c.started = !isLast;
    c.wrapping = isLast;
}

} // namespace ItlScan

#endif
