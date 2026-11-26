// Several unicast AWDL frames in flight on the monitor queue. The firmware reports them in
// the order they were sent. After a failure nothing new goes until those in flight finish,
// and failed frames are then resent one at a time, oldest first, to keep the order. A resend
// is one more frame in this window, so it never goes back on the retry list by itself.
#pragma once
#include <stdint.h>
#include <stddef.h>
namespace ItlAWDL {
constexpr unsigned kTxBurstCapacity = 8;
constexpr unsigned kTxFrameBytes = 1600;
constexpr unsigned txWindowFor(int requested) {
    return requested < 1 ? 1U : requested > int(kTxBurstCapacity) ? kTxBurstCapacity : unsigned(requested);
}
struct BurstFrame { uint64_t submitUS; uint16_t length; uint8_t step; bool isRetry;
    bool requestedWideRate; uint8_t bytes[kTxFrameBytes]; };
// True when the send path has stopped reporting completions for this long.
constexpr uint64_t kTxStallUS = 3000000;
constexpr bool txStalled(bool busy, uint64_t nowUS, uint64_t busySinceUS, uint64_t lastCompletionUS) {
    const uint64_t from = busySinceUS > lastCompletionUS ? busySinceUS : lastCompletionUS;
    return busy && busySinceUS && nowUS >= from && nowUS - from >= kTxStallUS;
}
// Group frames get no ACK, and a peer only hears them while it's on this channel. One AWDL slot
// is about 64 TU, so copies 64 TU apart should reach any slot the peer gives this channel.
constexpr uint64_t kMulticastRepeatUS = 64U * 1024U;
constexpr unsigned kMulticastRepeatFrames = 4;
constexpr unsigned multicastRepeatsFor(int requested) {
    return requested < 1 ? 1U : requested > 32 ? 32U : unsigned(requested);
}
struct MulticastRepeat { uint64_t nextUS; unsigned left; uint16_t length; uint8_t bytes[kTxFrameBytes]; };
struct MulticastRepeats {
    MulticastRepeat frames[kMulticastRepeatFrames];
    unsigned next;
    uint32_t overwritten;
    void reset() { next = overwritten = 0; for (auto &f : frames) f.left = 0; }
    // copies is the total, including the one being sent now.
    void add(const uint8_t *frame, size_t length, uint64_t nowUS, unsigned copies) {
        if (copies < 2 || !frame || !length || length > kTxFrameBytes) return;
        MulticastRepeat &slot = frames[next];
        if (slot.left) ++overwritten;
        next = (next + 1) % kMulticastRepeatFrames;
        slot.left = copies - 1;
        slot.nextUS = nowUS + kMulticastRepeatUS;
        slot.length = uint16_t(length);
        for (size_t i = 0; i < length; ++i) slot.bytes[i] = frame[i];
    }
    // The earliest copy that's due, or nullptr. The caller sends it, then calls sent().
    MulticastRepeat *due(uint64_t nowUS) {
        MulticastRepeat *best = nullptr;
        for (auto &f : frames)
            if (f.left && nowUS >= f.nextUS && (!best || f.nextUS < best->nextUS)) best = &f;
        return best;
    }
    static void sent(MulticastRepeat &f, uint64_t nowUS) { --f.left; f.nextUS = nowUS + kMulticastRepeatUS; }
};
struct TxBurst {
    BurstFrame inFlight[kTxBurstCapacity];
    BurstFrame retry[kTxBurstCapacity];
    unsigned head, count, retryHead, retryCount;
    void reset() { head = count = retryHead = retryCount = 0; }
    bool canSend(unsigned window) const {
        return count < (window > kTxBurstCapacity ? kTxBurstCapacity : window) && !retryCount;
    }
    // Copies the frame. False leaves everything as it was.
    bool push(const uint8_t *frame, size_t length, uint64_t nowUS, uint8_t step, bool isRetry = false) {
        if (!frame || !length || length > kTxFrameBytes || count >= kTxBurstCapacity) return false;
        BurstFrame &slot = inFlight[(head + count) % kTxBurstCapacity];
        slot.submitUS = nowUS;
        slot.length = uint16_t(length);
        slot.step = step;
        slot.isRetry = isRetry;
        slot.requestedWideRate = false;
        for (size_t i = 0; i < length; ++i) slot.bytes[i] = frame[i];
        ++count;
        return true;
    }
    const BurstFrame *front() const { return count ? &inFlight[head] : nullptr; }
    void markNewestWideRate() {
        if (count)
            inFlight[(head + count - 1) % kTxBurstCapacity].requestedWideRate = true;
    }
    // For a frame that couldn't be handed to the firmware.
    void dropNewest() { if (count) --count; }
    void complete(bool ok) {
        if (!count) return;
        if (!ok && !inFlight[head].isRetry && retryCount < kTxBurstCapacity) {
            BurstFrame &slot = retry[(retryHead + retryCount) % kTxBurstCapacity];
            slot = inFlight[head];
            ++retryCount;
        }
        head = (head + 1) % kTxBurstCapacity;
        --count;
    }
    bool readyForRetry() const { return !count && retryCount; }
    bool takeRetry(uint8_t *output, size_t capacity, size_t *length) {
        if (!readyForRetry() || !output || !length) return false;
        const BurstFrame &slot = retry[retryHead];
        if (slot.length > capacity) return false;
        for (size_t i = 0; i < slot.length; ++i) output[i] = slot.bytes[i];
        *length = slot.length;
        retryHead = (retryHead + 1) % kTxBurstCapacity;
        --retryCount;
        return true;
    }
};
}
