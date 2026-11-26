// SPDX-License-Identifier: GPL-3.0-only
// The HCI hook follows IntelBTPatcher (OpenIntelWireless/IntelBluetoothFirmware, GPLv3),
// the page hook follows BlueToolFixup (acidanthera/BrcmPatchRAM).
//
// Separate Lilu plugin: lets bluetoothd use extended LE advertising on a third-party
// controller. It only patches a process in memory, and does nothing without its boot
// flag. See docs/HOW-IT-WORKS.md. Nothing on disk changes.
#include <Headers/kern_api.hpp>
#include <Headers/kern_user.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/plugin_start.hpp>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/usb/IOUSBHostDevice.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <mach/mach_time.h>
#include <sys/vnode.h>
#include "BTLEAdvPatches.hpp"
#include "BTLEAdvHci.hpp"
#include "BTLEAdvVerify.hpp"

// Patches bluetoothd's pages as they're validated, the same way BlueToolFixup does.
// Lilu's onProcLoad route was tried first and didn't apply to this process.
static mach_vm_address_t orig_cs_validate {};
// bluetoothd pages validated again while still patched, given their original bytes for the check (#62).
static uint32_t revalidations {};
static bool patchScanning {};
// Experimental, off by default: -btleadvnodupfilter turns bluetoothd's scan duplicate filter off.
static bool patchDuplicateFilter {};

// The original bytes of every bluetoothd page a kext patched, for APFS's integrity check (BTLEAdvVerify.hpp, #62).
// This hook sees BlueToolFixup's patches too when it runs outside BlueToolFixup's, that is when BTLEAdvFixup loads
// after BlueToolFixup. pagesLock, a mutex, guards patchedPages, pageScratch and the bluetoothd vnode; it's held
// across the validation of one bluetoothd page, never across an allocation, a registry write or the check itself.
static BTLEAdv::PatchedPages *patchedPages {};
static uint8_t *pageScratch {};
static IOLock *pagesLock {};
static vnode_t bluetoothdVnode {};
static uint32_t bluetoothdVid {};
static thread_call_t publishCall {};

static void patched_cs_validate_page(vnode_t vp, memory_object_t pager, memory_object_offset_t page_offset,
                                     const void *data, int *validated_p, int *tainted_p, int *nx_p) {
    char path[PATH_MAX];
    int pathlen = PATH_MAX;
    if (vn_getpath(vp, path, &pathlen) != 0 || LIKELY(strcmp(path, "/usr/sbin/bluetoothd") != 0)) {
        FunctionCast(patched_cs_validate_page, orig_cs_validate)(vp, pager, page_offset, data, validated_p, tainted_p, nx_p);
        return;
    }
    // The page as it came from disk, before any hook in the chain changes it.
    const bool keep = data && patchedPages && pageScratch && pagesLock;
    // A page validated again while it still holds its patches (#62, "Code Signature Invalid"): it gets its original
    // bytes back for the check, and its patches again after it.
    const BTLEAdv::PatchedPage *again = nullptr;
    if (keep) {
        IOLockLock(pagesLock);
        if (bluetoothdVnode == vp && bluetoothdVid == vnode_vid(vp))
            again = BTLEAdv::patchedPageAt(*patchedPages, page_offset, static_cast<const uint8_t *>(data));
        if (again) {
            memcpy(const_cast<void *>(data), again->original, PAGE_SIZE);
            __atomic_add_fetch(&revalidations, 1, __ATOMIC_RELAXED);
        }
        memcpy(pageScratch, data, PAGE_SIZE);
    }
    FunctionCast(patched_cs_validate_page, orig_cs_validate)(vp, pager, page_offset, data, validated_p, tainted_p, nx_p);
    // Each set only matches its own bluetoothd build; on any other build nothing changes.
    for (const auto &patch : BTLEAdv::kPatches)
        if ((!patch.scanningOnly || patchScanning) && (!patch.dupFilter || patchDuplicateFilter))
            KernelPatcher::findAndReplace(const_cast<void *>(data), PAGE_SIZE, patch.find, patch.size,
                                          patch.replace, patch.size);
    if (!keep)
        return;
    // Every recorded patch back, BlueToolFixup's included when its hook isn't in this chain. Only after a validation
    // that passed: a page that failed keeps the bytes it was checked with.
    if (again && validated_p && *validated_p && !(tainted_p && *tainted_p))
        memcpy(const_cast<void *>(data), again->patched, PAGE_SIZE);
    // A new vnode for the file has its own pages: the old records don't apply to it.
    const uint32_t vid = vnode_vid(vp);
    if (bluetoothdVnode != vp || bluetoothdVid != vid) {
        patchedPages->count = 0;
        bluetoothdVnode = vp;
        bluetoothdVid = vid;
    }
    const bool added = BTLEAdv::recordPatchedPage(*patchedPages, page_offset, pageScratch, static_cast<const uint8_t *>(data));
    IOLockUnlock(pagesLock);
    if (added && publishCall)
        thread_call_enter(publishCall);
}

// bluetoothd talks to the controller over USB control requests. Commands it doesn't send in
// the required order are added here, after the command they depend on. Their completion
// events reach bluetoothd as unmatched, as they already do for IntelBTPatcher's command.
static mach_vm_address_t orig_device_request {};
// deviceRequest runs on many threads at once. hciState is only read or changed with hciLock held,
// never across a USB call, and belongs to the one controller in hciOwner.
static BTLEAdv::State hciState {};
static IOLock *hciLock {};
static void *hciOwner {};
// An added command never waits longer than this, even when the caller's request had no timeout.
static constexpr uint32_t kExtraTimeoutMS = 1000;

// The LE Data Length Change fix (OpenIntelWireless#514) needs the controller's interrupt IN pipe,
// which is only reachable through IOUSBHostPipe: the pipe is remembered when it's created.
static mach_vm_address_t orig_pipe_io {};
static mach_vm_address_t orig_init_pipe {};
static mach_vm_address_t orig_init_pipe_config {};
static void *interruptPipe {};
// Written when a command goes out (any thread) and read when an interrupt read is submitted or completes
// (the USB workloop). lengthLock is a spinlock held only around the table itself: never across a USB
// call, an allocation or a registry write. Taken after hciLock when both are needed, never before.
// Entries are per connection handle and expire after 2 s (audit BT03; this also bounds BT02's window).
static BTLEAdv::DataLengthState lengthState {};
static IOSimpleLock *lengthLock {};
static uint32_t lengthRewrites {}, lengthFailures {}, lengthExpiredSeen {}, lengthAbortsSeen {};
static uint32_t bumpCounter(uint32_t &counter) { return __atomic_add_fetch(&counter, 1, __ATOMIC_RELAXED); }
static uint64_t nowNanoseconds() {
    uint64_t now = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &now);
    return now;
}
// Asynchronous originals the added commands were sent beside (audit P-R06), so testers' reports show
// whether that case happens before anything is changed for it.
static uint32_t asyncSeen {};
// Interrupt IN pipes of the Intel controller seen being created.
static uint32_t eventPipes {};

static IOReturn patched_device_request(void *that, IOService *provider, StandardUSB::DeviceRequest &request, void *data,
                                       IOMemoryDescriptor *descriptor, unsigned int &length,
                                       IOUSBHostCompletion *completion, uint32_t timeout);

// Evidence for tests, in the I/O Registry root. Set only on rare events, in thread context.
static uint32_t extraCommands {}, setAddresses {}, extraFailures {}, enableAddresses {};
static BTLEAdv::PrivacyStats privacyStats {};   // under hciLock
static bool privacyChanged {};
static void noteHook(const char *key, uint32_t value) {
    IORegistryEntry::getRegistryRoot()->setProperty(key, value, 32);
}

// APFS's check of file data read from disk (#62). For bluetoothd's file, when the block being checked holds a
// page as the patches left it, the check gets a copy with that page's original bytes; the pages themselves keep
// their patches. Every other file, and every other kind of call, goes straight through.
// decmpfs calls the filesystem's function through the vnode's operation table (the kernel inlines VNOP_VERIFY
// there), so the hook is on APFS's apfs_vnop_verify, which takes the arguments as one struct.
struct VerifyArgs {
    void *desc;
    vnode_t vp;
    off_t foffset;
    uint8_t *buf;
    size_t bufsize;
    size_t *verifyBlockSize;
    void **verifyContext;
    int flags;
    vfs_context_t context;
#if !defined(BTLEADV_SEQUOIA) && !defined(BTLEADV_SONOMA)
    void *verifyKind;   // from macOS 26
#endif
};
static mach_vm_address_t orig_apfs_verify {};
static uint32_t verifyRescues {}, verifyRescueFailures {};

static int patched_apfs_verify(VerifyArgs *args) {
    // Only checks of file data: no flags, or the filesystem's own context (VNODE_VERIFY_WITH_CONTEXT).
    if (LIKELY(!args || args->vp != bluetoothdVnode) || !args->buf || !args->bufsize || args->foffset < 0 ||
        (args->flags & ~2) || !pagesLock)
        return FunctionCast(patched_apfs_verify, orig_apfs_verify)(args);
    IOLockLock(pagesLock);
    const bool needed = args->vp == bluetoothdVnode && vnode_vid(args->vp) == bluetoothdVid &&
                        BTLEAdv::holdsPatchedBytes(*patchedPages, uint64_t(args->foffset), args->buf, args->bufsize);
    IOLockUnlock(pagesLock);
    if (!needed)
        return FunctionCast(patched_apfs_verify, orig_apfs_verify)(args);
    uint8_t *copy = static_cast<uint8_t *>(IOMalloc(args->bufsize));
    int error;
    if (copy) {
        memcpy(copy, args->buf, args->bufsize);
        IOLockLock(pagesLock);
        BTLEAdv::restoreOriginalBytes(*patchedPages, uint64_t(args->foffset), copy, args->bufsize);
        IOLockUnlock(pagesLock);
        VerifyArgs copied = *args;
        copied.buf = copy;
        error = FunctionCast(patched_apfs_verify, orig_apfs_verify)(&copied);
        IOFree(copy, args->bufsize);
    } else {
        error = FunctionCast(patched_apfs_verify, orig_apfs_verify)(args);
    }
    bumpCounter(copy && !error ? verifyRescues : verifyRescueFailures);
    if (publishCall)
        thread_call_enter(publishCall);
    return error;
}

// Registry keys for the above, written from a thread call: the hooks run where a registry write isn't safe.
static void publishVerify(thread_call_param_t, thread_call_param_t) {
    uint32_t count = 0, full = 0;
    IOLockLock(pagesLock);
    count = uint32_t(patchedPages->count);
    full = patchedPages->full;
    IOLockUnlock(pagesLock);
    noteHook("BTLEAdvPatchedPages", count);
    noteHook("BTLEAdvPatchedPagesFull", full);
    noteHook("BTLEAdvVerifyRescues", __atomic_load_n(&verifyRescues, __ATOMIC_RELAXED));
    noteHook("BTLEAdvVerifyRevalidations", __atomic_load_n(&revalidations, __ATOMIC_RELAXED));
    noteHook("BTLEAdvVerifyRescueFailures", __atomic_load_n(&verifyRescueFailures, __ATOMIC_RELAXED));
}

// Intel's vendor ID is also on hubs and other devices. Without the controller's product name, it
// must at least be a wireless controller (USB class 0xE0).
static bool isIntelBluetooth(void *that) {
    auto *device = static_cast<IORegistryEntry *>(that);
    auto *vendor = OSDynamicCast(OSNumber, device->getProperty("idVendor"));
    if (!vendor || vendor->unsigned32BitValue() != 0x8087)
        return false;
    if (auto *name = OSDynamicCast(OSString, device->getProperty("USB Product Name")))
        return name->isEqualTo("Bluetooth USB Host Controller");
    auto *deviceClass = OSDynamicCast(OSNumber, device->getProperty("bDeviceClass"));
    return deviceClass && deviceClass->unsigned32BitValue() == 0xE0;
}

static IOReturn sendExtra(void *that, IOService *provider, const StandardUSB::DeviceRequest &request,
                          const uint8_t *bytes, size_t size, uint32_t timeout) {
    auto *extra = IOBufferMemoryDescriptor::withBytes(bytes, size, kIODirectionOut);
    if (!extra)
        return kIOReturnNoMemory;
    StandardUSB::DeviceRequest extraRequest = request;
    extraRequest.wLength = uint16_t(size);
    unsigned int extraLength = uint32_t(size);
    // Synchronous (no completion), so bounded: a stalled controller can't hold the thread forever.
    const uint32_t extraTimeout = timeout == 0 || timeout > kExtraTimeoutMS ? kExtraTimeoutMS : timeout;
    IOReturn result = extra->prepare(kIODirectionOut);
    if (result == kIOReturnSuccess) {
        result = FunctionCast(patched_device_request, orig_device_request)(that, provider, extraRequest, nullptr, extra,
                                                                           extraLength, nullptr, extraTimeout);
        extra->complete(kIODirectionOut);
    }
    extra->release();
    return result;
}

static IOReturn patched_device_request(void *that, IOService *provider, StandardUSB::DeviceRequest &request, void *data,
                                       IOMemoryDescriptor *descriptor, unsigned int &length,
                                       IOUSBHostCompletion *completion, uint32_t timeout) {
    uint8_t hci[32] = {};
    size_t hciLength = 0;
    // Every USB device comes through here, so only look at the Intel Bluetooth controller.
    // Class requests to the device carry HCI commands; bRequest isn't reliable for this.
    // HCI commands are class requests, host to device, addressed to the device (or its interface).
    if (hciLock && (request.bmRequestType == 0x20 || request.bmRequestType == 0x21) && isIntelBluetooth(that)) {
        if (data) {
            hciLength = min(size_t(request.wLength), sizeof(hci));
            lilu_os_memcpy(hci, data, hciLength);
        } else if (descriptor && descriptor->prepare(kIODirectionOut) == kIOReturnSuccess) {
            hciLength = min(size_t(descriptor->getLength()), sizeof(hci));
            descriptor->readBytes(0, hci, hciLength);
            descriptor->complete(kIODirectionOut);
        }
    }
    bool legacyScanAddress = false;
    unsigned remoteReads = 0;
    BTLEAdv::Action action {};
    if (hciLength) {
        IOLockLock(hciLock);
        // A different controller than last time starts from nothing.
        if (hciOwner != that) {
            hciState = BTLEAdv::State{};
            hciOwner = that;
            // A different controller object (re-enumerated, or a second one): any pending duplicates
            // belonged to the old one (audit BT02). The pipe is kept: it's created before the controller's
            // first command, so forgetting it here left the data-length fix off for good (#71). A new
            // controller's pipe replaces it when that pipe is created.
            if (lengthLock) {
                IOSimpleLockLock(lengthLock);
                const uint32_t expired = lengthState.expired, aborts = lengthState.aborts;
                lengthState = BTLEAdv::DataLengthState{};
                lengthState.expired = expired;
                lengthState.aborts = aborts;
                IOSimpleLockUnlock(lengthLock);
            }
        }
        legacyScanAddress = BTLEAdv::wantsLegacyScanAddress(hciState, hci, hciLength);
        BTLEAdv::notePrivacy(privacyStats, hci, hciLength);
        privacyChanged = true;
        action = BTLEAdv::onCommand(hciState, hci, hciLength, patchScanning);
        IOLockUnlock(hciLock);
        if (lengthLock) {
            const uint64_t now = nowNanoseconds();
            IOSimpleLockLock(lengthLock);
            remoteReads = BTLEAdv::extraRemoteReads(lengthState, hci, hciLength, now);
            IOSimpleLockUnlock(lengthLock);
        }
    }
    if (completion && (remoteReads || legacyScanAddress || action.sendSetAddress || action.sendEventMask ||
                       action.beforeCount))
        noteHook("BTLEAdvAsyncSeen", bumpCounter(asyncSeen));
    for (unsigned i = 0; i < remoteReads; ++i) {
        // Sent before the real command, as IntelBTPatcher does: the three completions carry the
        // same features, so the first one reaches bluetoothd unchanged and the other two are
        // rewritten into the events it's missing.
        if (sendExtra(that, provider, request, hci, hciLength, timeout) != kIOReturnSuccess) {
            IOSimpleLockLock(lengthLock);
            BTLEAdv::forgetRemoteRead(lengthState, hci, hciLength);
            IOSimpleLockUnlock(lengthLock);
            noteHook("BTLEAdvLengthFailures", bumpCounter(lengthFailures));
        }
    }
    if (legacyScanAddress) {
        // IntelBTPatcher's workaround, sent before the scan command like the original.
        uint8_t fixed[9] = {0x05, 0x20, 0x06};
        lilu_os_memcpy(fixed + 3, BTLEAdv::kFixedPatcherAddress, 6);
        sendExtra(that, provider, request, fixed, sizeof(fixed), timeout);
    }
    // A set's address again right before its first enable (#102), in order with the enable: sent from this thread
    // before the enable itself. One that doesn't go out is put back, so the next enable tries again.
    for (unsigned i = 0; i < action.beforeCount; ++i) {
        const IOReturn sent = sendExtra(that, provider, request, action.before[i], sizeof(action.before[i]), timeout);
        if (sent == kIOReturnSuccess) {
            noteHook("BTLEAdvExtraCommands", ++extraCommands);
            noteHook("BTLEAdvEnableAddresses", ++enableAddresses);
        } else {
            IOLockLock(hciLock);
            if (hciOwner == that)
                hciState.checkAtEnable |= 1U << action.beforeHandle[i];
            IOLockUnlock(hciLock);
            noteHook("BTLEAdvExtraFailures", ++extraFailures);
        }
    }
    static bool sawCommand {};
    if (hciLength >= 3 && !sawCommand) {
        sawCommand = true;
        noteHook("BTLEAdvFirstRequest", request.bRequest);
    }
    const IOReturn result = FunctionCast(patched_device_request, orig_device_request)(that, provider, request, data, descriptor, length, completion, timeout);
    if (hciLength >= 3 && privacyChanged) {
        const uint16_t op = uint16_t(hci[0] | hci[1] << 8);
        if (op == BTLEAdv::kOpLeAddResolving || op == BTLEAdv::kOpLeAddressResolution ||
            op == BTLEAdv::kOpLeCreateConnection || op == BTLEAdv::kOpLeExtCreateConnection) {
            IOLockLock(hciLock);
            const BTLEAdv::PrivacyStats p = privacyStats;
            privacyChanged = false;
            IOLockUnlock(hciLock);
            noteHook("BTLEAdvResolvingAdds", p.resolvingAdds);
            noteHook("BTLEAdvResolutionOn", p.resolutionOn);
            noteHook("BTLEAdvResolutionOff", p.resolutionOff);
            noteHook("BTLEAdvResolutionEnabled", p.resolutionEnabled ? 1 : 0);
            noteHook("BTLEAdvConnectsPublic", p.connects[0]);
            noteHook("BTLEAdvConnectsRandom", p.connects[1]);
            noteHook("BTLEAdvConnectsIdentity", p.connects[2] + p.connects[3]);
            noteHook("BTLEAdvConnectsNoResolution", p.connectsWithoutResolution);
        }
    }
    if (action.sendSetAddress || action.sendEventMask) {
        // Only after the command it depends on was accepted. A set address that didn't go out is
        // forgotten, so the next parameters command for that set tries again.
        const IOReturn extra = result == kIOReturnSuccess ?
            sendExtra(that, provider, request, action.output, action.outputLength, timeout) : result;
        if (action.sendSetAddress && extra != kIOReturnSuccess) {
            IOLockLock(hciLock);
            if (hciOwner == that)
                hciState.addressedSets &= ~(1U << action.output[3]);
            IOLockUnlock(hciLock);
        }
        if (extra == kIOReturnSuccess) {
            noteHook("BTLEAdvExtraCommands", ++extraCommands);
            if (action.sendSetAddress)
                noteHook("BTLEAdvSetAddresses", ++setAddresses);
        } else {
            noteHook("BTLEAdvExtraFailures", ++extraFailures);
        }
    }
    return result;
}

// The controller's events arrive on its interrupt IN pipe, and only the pipe object can be used
// to wrap them, so it's remembered when it's created. Anything else on the bus is left alone.
static void captureInterruptPipe(void *that, StandardUSB::EndpointDescriptor const *descriptor, IOUSBHostDevice *device) {
    if (!descriptor || !device || !isIntelBluetooth(device))
        return;
    // The endpoint is picked apart by hand: StandardUSB::getEndpointType/getEndpointDirection are
    // exports of IOUSBHostFamily, and OpenCore's prelinker resolves them to 0 (RIP-relative
    // overflow), which makes injection fail. The descriptor is the 7-byte USB layout:
    // bEndpointAddress (offset 2, bit 7 = direction in), bmAttributes (offset 3, bits 0-1 = type).
    auto *bytes = reinterpret_cast<const uint8_t *>(descriptor);
    if (bytes[2] & 0x80 && (bytes[3] & 0x03) == 0x03) {
        interruptPipe = that;
        // Shows in reports that the fix has a pipe to work with (#71).
        noteHook("BTLEAdvEventPipes", bumpCounter(eventPipes));
    }
}

// The pipe is created through one of two overloads, depending on the macOS version.
static int patched_init_pipe(void *that, StandardUSB::EndpointDescriptor const *descriptor,
                             StandardUSB::SuperSpeedEndpointCompanionDescriptor const *companion, void *controller,
                             IOUSBHostDevice *device, void *interface, unsigned char a7, unsigned short a8) {
    const int result = FunctionCast(patched_init_pipe, orig_init_pipe)(that, descriptor, companion, controller, device,
                                                                       interface, a7, a8);
    captureInterruptPipe(that, descriptor, device);
    return result;
}

static int patched_init_pipe_config(void *that, StandardUSB::EndpointDescriptor const *descriptor,
                                    StandardUSB::ConfigurationDescriptor const *config, void *controller,
                                    IOUSBHostDevice *device, void *interface, unsigned char a7, unsigned short a8) {
    const int result = FunctionCast(patched_init_pipe_config, orig_init_pipe_config)(that, descriptor, config, controller,
                                                                                     device, interface, a7, a8);
    captureInterruptPipe(that, descriptor, device);
    return result;
}

// A completion owns the caller's closure, so the original one is kept here while ours runs.
struct DelayedCompletion {
    IOUSBHostCompletion original;
    IOMemoryDescriptor *buffer;
    IOUSBHostCompletion wrapped;    // what the USB stack is given (audit BT01)
};

// Publishes a counter that changed, outside the spinlock (a registry write allocates).
static void noteChanged(const char *key, uint32_t value, uint32_t &seen) {
    if (value != __atomic_load_n(&seen, __ATOMIC_RELAXED)) {
        __atomic_store_n(&seen, value, __ATOMIC_RELAXED);
        noteHook(key, value);
    }
}

static void rewriteCompletion(void *owner, void *parameter, IOReturn status, uint32_t bytesTransferred) {
    auto *delayed = static_cast<DelayedCompletion *>(owner);
    IOMemoryDescriptor *buffer = delayed->buffer;
    // readBytes() and writeBytes() need the descriptor wired, and only a hold this call took is known to
    // be there: touching a buffer this call couldn't prepare panics with "IOGMD: not wired for the
    // IODMACommand" (PR #61). Before, a refused prepare() was assumed to mean "already prepared on
    // Tahoe", which was never tested; PR #61's Tahoe test shows prepare() succeeds. A hold taken here is
    // also the only one released here.
    const bool held = status == kIOReturnSuccess && buffer &&
        buffer->getLength() >= BTLEAdv::kDataLengthEventLength &&
        buffer->prepare(kIODirectionInOut) == kIOReturnSuccess;
    bool abort = !held;
    if (held) {
        // Events shorter than 6 bytes can't be the one rewritten; they pass through untouched.
        if (bytesTransferred >= 6) {
            uint8_t event[32] = {};
            const size_t size = min(size_t(bytesTransferred), sizeof(event));
            buffer->readBytes(0, event, size);
            IOSimpleLockLock(lengthLock);
            const size_t rewritten = BTLEAdv::rewriteEvent(lengthState, event, size);
            IOSimpleLockUnlock(lengthLock);
            // writeBytes returns the number of bytes written, not an IOReturn. The shrunk size may only
            // be claimed when every rewritten byte is really in the buffer: forwarding the original
            // size leaves stale feature bytes behind, which the stack parses as garbage events and
            // bluetoothd takes the parser desync as fatal (reason 607).
            if (rewritten != size) {
                if (buffer->writeBytes(0, event, rewritten) == rewritten) {
                    bytesTransferred = uint32_t(rewritten);
                    noteHook("BTLEAdvLengthRewrites", bumpCounter(lengthRewrites));
                } else {
                    noteHook("BTLEAdvLengthFailures", bumpCounter(lengthFailures));
                    abort = true;   // a duplicate that can't be rewritten can't be waited for either
                }
            }
        }
        buffer->complete(kIODirectionInOut);
    }
    if (abort) {
        // Nothing could be rewritten into this read (failed transfer, no hold of our own, short write):
        // drop the pending round so no further read is wrapped for it (PR #61).
        IOSimpleLockLock(lengthLock);
        BTLEAdv::abortLinks(lengthState);
        const uint32_t aborts = lengthState.aborts;
        IOSimpleLockUnlock(lengthLock);
        noteChanged("BTLEAdvLengthAborts", aborts, lengthAbortsSeen);
    }
    const IOUSBHostCompletion original = delayed->original;
    IOFree(delayed, sizeof(*delayed));
    if (original.action)
        original.action(original.owner, parameter, status, bytesTransferred);
}

static IOReturn patched_pipe_io(void *that, IOMemoryDescriptor *dataBuffer, uint32_t bytesTransferred,
                                IOUSBHostCompletion *completion, uint32_t completionTimeoutMs) {
    bool wrap = false;
    if (completion && dataBuffer && lengthLock && that == interruptPipe) {
        const uint64_t now = nowNanoseconds();
        const size_t bufferLength = dataBuffer->getLength();
        IOSimpleLockLock(lengthLock);
        // Only while a link waits, for a buffer that can hold the rewritten event, and at most
        // kMaxWrappedReads per round (PR #61). Entries expire after 2 s (audit BT03).
        wrap = BTLEAdv::wrapRead(lengthState, now, bufferLength);
        const uint32_t expired = lengthState.expired, aborts = lengthState.aborts;
        IOSimpleLockUnlock(lengthLock);
        // Their own counters: BTLEAdvLengthFailures counts copies that couldn't be sent or written back.
        noteChanged("BTLEAdvLengthExpired", expired, lengthExpiredSeen);
        noteChanged("BTLEAdvLengthAborts", aborts, lengthAbortsSeen);
    }
    if (wrap) {
        auto *delayed = static_cast<DelayedCompletion *>(IOMalloc(sizeof(DelayedCompletion)));
        if (delayed) {
            // The caller's completion is never modified: ours is a copy held in the same allocation, so
            // a caller that reuses its structure can't send a read pointing at a freed wrapper, and a
            // failed submit leaves the caller's structure as it was (audit BT01).
            delayed->original = *completion;
            delayed->buffer = dataBuffer;
            delayed->wrapped = *completion;
            delayed->wrapped.action = rewriteCompletion;
            delayed->wrapped.owner = delayed;
            const IOReturn result = FunctionCast(patched_pipe_io, orig_pipe_io)(that, dataBuffer, bytesTransferred,
                                                                                &delayed->wrapped, completionTimeoutMs);
            // A refused submit never calls the completion, so nothing else would free this. That is the
            // documented contract: IOUSBHostIOSource::io (which IOUSBHostPipe::io refers to) returns
            // "kIOReturnSuccess if the completion will be called in the future, otherwise error" (audit V-2).
            if (result != kIOReturnSuccess)
                IOFree(delayed, sizeof(*delayed));
            return result;
        }
    }
    return FunctionCast(patched_pipe_io, orig_pipe_io)(that, dataBuffer, bytesTransferred, completion, completionTimeoutMs);
}

static const char *usbHostPaths[] {"/System/Library/Extensions/IOUSBHostFamily.kext/Contents/MacOS/IOUSBHostFamily"};
static KernelPatcher::KextInfo usbHostInfo {"com.apple.iokit.IOUSBHostFamily", usbHostPaths, 1, {true}, {}, KernelPatcher::KextInfo::Unloaded};
static const char *apfsPaths[] {"/System/Library/Extensions/apfs.kext/Contents/MacOS/apfs"};
static KernelPatcher::KextInfo apfsInfo {"com.apple.filesystems.apfs", apfsPaths, 1, {true}, {}, KernelPatcher::KextInfo::Unloaded};

static const char *bootargOff[] = {"-btleadvoff"};
static const char *bootargDebug[] = {"-btleadvdbg"};
static const char *bootargBeta[] = {"-btleadvbeta"};

PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal | LiluAPI::AllowInstallerRecovery | LiluAPI::AllowSafeMode,
    bootargOff, arrsize(bootargOff),
    bootargDebug, arrsize(bootargDebug),
    bootargBeta, arrsize(bootargBeta),
    // Lilu disables a plugin outside this range. Each build declares only its own macOS version:
    // before 0.8.3 the Sequoia build declared Tahoe here too, so Lilu never started it on Sequoia.
#if defined(BTLEADV_SONOMA)
    KernelVersion::Sonoma,
    KernelVersion::Sonoma,
#elif defined(BTLEADV_SEQUOIA)
    KernelVersion::Sequoia,
    KernelVersion::Sequoia,
#else
    KernelVersion::Tahoe,
    KernelVersion::Tahoe,
#endif
    []() {
        // Off unless asked for, so this kext can sit in the EFI doing nothing.
        if (!checkKernelArgument("-btleadv"))
            return;
        // Advertising alone, to compare with both.
        patchScanning = !checkKernelArgument("-btlenoscan");
        patchDuplicateFilter = checkKernelArgument("-btleadvnodupfilter");
        // For the integrity check of bluetoothd's patched pages (#62). Without any of these it stays off and the
        // pages are patched as before.
        pagesLock = IOLockAlloc();
        patchedPages = static_cast<BTLEAdv::PatchedPages *>(IOMalloc(sizeof(BTLEAdv::PatchedPages)));
        pageScratch = static_cast<uint8_t *>(IOMalloc(PAGE_SIZE));
        if (patchedPages)
            memset(patchedPages, 0, sizeof(BTLEAdv::PatchedPages));
        if (pagesLock && patchedPages && pageScratch)
            publishCall = thread_call_allocate(publishVerify, nullptr);
        if (!pagesLock || !patchedPages || !pageScratch || !publishCall) {
            SYSLOG("btleadv", "no memory for the integrity check fix, it stays off");
            if (patchedPages)
                IOFree(patchedPages, sizeof(BTLEAdv::PatchedPages));
            if (pageScratch)
                IOFree(pageScratch, PAGE_SIZE);
            if (pagesLock)
                IOLockFree(pagesLock);
            patchedPages = nullptr;
            pageScratch = nullptr;
            pagesLock = nullptr;
        }
        lilu.onPatcherLoadForce([](void *, KernelPatcher &patcher) {
            KernelPatcher::RouteRequest route("_cs_validate_page", patched_cs_validate_page, orig_cs_validate);
            if (!patcher.routeMultipleLong(KernelPatcher::KernelID, &route, 1))
                SYSLOG("btleadv", "failed to route cs validation");
        });
        // Routed on its own: if it fails, bluetoothd is still patched, as before.
        if (pagesLock)
            lilu.onKextLoadForce(&apfsInfo, 1, [](void *, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
                if (index != apfsInfo.loadIndex)
                    return;
                KernelPatcher::RouteRequest route("_apfs_vnop_verify", patched_apfs_verify, orig_apfs_verify);
                const bool routed = patcher.routeMultipleLong(index, &route, 1, address, size);
                if (!routed) {
                    SYSLOG("btleadv", "failed to route the integrity check");
                    patcher.clearError();
                }
                noteHook("BTLEAdvVerifyHook", routed ? 1 : 0);
            });
        hciLock = IOLockAlloc();
        lengthLock = IOSimpleLockAlloc();
        if (!lengthLock)
            SYSLOG("btleadv", "no lock for the data length fix, it stays off");
        lilu.onKextLoadForce(&usbHostInfo, 1, [](void *, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
            if (index != usbHostInfo.loadIndex || !hciLock)
                return;
            KernelPatcher::RouteRequest route(
                "__ZN15IOUSBHostDevice13deviceRequestEP9IOServiceRN11StandardUSB13DeviceRequestEPvP18IOMemoryDescriptorRjP19IOUSBHostCompletionj",
                patched_device_request, orig_device_request);
            const bool routed = patcher.routeMultiple(index, &route, 1, address, size);
            if (!routed) {
                SYSLOG("btleadv", "failed to route device request");
                patcher.clearError();
            }
            noteHook("BTLEAdvHookRouted", routed ? 1 : 0);
            // The LE Data Length Change fix also needs the pipe object and its completions.
            KernelPatcher::RouteRequest ioRoute("__ZN13IOUSBHostPipe2ioEP18IOMemoryDescriptorjP19IOUSBHostCompletionj",
                                                patched_pipe_io, orig_pipe_io);
            const bool ioRouted = patcher.routeMultiple(index, &ioRoute, 1, address, size);
            if (!ioRouted) {
                SYSLOG("btleadv", "failed to route pipe io");
                patcher.clearError();
            }
            // 26.5 and later take the configuration descriptor where older builds take the
            // endpoint companion one. Only one of the two exists, so a miss is not an error.
            KernelPatcher::RouteRequest configRoute("__ZN13IOUSBHostPipe28initWithDescriptorsAndOwnersEPKN11StandardUSB18EndpointDescriptorEPKNS0_23ConfigurationDescriptorEP22AppleUSBHostControllerP15IOUSBHostDeviceP18IOUSBHostInterfaceht",
                                                    patched_init_pipe_config, orig_init_pipe_config);
            const bool configRouted = patcher.routeMultiple(index, &configRoute, 1, address, size);
            if (!configRouted)
                patcher.clearError();
            KernelPatcher::RouteRequest initRoute("__ZN13IOUSBHostPipe28initWithDescriptorsAndOwnersEPKN11StandardUSB18EndpointDescriptorEPKNS0_37SuperSpeedEndpointCompanionDescriptorEP22AppleUSBHostControllerP15IOUSBHostDeviceP18IOUSBHostInterfaceht",
                                                  patched_init_pipe, orig_init_pipe);
            const bool initRouted = patcher.routeMultiple(index, &initRoute, 1, address, size);
            if (!initRouted)
                patcher.clearError();
            if (!configRouted && !initRouted)
                SYSLOG("btleadv", "failed to route pipe creation");
            noteHook("BTLEAdvPipeHooks", (configRouted ? 1U : 0U) | (initRouted ? 2U : 0U) | (ioRouted ? 4U : 0U));
        });
    }
};

// Match Xcode's kext lifecycle. The kernel runs C++ initializers; libkmod
// forwards the start/stop callbacks through _realmain and _antimain.
extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
extern kern_return_t IntelBTPatcher_kern_start(kmod_info_t *, void *);
extern kern_return_t IntelBTPatcher_kern_stop(kmod_info_t *, void *);
__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(org.forbiddenitlwm.IntelBTPatcher, xStringify(MODULE_VERSION), _start, _stop)
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = IntelBTPatcher_kern_start;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain = IntelBTPatcher_kern_stop;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}
