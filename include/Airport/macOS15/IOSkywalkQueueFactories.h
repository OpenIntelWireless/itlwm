// Sequoia 15.8 (24H23, 24H241) native factories: the same exported constructors as Tahoe, and the
// same queue vtables (checked against the KDK). Queues are used through their IOEventSource base.
#pragma once
#include <IOKit/IOEventSource.h>
#include <Airport/IOSkywalkPacketBufferPool.h>
class IOSkywalkPacket;
class IOSkywalkTxSubmissionQueue;
class IOSkywalkTxCompletionQueue;
class IOSkywalkRxSubmissionQueue;
class IOSkywalkRxCompletionQueue;
using ItlTxSubmitAction = UInt32 (*)(OSObject*, IOSkywalkTxSubmissionQueue*, IOSkywalkPacket *const*, UInt32, void*);
using ItlRxSupplyAction = UInt32 (*)(OSObject*, IOSkywalkRxSubmissionQueue*, IOSkywalkPacket *const*, UInt32, void*);
using ItlTxCompleteAction = UInt32 (*)(OSObject*, IOSkywalkTxCompletionQueue*, IOSkywalkPacket**, UInt32, void*);
using ItlRxCompleteAction = UInt32 (*)(OSObject*, IOSkywalkRxCompletionQueue*, IOSkywalkPacket**, UInt32, void*);
extern "C" IOEventSource *itlMakeTxSubmission(IOSkywalkPacketBufferPool*, UInt32, UInt32, OSObject*, ItlTxSubmitAction, void*, UInt32)
    __asm__("__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PKP15IOSkywalkPacketjPvES9_j");
extern "C" IOEventSource *itlMakeTxCompletion(IOSkywalkPacketBufferPool*, UInt32, UInt32, OSObject*, ItlTxCompleteAction, void*, UInt32)
    __asm__("__ZN26IOSkywalkTxCompletionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PP15IOSkywalkPacketjPvES8_j");
extern "C" IOEventSource *itlMakeRxSubmission(IOSkywalkPacketBufferPool*, UInt32, UInt32, UInt32, OSObject*, ItlRxSupplyAction, void*, UInt32)
    __asm__("__ZN26IOSkywalkRxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjjP8OSObjectPFjS3_PS_PKP15IOSkywalkPacketjPvES9_j");
extern "C" IOEventSource *itlMakeRxCompletion(IOSkywalkPacketBufferPool*, UInt32, UInt32, OSObject*, ItlRxCompleteAction, void*, UInt32)
    __asm__("__ZN26IOSkywalkRxCompletionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PP15IOSkywalkPacketjPvES8_j");
static_assert(sizeof(IOSkywalkPacketBufferPool::PoolOptions)==0x20, "Native pool option ABI");
