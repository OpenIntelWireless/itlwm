#include <IOKit/IOWorkLoop.h>

class IO80211WorkLoop : public IOWorkLoop
{
    OSDeclareDefaultStructors( IO80211WorkLoop )
    
public:
    
    static IO80211WorkLoop * workLoop();
    
    virtual void openGate() override;
    virtual void closeGate() override;
    virtual int sleepGate( void * event, UInt32 interuptibleType ) override;
    virtual int sleepGateDeadline( void * event, UInt32 interuptibleType, AbsoluteTime deadline );
    virtual void wakeupGate( void * event, bool oneThread ) override;

};

