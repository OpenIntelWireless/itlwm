//
//  FirmwareStoreService.h
//  itlwm
//
//  Created by zhongxianyao on 2020/9/2.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef FirmwareStoreService_h
#define FirmwareStoreService_h

#include <IOKit/IOService.h>

class FirmwareStoreService : public IOService {
    OSDeclareDefaultStructors(FirmwareStoreService)
    
public:
    virtual void free() override;
    
    virtual bool start(IOService *provider) override;
    
    virtual bool init(OSDictionary *dictionary = NULL) override;
    
    virtual void stop(IOService *provider) override;
};

#endif /* FirmwareStoreService_h */
