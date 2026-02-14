#pragma once
#include <cstdint>

class FrameCounter {
    uint32_t counter = 0;
public:
    uint32_t next();
    uint32_t current() const;
};
