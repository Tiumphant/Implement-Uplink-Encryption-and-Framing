#include "FrameCounter.h"

uint32_t FrameCounter::next() {
    return ++counter;
}

uint32_t FrameCounter::current() const {
    return counter;
}
