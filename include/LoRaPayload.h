#pragma once
#include <vector>
#include <cstdint>

class LoRaPayload {
public:
    static std::vector<uint8_t> buildUplink(
        uint32_t devAddr,
        uint32_t fCnt,
        const std::vector<uint8_t>& appSKey,
        const std::vector<uint8_t>& nwkSKey,
        const std::vector<uint8_t>& data);
};
