#pragma once
#include <vector>
#include <cstdint>

class Crypto {
public:
    static std::vector<uint8_t> aesEncrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data);

    static std::vector<uint8_t> aesCmac(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data);

    static std::vector<uint8_t> encryptPayload(
        const std::vector<uint8_t>& appSKey,
        uint32_t devAddr,
        uint32_t fCnt,
        const std::vector<uint8_t>& payload);
};
