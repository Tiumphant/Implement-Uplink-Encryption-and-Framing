#include <gtest/gtest.h>
#include "Crypto.h"
#include "FrameCounter.h"
#include "LoRaPayload.h"

TEST(FrameCounterTest, Increment) {
    FrameCounter fc;
    EXPECT_EQ(fc.next(), 1);
    EXPECT_EQ(fc.next(), 2);
}

TEST(CryptoTest, EncryptNotEmpty) {
    std::vector<uint8_t> key(16, 0x01);
    std::vector<uint8_t> data = {1,2,3,4};

    auto enc = Crypto::encryptPayload(key, 0x01020304, 1, data);
    EXPECT_EQ(enc.size(), data.size());
    EXPECT_NE(enc[0], data[0]);
}

TEST(PayloadTest, BuildPayload) {
    std::vector<uint8_t> key(16, 0x01);
    std::vector<uint8_t> data = {10,20,30};

    auto p = LoRaPayload::buildUplink(
        0x01020304, 1, key, key, data);

    EXPECT_GT(p.size(), data.size());
}
