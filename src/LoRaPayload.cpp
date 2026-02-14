#include "LoRaPayload.h"
#include "Crypto.h"

static std::vector<uint8_t> buildB0(
    uint32_t devAddr,
    uint32_t fCnt,
    uint8_t direction,
    size_t len)
{
    std::vector<uint8_t> b0(16, 0);

    b0[0] = 0x49;
    b0[5] = direction;

    b0[6] = devAddr & 0xFF;
    b0[7] = (devAddr >> 8) & 0xFF;
    b0[8] = (devAddr >> 16) & 0xFF;
    b0[9] = (devAddr >> 24) & 0xFF;

    b0[10] = fCnt & 0xFF;
    b0[11] = (fCnt >> 8) & 0xFF;
    b0[12] = (fCnt >> 16) & 0xFF;
    b0[13] = (fCnt >> 24) & 0xFF;

    b0[15] = static_cast<uint8_t>(len);

    return b0;
}

std::vector<uint8_t> LoRaPayload::buildUplink(
    uint32_t devAddr,
    uint32_t fCnt,
    const std::vector<uint8_t>& appSKey,
    const std::vector<uint8_t>& nwkSKey,
    const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> msg;

    // MHDR
    msg.push_back(0x40); // Unconfirmed uplink

    // FHDR
    msg.push_back(devAddr & 0xFF);
    msg.push_back((devAddr >> 8) & 0xFF);
    msg.push_back((devAddr >> 16) & 0xFF);
    msg.push_back((devAddr >> 24) & 0xFF);

    msg.push_back(0x00); // FCtrl

    msg.push_back(fCnt & 0xFF);
    msg.push_back((fCnt >> 8) & 0xFF);

    // FPort
    msg.push_back(1);

    // Encrypt payload
    auto enc = Crypto::encryptPayload(appSKey, devAddr, fCnt, data);
    msg.insert(msg.end(), enc.begin(), enc.end());

    // ---------- MIC ----------
    auto b0 = buildB0(devAddr, fCnt, 0 /*uplink*/, msg.size());

    std::vector<uint8_t> micInput;
    micInput.insert(micInput.end(), b0.begin(), b0.end());
    micInput.insert(micInput.end(), msg.begin(), msg.end());

    auto cmac = Crypto::aesCmac(nwkSKey, micInput);

    msg.insert(msg.end(), cmac.begin(), cmac.begin() + 4);

    return msg;
}
