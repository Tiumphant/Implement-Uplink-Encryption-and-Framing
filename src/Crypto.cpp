#include "Crypto.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdexcept>

std::vector<uint8_t> Crypto::aesEncrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP ctx alloc failed");

    std::vector<uint8_t> out(16);
    int outlen = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
                            key.data(), nullptr))
        throw std::runtime_error("EncryptInit failed");

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (!EVP_EncryptUpdate(ctx, out.data(), &outlen,
                           data.data(), data.size()))
        throw std::runtime_error("EncryptUpdate failed");

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<uint8_t> Crypto::aesCmac(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data)
{
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_CIPHER,
            (char*)"AES-128-CBC", 0),
        OSSL_PARAM_END
    };

    if (!EVP_MAC_init(ctx, key.data(), key.size(), params))
        throw std::runtime_error("CMAC init failed");

    if (!EVP_MAC_update(ctx, data.data(), data.size()))
        throw std::runtime_error("CMAC update failed");

    std::vector<uint8_t> out(16);
    size_t outlen = 0;

    if (!EVP_MAC_final(ctx, out.data(), &outlen, out.size()))
        throw std::runtime_error("CMAC final failed");

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    out.resize(outlen);
    return out;
}

std::vector<uint8_t> Crypto::encryptPayload(
    const std::vector<uint8_t>& appSKey,
    uint32_t devAddr,
    uint32_t fCnt,
    const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> result(payload.size());

    for (size_t i = 0; i < payload.size(); i += 16) {
        std::vector<uint8_t> block(16, 0);

        block[0] = 0x01;
        block[5] = devAddr & 0xFF;
        block[6] = (devAddr >> 8) & 0xFF;
        block[7] = (devAddr >> 16) & 0xFF;
        block[8] = (devAddr >> 24) & 0xFF;

        block[10] = fCnt & 0xFF;
        block[11] = (fCnt >> 8) & 0xFF;

        block[15] = (i / 16) + 1;

        auto s = aesEncrypt(appSKey, block);

        for (size_t j = 0; j < 16 && i + j < payload.size(); j++) {
            result[i + j] = payload[i + j] ^ s[j];
        }
    }

    return result;
}
