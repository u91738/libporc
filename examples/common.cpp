#include <cassert>
#include <cstdio>
#include <memory>
#include <openssl/evp.h>
#include "common.hpp"

void hexdump(const std::string &header, const std::vector<uint8_t> &v)
{
    printf("%s", header.c_str());
    for(auto i : v)
        printf("%02X", i);
    printf("\n");
}

void hexdump(const std::string &header, const std::deque<uint8_t> &v)
{
    printf("%s", header.c_str());
    for(auto i : v)
        printf("%02X", i);
    printf("\n");
}

std::vector<uint8_t> cbc_aes256_encrypt(
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &data)
{
    assert(iv.size() == 16 && key.size() == 32);
    auto *ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    assert(ret == 1);

    int enc_len;
    std::vector<uint8_t> ciphertext;
    ciphertext.resize((data.size() / 16 + 1) * 16);
    ret = EVP_EncryptUpdate(ctx, ciphertext.data(), &enc_len, data.data(), data.size());
    assert(ret == 1);

    int fin_enc_len;
    ret = EVP_EncryptFinal_ex(ctx, ciphertext.data() + enc_len, &fin_enc_len);
    assert(ret == 1);
    assert((int)ciphertext.size() == enc_len + fin_enc_len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::optional<std::vector<uint8_t>> cbc_aes256_decrypt(
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &data)
{
    assert(iv.size() == 16 && key.size() == 32);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    assert(ctx);

    int ret = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    assert(ret == 1);

    int dec_len;
    std::vector<uint8_t> plain;
    plain.resize(data.size());
    ret = EVP_DecryptUpdate(ctx.get(), plain.data(), &dec_len, data.data(), data.size());
    if (ret != 1)
        return std::nullopt;

    int fin_dec_len;
    ret = EVP_DecryptFinal_ex(ctx.get(), plain.data() + dec_len, &fin_dec_len);
    if (ret != 1)
        return std::nullopt;
    plain.resize(dec_len + fin_dec_len);

    return make_optional(plain);
}
