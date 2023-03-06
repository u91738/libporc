#include <cassert>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <openssl/evp.h>
#include <unistd.h>

#include "porc.hpp"

/*
    Basic encryption-decryption
*/

static std::vector<uint8_t> iv = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static std::vector<uint8_t> key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static std::vector<uint8_t> data = { 11, 12, 13, 14, 15, 16, 17, 18, 19, 110, 111, 112, 113, 114, 115, 116,
                                      21, 22, 23, 24, 25, 26, 27, 28, 29, 210, 211, 212, 213, 214 };

static std::vector<uint8_t> data2 = { 21, 22, 23, 24, 25, 26, 27, 28, 29, 210, 211, 212, 213, 214 };

static std::vector<uint8_t> cbc_aes256_encrypt(
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

static  std::optional<std::vector<uint8_t>> cbc_aes256_decrypt(
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

#ifdef USLEEP_CHEAT
    usleep(100);
#endif
    return  make_optional(plain);
}

/*
    Direct padding oracle
*/

class example : public porc::porc_pkcs7 {
    public:
        bool is_well_padded(
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &data) override
        {
            return cbc_aes256_decrypt(iv, key, data).has_value();
        }
};

/*
    Timing based padding oracle
*/

class timed_example : public porc::timed::decryptor {
    private:
        std::vector<uint8_t> data;
    public:
        timed_example(const std::vector<uint8_t> &d) : data(d) { }

        int64_t measure() override
        {
            auto start = std::chrono::high_resolution_clock::now();
            cbc_aes256_decrypt(iv, key, this->data);
            auto end = std::chrono::high_resolution_clock::now();
            return std::chrono::nanoseconds(end - start).count();
        }
};

static void dump_vector(const std::vector<uint8_t> &v)
{
    for(auto i : v)
        printf("%02X", i);
    printf("\n");
}

int main(void)
{
    // run basic encryption-decryption
    auto ciphertext = cbc_aes256_encrypt(iv, key, data);
    printf("ciphertext:     ");
    dump_vector(ciphertext);

    auto dec = cbc_aes256_decrypt(iv, key, ciphertext);
    assert(dec);
    printf("decrypted:      ");
    dump_vector(dec.value());

    // direct attack
    example conf;
    auto porc_dec = porc::decrypt(conf, iv, ciphertext);
    printf("porc decrypted: ");
    dump_vector(porc_dec);

    auto ciphertext2 = cbc_aes256_encrypt(iv, key, data2);
    porc_dec = porc::decrypt(conf, iv, ciphertext2);
    printf("porc decrypted2: ");
    dump_vector(porc_dec);

    // timing attack
#ifdef USLEEP_CHEAT
    unsigned reps = 100;
#else
    unsigned reps = 2000000;
#endif
    porc::stats::median_collector stats;
    porc::timed::decryptor_factory_default<timed_example, true> decryptors;
    porc::timed::timed_porc timed_conf(&stats, &decryptors, reps, true);
    auto timed_porc_dec = porc::decrypt(timed_conf, iv, ciphertext);
    printf("timed porc decrypted: ");
    dump_vector(timed_porc_dec);
}
