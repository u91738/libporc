#include <cassert>
#include <cstdio>
#include <unistd.h>
#include <iterator>

#include "porc/porc.hpp"
#include "porc/stats.hpp"
#include "common.hpp"

/*
    Timing based padding oracle where decryption has increasing delay
    so attacker can't stop early to decide which option is good
*/

void cbc_decrypt(const std::vector<uint8_t> &iv, const std::vector<uint8_t> &ct)
{
    static size_t calls = 0;
    ++calls;
    if(cbc_aes256_decrypt(iv, key, ct).has_value())
        usleep(10 + calls / 10000);
    else
        usleep(calls / 10000);
}

std::deque<uint8_t> decrypt(const std::vector<uint8_t> &ct)
{
    const size_t tries = 10000;
    porc::time_ns(cbc_decrypt, iv, ct, tries);

    std::vector<uint8_t> bad_ct = ct;
    bad_ct[bad_ct.size() - 1] ^= 0x12;
    auto bad = porc::stats::median(porc::time_ns(cbc_decrypt, iv, bad_ct, tries));
    auto good = porc::stats::median(porc::time_ns(cbc_decrypt, iv, ct, tries));
    auto bad2 = porc::stats::median(porc::time_ns(cbc_decrypt, iv, bad_ct, tries));

    auto diff = std::max(good, bad) - std::min(good, bad);
    auto m_err = std::max(bad2, bad) - std::min(bad2, bad);
    printf("good: %" PRIuMAX " bad: %" PRIuMAX " diff: %" PRIuMAX " measurement error: %" PRIuMAX "\n",
           good, bad, diff, m_err);

    porc::decryptor p(iv, ct, porc::pkcs7_get_byte);
    while (p.status() != porc::dec_status::DONE) {
        std::vector<std::tuple<uintmax_t, std::optional<uintmax_t>, size_t>> ms;
        for (auto &o : p) {
            ms.push_back(porc::measure_opt([&](auto &opt) {
                return porc::stats::median(porc::time_ns(cbc_decrypt, opt, tries / 500));
            }, o));
        }

        std::partial_sort(ms.begin(), ms.begin() + 3, ms.end(),
                          [](auto &a, auto &b) { return a > b; });

        auto [m, __, ind] = *std::max_element(ms.begin(), ms.begin() + 3,
                                              [](auto a, auto b) { return std::get<1>(a) < std::get<1>(b); });
        p.step(ind);
        printf("time: %" PRIuMAX " ", m);
        hexdump("pt: ", p.plaintext());
    }
    hexdump("plaintext: ", p.plaintext());
    return p.plaintext();
}

int main(void)
{
    hexdump("plaintext:  ", data_2blocks);
    auto ct = cbc_aes256_encrypt(iv, key, data_2blocks);
    hexdump("ciphertext: ", ct);
    auto pdec = decrypt(ct);
    assert(std::equal(data_2blocks.begin(), data_2blocks.end(), pdec.begin()));
}
