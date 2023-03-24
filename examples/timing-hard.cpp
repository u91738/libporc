#include <cassert>
#include <chrono>
#include <cstdio>
#include <unistd.h>
#include <execution>

#include "porc/porc.hpp"
#include "porc/stats.hpp"
#include "common.hpp"

/*
    Timing based padding oracle
*/

void cbc_decrypt(const std::vector<uint8_t> &iv, const std::vector<uint8_t> &ct)
{
    cbc_aes256_decrypt(iv, key, ct);
}

std::deque<uint8_t> decrypt(const std::vector<uint8_t> &ct)
{
    const size_t tries = 100000;
    porc::time_ns(cbc_decrypt, iv, ct, tries); // empty run makes measurements more consistent

    std::vector<uint8_t> bad_ct = ct;
    bad_ct[bad_ct.size() - 1] ^= 0x12;
    auto bad = porc::stats::mean(porc::time_ns(cbc_decrypt, iv, bad_ct, tries));
    auto good = porc::stats::mean(porc::time_ns(cbc_decrypt, iv, ct, tries));
    auto bad2 = porc::stats::mean(porc::time_ns(cbc_decrypt, iv, bad_ct, tries));

    auto mid = (good + bad) / 2;
    // reasonable person could think that good padding case will be slower,
    // and check for greater_good is unnecessary but optimizers are funny.
    // Also sanitizers change timings A LOT.
    bool greater_good = good > bad;

    auto diff = std::max(good, bad) - std::min(good, bad);
    auto m_err = std::max(bad2, bad) - std::min(bad2, bad);
    printf("good: %" PRIuMAX " bad: %" PRIuMAX " diff: %" PRIuMAX " measurement error: %" PRIuMAX "\n",
           good, bad, diff, m_err);

    if (diff < 5*m_err) {
        printf("Good-bad case diff should be about 5 time bigger than measurement error.\n"
               "Attack will be unreliable.");
    }

    porc::decryptor p(iv, ct, porc::pkcs7_get_byte);
    while (p.status() != porc::dec_status::DONE) {
        auto o = std::find_if(
            std::execution::par_unseq,
            p.begin(), p.end(), porc::check_opt_f([&](porc::cipher_desc &opt) {
            auto m = porc::stats::mean(porc::time_ns(cbc_decrypt, opt, tries / 100));
            //printf("g: %" PRIuMAX" b: %" PRIuMAX " m: %" PRIuMAX " r: %d\n",
            //    good, bad, m, greater_good ? (m > mid) : (m < mid));
            return greater_good ? (m > mid) : (m < mid);
        }));
        p.step(o);
        hexdump("pt: ", p.plaintext());
    }
    hexdump("plaintext: ", p.plaintext());
    return p.plaintext();
}

int main(void)
{
    for(auto &pt : { data_2blocks, data2_1block }) {
        hexdump("plaintext:  ", pt);
        auto ct = cbc_aes256_encrypt(iv, key, pt);
        hexdump("ciphertext: ", ct);
        auto pdec = decrypt(ct);
        assert(std::equal(pt.begin(), pt.end(), pdec.begin()));
    }
}
