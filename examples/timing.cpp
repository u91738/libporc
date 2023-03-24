#include <cassert>
#include <chrono>
#include <cstdio>
#include <unistd.h>

#include "porc/porc.hpp"
#include "porc/stats.hpp"
#include "common.hpp"

/*
    Very easy timing-based padding oracle
*/
void cbc_decrypt(const std::vector<uint8_t> &iv, const std::vector<uint8_t> &ct)
{
    if(cbc_aes256_decrypt(iv, key, ct).has_value())
        usleep(0); // timing leak
}

std::deque<uint8_t> decrypt(const std::vector<uint8_t> &ct)
{
    const size_t tries = 10;
    auto good = porc::stats::mean(porc::time_ns(cbc_decrypt, iv, ct, tries));
    std::vector<uint8_t> bad_ct = ct;
    bad_ct[bad_ct.size() - 1] ^= 0x12;
    auto bad = porc::stats::mean(porc::time_ns(cbc_decrypt, iv, bad_ct, tries));
    auto mid = (good + bad) / 2;

    printf("good: %" PRIuMAX " bad: %" PRIuMAX " diff: %" PRIuMAX "\n",
           bad, good, std::max(good, bad) - std::min(good, bad));

    porc::decryptor p(iv, ct, porc::pkcs7_get_byte);
    while (p.status() != porc::dec_status::DONE) {
        auto o = std::find_if(p.begin(), p.end(), porc::check_opt_f([mid](porc::cipher_desc &opt) {
            return porc::stats::mean(porc::time_ns(cbc_decrypt, opt, tries)) > mid;
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
