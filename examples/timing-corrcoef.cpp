#include <cassert>
#include <cstdio>
#include <unistd.h>
#include <execution>

#include "porc/porc.hpp"
#include "porc/stats.hpp"
#include "common.hpp"

/*
    Timing has close mean and median but different distributions.
    Building distributions and measuring their correlation coefficients solves this
    with less attempts than mean/median
*/

void cbc_decrypt(const std::vector<uint8_t> &iv, const std::vector<uint8_t> &ct)
{
    if(cbc_aes256_decrypt(iv, key, ct).has_value())
        usleep(rand() % 2 ? 0 : 40);
    else
        usleep(20);
}

std::deque<uint8_t> decrypt(const std::vector<uint8_t> &ct)
{
    const size_t tries = 100;
    const size_t buckets = 10;
    porc::time_ns(cbc_decrypt, iv, ct, tries);

    std::vector<uint8_t> bad_ct = ct;
    bad_ct[bad_ct.size() - 1] ^= 0x12;

    auto bad_data = porc::time_ns(cbc_decrypt, iv, bad_ct, tries);
    auto good_data = porc::time_ns(cbc_decrypt, iv, ct, tries);

    auto [gmin, gmax] = std::minmax_element(good_data.begin(), good_data.end());
    auto [bmin, bmax] = std::minmax_element(bad_data.begin(), bad_data.end());
    auto min = std::min(*gmin, *bmin);
    auto max = std::max(*gmax, *bmax);

    porc::stats::bucket_distribution bad( min, max, buckets, bad_data);
    porc::stats::bucket_distribution good(min, max, buckets, good_data);

    porc::stats::bucket_distribution bad2(min, max, buckets, porc::time_ns(cbc_decrypt, iv, bad_ct, tries));
    printf("min: %" PRIuMAX " max: %" PRIuMAX " corrcoef(good, bad): %Lf corrcoef(bad, bad2): %Lf\n",
           min, max, good.corrcoef(bad), bad.corrcoef(bad2));

    porc::decryptor p(iv, ct, porc::pkcs7_get_byte);
    while (p.status() != porc::dec_status::DONE) {
        //std::vector<std::tuple<uintmax_t, std::optional<uintmax_t>, size_t>> ms;
        auto o = std::find_if(p.begin(), p.end(), porc::check_opt_f([&](auto &opt) {
            auto m = porc::time_ns(cbc_decrypt, opt.iv, opt.ciphertext, tries / 5);
            porc::stats::bucket_distribution b(min, max, buckets, m);
            return good.corrcoef(b) > bad.corrcoef(b);
        }));

        p.step(o);
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
