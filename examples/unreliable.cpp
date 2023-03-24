#include <cassert>
#include <cstdio>
#include <unistd.h>
#include <execution>

#include "porc/porc.hpp"
#include "porc/stats.hpp"
#include "common.hpp"

/*
    Padding oracle attack with unreliable oracle.
    Result of is_padded is mostly correct.
    Help the situation by using some knowledge of plaintext.
    Attacker knows bytes 0 and 10 of plaintext.
*/

bool is_padded(const porc::cipher_desc &opt)
{
    if(cbc_aes256_decrypt(opt.iv, key, opt.ciphertext).has_value())
        return true;
    else
        return rand() % 100 == 0; // return "mostly false"
}

bool can_be_pkcs7_padded(const std::deque<uint8_t> &d)
{
    uint8_t padval = d[d.size() - 1];
    auto begin = padval >= d.size() ? d.begin() : d.end() - padval;
    return std::all_of(begin, d.end(), [=](uint8_t v) { return padval == v; });
}


bool can_be_good_pt(const std::deque<uint8_t> &d)
{
    if(!can_be_pkcs7_padded(d))
        return false;

    if(d.size() == 6 && d[0] != 0xB1)
        return false;

    if(d.size() == 16 && d[0] != 0x21)
        return false;

    return true;
}

void decrypt_rec(const porc::decrypt &p, std::vector<std::deque<uint8_t>> &res)
{
    for(auto v : p) {
        if (porc::check_opt(is_padded, v)) {
            porc::decryptor ptmp = p;
            ptmp.step(v.index);

            if(can_be_good_pt(ptmp.plaintext()))
            {
                if(ptmp.status() == porc::dec_status::DONE) {
                    res.push_back(ptmp.plaintext());
                } else {
                    decrypt_rec(ptmp, res);
                }
            }
        }
    }
}

std::vector<std::deque<uint8_t>> decrypt(const std::vector<uint8_t> &ct)
{
    porc::decryptor p(iv, ct, porc::pkcs7_get_byte);
    for(auto v : p)
        assert(v.index < 0x100);
    std::vector<std::deque<uint8_t>> res;
    decrypt_rec(p, res);
    assert(!res.empty());
    return res;
}

int main(void)
{
    hexdump("plaintext:  ", data2_1block);
    auto ct = cbc_aes256_encrypt(iv, key, data2_1block);
    hexdump("ciphertext: ", ct);

    bool has_correct_pt = false;
    for(auto i : decrypt(ct)) {
        bool e =  std::equal(data2_1block.begin(), data2_1block.end(), i.begin());
        hexdump(e ? ">>> " : "    ", i);
        has_correct_pt |= e;
    }
    assert(has_correct_pt);
}
