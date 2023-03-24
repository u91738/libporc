#include <cassert>
#include <cstdio>
#include "common.hpp"
#include "porc/porc.hpp"

/*
    Classic padding oracle attack.
*/

bool is_padded(const porc::cipher_desc &opt)
{
    return cbc_aes256_decrypt(opt.iv, key, opt.ciphertext).has_value();
}

std::deque<uint8_t> decrypt(const std::vector<uint8_t> &ct)
{
    porc::decryptor p(iv, ct, porc::pkcs7_get_byte);
    while (p.status() != porc::dec_status::DONE) {
        auto o = std::find_if(p.begin(), p.end(), porc::check_opt_f(is_padded));
        p.step(o);
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
        auto dec = cbc_aes256_decrypt(iv, key, ct);
        assert(dec && dec.value() == pt);

        auto pdec = decrypt(ct);
        assert(std::equal(pt.begin(), pt.end(), pdec.begin()));
    }
}
