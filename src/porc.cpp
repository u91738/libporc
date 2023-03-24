#include <algorithm>
#include <cassert>
#include <cmath>
#include <memory>
#include <vector>
#include "porc/porc.hpp"

namespace porc {

uint8_t pkcs7_get_byte(size_t pad_pos, size_t pad_len)
{
    (void)pad_pos;
    return pad_len;
};

bool check_opt(std::function<bool(cipher_desc&)> f, dec_option& opt)
{
    return f(opt.option) && (!opt.false_pos_check.has_value() || f(opt.false_pos_check.value()));
}

std::function<bool(dec_option&)> check_opt_f(std::function<bool(cipher_desc&)> f)
{
    return ([f] (dec_option& opt) { return check_opt(f, opt); });
}

std::function<
    std::tuple<uintmax_t, std::optional<uintmax_t>, size_t>(dec_option&)
>
measure_opt_f(std::function<uintmax_t(cipher_desc&)> f)
{
    return ([f] (dec_option& opt) { return measure_opt(f, opt); });
}

std::tuple<uintmax_t, std::optional<uintmax_t>, size_t>
measure_opt(std::function<uintmax_t(cipher_desc&)> f, dec_option& opt)
{
    if (opt.false_pos_check.has_value())
        return std::make_tuple(f(opt.option), std::make_optional(f(opt.false_pos_check.value())), opt.index);
    else
        return std::make_tuple(f(opt.option), std::optional<uintmax_t>(), opt.index);
}

decryptor::decryptor(
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &ciphertext,
    std::function<uint8_t(size_t, size_t)> get_padding_byte
) : _orig(iv, ciphertext),
    _playground(iv, ciphertext),
    _block_size(iv.size()),
    _block_count(ciphertext.size() / iv.size()),
    _current_block(_block_count - 1),
    _current_byte(iv.size() - 1),
    _get_padding_byte(get_padding_byte)
{
    assert(ciphertext.size() % this->_block_size == 0);
}

dec_option decryptor::option(uint8_t v) const
{
    bool last_byte = this->_current_byte == this->_block_size - 1;

    cipher_desc opt = this->_playground;
    std::optional<cipher_desc> fp = std::nullopt;

    if (this->_block_count == 1) {
        opt.iv[this->_current_byte] = v;
        if(last_byte) {
            fp = opt;
            *(fp.value().iv.rbegin() + 1) ^= 1;
        }
    } else {
        size_t byte_ind = this->_block_size * (this->_block_count - 2) + this->_current_byte;

        opt.ciphertext[byte_ind] = v;
        if(last_byte) {
            fp = opt;
            *(fp.value().ciphertext.rbegin() + this->_block_size + 1) ^= 1;
        }
    }
    return dec_option(v, opt, fp);
}

void decryptor::apply_padding(
            std::vector<uint8_t>::const_iterator pm,
            std::vector<uint8_t>::iterator bi)
{
    size_t padlen = this->_block_size - this->_current_byte;
    size_t padi = this->_current_byte;
    auto pt = this->_plaintext.begin();
    assert(this->_plaintext.size() >= padlen);
    while(padi < this->_block_size) {
        *bi = *pm ^ *pt ^ this->_get_padding_byte(padi, padlen + 1);
        ++padi;
        ++pm;
        ++bi;
        ++pt;
    }
}

void decryptor::update_plaintext(size_t good_opt)
{
    uint8_t pad = this->_get_padding_byte(this->_current_byte,
                                            this->_block_size - this->_current_byte);
    if (this->_block_count == 1 || this->_current_block == 0) {
        this->_plaintext.push_front(this->_orig.iv[this->_current_byte] ^ pad ^ good_opt);
    } else {
        size_t bi = this->_block_size * (this->_current_block - 1) + this->_current_byte;
        this->_plaintext.push_front(this->_orig.ciphertext[bi] ^ pad ^ good_opt);
    }
}

void decryptor::update_playground()
{
    if (this->_block_count == 1) {
        this->apply_padding(this->_orig.iv.cbegin() + this->_current_byte,
                            this->_playground.iv.begin() + this->_current_byte);
    } else {
        size_t play_byte = this->_block_size * (this->_block_count - 2) + this->_current_byte;

        size_t pos_block = std::max<size_t>(1, this->_current_block) - 1;
        size_t ori_offset = this->_block_size * pos_block + this->_current_byte;
        auto ori = this->_current_block == 0 ?
                        this->_orig.iv.cbegin() + ori_offset :
                        this->_orig.ciphertext.cbegin() + ori_offset;
        this->apply_padding(ori,
                            this->_playground.ciphertext.begin() + play_byte);
    }
}

dec_status decryptor::step(size_t good_opt)
{
    assert(good_opt < 0x100);
    this->update_plaintext(good_opt);
    this->update_playground();


    if(this->_current_byte == 0) {
        this->_current_byte = this->_block_size - 1;
        if(this->_current_block == 0) {
            this->_status = dec_status::DONE;
            return this->_status;
        } else {
            --this->_current_block;
            std::copy(
                this->_orig.ciphertext.begin() + this->_current_block * this->_block_size,
                this->_orig.ciphertext.begin() + (this->_current_block + 1) * this->_block_size,
                this->_playground.ciphertext.end() - this->_block_size);

            this->_status = dec_status::NEW_BLOCK;
            return this->_status;
        }
    } else {
        --this->_current_byte;
    }
    this->_status = dec_status::NONE;
    return this->_status;
}

}
