#include <memory>
#include <cassert>
#include <vector>
#include "porc.hpp"

namespace porc {

static void apply_padding(
    porc_provider &config,
    size_t block_size,
    const std::vector<uint8_t> &padding_mask,
    std::vector<uint8_t>::iterator block_begin)
{
    size_t padi = block_size - padding_mask.size();
    auto pm = padding_mask.crbegin();
    auto bi = block_begin + padi;
    while(padi < block_size) {
        *bi = config.get_padding_byte(padi, padding_mask.size() + 1) ^ *pm;

        ++padi;
        ++pm;
        ++bi;
    }
}

static std::vector<uint8_t> decrypt_block(
    porc_provider &config,
    const std::vector<uint8_t> &iv,
    std::vector<uint8_t> &ct,
    std::vector<uint8_t>::const_iterator prev_block_end
)
{
    size_t block_size = iv.size();
    auto block_start = ct.end() - block_size * 2;
    auto block_end = ct.end() - block_size;

    std::vector<uint8_t> padding_mask;
    std::vector<uint8_t> plaintext(block_size);
    for(size_t i = 1; i <= block_size; ++i) {
        uint8_t exp_pad_byte = config.get_padding_byte(i, i);
        --block_end;
        --prev_block_end;

        size_t v;
        for(v = 0; v < 0x100; ++v) {
            *block_end = v;
            if(config.is_well_padded(iv, ct)) {
                if(i == 1) {
                    // check for false positive
                    *(block_end - 1) ^= 1;
                    if(config.is_well_padded(iv, ct))
                        break;
                } else {
                    break;
                }
            }
        }
        padding_mask.push_back(exp_pad_byte ^ v);
        plaintext[block_size - i] = *prev_block_end ^ exp_pad_byte ^ v;
        apply_padding(config, block_size, padding_mask, block_start);
    }

    return plaintext;
}

std::vector<uint8_t> decrypt(
    porc_provider &config,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &ciphertext
)
{
    std::vector<uint8_t> plaintext;
    size_t block_size = iv.size();
    size_t block_count = ciphertext.size() / block_size;
    assert(ciphertext.size() % block_size == 0);

    std::vector<uint8_t> ct(ciphertext);
    for(size_t block = 0; block < block_count; ++block) {
        // set last block
        std::copy(ciphertext.begin() + block * block_size,
                  ciphertext.begin() + (block + 1) * block_size,
                  ct.end() - block_size);

        auto prev_block_start = block == 0 ? iv.begin() : ciphertext.begin() + (block - 1) * block_size;
        auto prev_block_end = prev_block_start + block_size;

        auto block_pt = decrypt_block(config, iv, ct, prev_block_end);
        plaintext.insert(plaintext.end(), block_pt.begin(), block_pt.end());
    }
    return plaintext;
}

}
