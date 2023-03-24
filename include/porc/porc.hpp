#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <iterator>
#include <memory>
#include <vector>

#include "porc/stats.hpp"

#pragma once

namespace porc {

/*
    Default padding implementation for the most common padding ever.
*/
uint8_t pkcs7_get_byte(size_t pad_pos, size_t pad_len);

enum class dec_status {
    NONE,
    DONE,
    NEW_BLOCK
};

/*
    Inputs to a padding oracle
*/
struct cipher_desc {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;

    cipher_desc() = default;
    cipher_desc(const std::vector<uint8_t> &iv, const std::vector<uint8_t> &ct)
        : iv(iv), ciphertext(ct) { }
};

/*
    Possible option for inputs to a pading oracle.
    option is the main input,
    false_pos_check contains data that needs to be checked to avoid last byte false-positive
    See check_opt / measure_opt.
*/
struct dec_option {
    size_t index;
    cipher_desc option;
    std::optional<cipher_desc> false_pos_check;

    dec_option() = default;

    dec_option(
        size_t index,
        cipher_desc &option,
        std::optional<cipher_desc> false_pos_check
    ) : index(index), option(option), false_pos_check(false_pos_check) {}
};

/*
    Use f to check the inputs in opt as necessary
*/
bool check_opt(std::function<bool(cipher_desc&)> f, dec_option& opt);

/*
    STL-friendly wrapper for check_opt to avoid nested lambdas
*/
std::function<bool(dec_option&)> check_opt_f(std::function<bool(cipher_desc&)> f);

/*
    Use f to measure the inputs in opt as necessary.
    Returns measurements of f(opt.option), f(false_pos_check), opt.index.
    This order in tuple gives an STL-friendly default comparison
    if you need it (see examples/timing-drift.cpp for example).
*/
std::tuple<uintmax_t, std::optional<uintmax_t>, size_t>
measure_opt(std::function<uintmax_t(cipher_desc&)> f, dec_option& opt);

/*
    STL-friendly wrapper for measure_opt to avoid nested lambdas
*/
std::function<
    std::tuple<uintmax_t, std::optional<uintmax_t>, size_t>
        (dec_option&)
>
measure_opt_f(std::function<uintmax_t(cipher_desc&)> f);

/*
    Measure execution time of f(iv, ct), n-times.
    Result in nanoseconds.
*/
template <typename F>
std::vector<int64_t> time_ns(F f, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &ct, size_t n)
{
    std::vector<int64_t> res;
    for(size_t i = 0; i < n; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        f(iv, ct);
        auto end = std::chrono::high_resolution_clock::now();
        res.push_back(std::chrono::nanoseconds(end - start).count());
    }
    return res;
}

/*
    Measure execution time of f(d.iv, d.ciphertext), n-times.
    Result in nanoseconds.
*/
template <typename F>
std::vector<int64_t> time_ns(F f, const porc::cipher_desc &d, size_t n)
{
    return time_ns(f, d.iv, d.ciphertext, n);
}

/*
    Main class to provide options for a padding oracle attack
*/
class decryptor {
    cipher_desc _orig;
    cipher_desc _playground;
    std::deque<uint8_t> _plaintext;
    size_t _block_size;
    size_t _block_count;
    size_t _current_block;
    size_t _current_byte;
    std::function<uint8_t(size_t, size_t)> _get_padding_byte;

    dec_status _status = dec_status::NONE;

    void apply_padding(
        std::vector<uint8_t>::const_iterator pm,
        std::vector<uint8_t>::iterator bi);
    void update_plaintext(size_t good_opt);
    void update_playground();

    public:

        class option_iterator {
            size_t _ind;
            const decryptor *_parent;
            dec_option _opt;

            public:
                option_iterator(const decryptor *parent, size_t ind)
                    : _ind(ind), _parent(parent), _opt(parent->option(this->_ind)) { }


                option_iterator(const option_iterator &a)
                    : _ind(a._ind), _parent(a._parent), _opt(a._opt) { }

                size_t index() const { return this->_ind; }

                option_iterator & operator +=(int i)
                {
                    this->_ind += i;
                    this->_opt = this->_parent->option(this->_ind);
                    return *this;
                }

                option_iterator & operator -=(int i)
                {
                    return *this += -i;
                }

                option_iterator & operator ++()
                {
                    return *this += 1;
                }

                option_iterator operator ++(int)
                {
                    auto ret = *this;
                    ++*this;
                    return ret;
                }

                option_iterator & operator --()
                {
                    return *this -= 1;
                }

                option_iterator operator --(int)
                {
                    auto ret = *this;
                    --*this;
                    return ret;
                }

                option_iterator operator +(ssize_t i) const
                {
                    option_iterator r(*this);
                    r += i;
                    return r;
                }

                option_iterator operator +(const option_iterator &a) const
                {
                    return *this + a._ind;
                }

                option_iterator operator -(ssize_t i) const
                {
                    return *this + -i;
                }

                ssize_t operator -(const option_iterator &a) const
                {
                    return this->_ind - a._ind;
                }

                dec_option & operator *() {
                    return this->_opt;
                }

                dec_option * operator ->() {
                    return &this->_opt;
                }

                bool operator==(const option_iterator &i) const
                {
                    return this->_ind == i._ind;
                }

                bool operator!=(const option_iterator &i) const
                {
                    return this->_ind != i._ind;
                }

                bool operator < (const option_iterator &i) const
                {
                    return this->_ind < i._ind;
                }

                bool operator <= (const option_iterator &i) const
                {
                    return this->_ind <= i._ind;
                }

                bool operator > (const option_iterator &i) const
                {
                    return this->_ind > i._ind;
                }

                bool operator >= (const option_iterator &i) const
                {
                    return this->_ind >= i._ind;
                }
        };

        decryptor(
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &ciphertext,
            std::function<uint8_t(size_t, size_t)> get_padding_byte
        );

        /*
            Get decryption status.
            Keep calling step() with correct option until status becomes DONE
        */
        dec_status status() const
        {
            return this->_status;
        }

        /*
            Iterate over possible options for a padding oracle.
            It is caller's responsibility to pick a good one.
        */
        option_iterator begin() const
        {
            return option_iterator(this, 0);
        }

        option_iterator end() const
        {
            return option_iterator(this, 0x100);
        }

        const std::vector<uint8_t> & iv() const
        {
            return this->_orig.iv;
        }

        const std::vector<uint8_t> & ciphertext() const
        {
            return this->_orig.ciphertext;
        }

        /*
            Part of plaintext that is currently known
        */
        const std::deque<uint8_t> & plaintext() const
        {
            return this->_plaintext;
        }

        /*
            Get possible option for a padding oracle.
            Iterate [0 .. UINT8_MAX] to get all of them
            or call begin() for an iterator.
        */
        dec_option option(uint8_t v) const;

        /*
            Choose an option with good padding and go to decryption of the next byte.
        */
        dec_status step(const option_iterator &good_opt) {
            assert(good_opt != this->end());
            return this->step(good_opt.index());
        }

        /*
            Choose an option with good padding and go to decryption of the next byte.
        */
        dec_status step(size_t good_opt);

};

}

template<>
struct std::iterator_traits<porc::decryptor::option_iterator> {
    typedef ssize_t difference_type;
    typedef porc::dec_option value_type;
    typedef porc::dec_option* pointer;
    typedef porc::dec_option& reference;
    // not a true random access iterator, can't fit [] signature returning reference
    typedef std::bidirectional_iterator_tag iterator_category;
};
