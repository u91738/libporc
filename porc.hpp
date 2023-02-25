#include <cstdio>
#include <vector>

#pragma once

namespace porc {

/**
    Base class for implementations of padding oracle
    with some basic callbacks to track progress.
*/
class porc_provider {
    public:
        virtual bool is_well_padded(
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &data) = 0;

        virtual uint8_t get_padding_byte(size_t pad_pos, size_t pad_len) = 0;

        virtual void on_new_byte(
            const std::vector<uint8_t> &block_pt,
            size_t pt_start_ind)
        { }

        virtual void on_new_block(
            const std::vector<uint8_t> &orig_ct,
            const std::vector<uint8_t> &playground_ct)
        { }

        virtual ~porc_provider() = default;

};

/**
    porc_provider for PKCS7 padding
*/
class porc_pkcs7 : public porc_provider {
    public:
        uint8_t get_padding_byte(size_t pad_pos, size_t pad_len) override
        {
            (void)pad_pos;
            return pad_len;
        }
};

/**
    use porc_provider to decrypt ciphertext via padding oracle attack
*/
std::vector<uint8_t> decrypt(
    porc_provider &config,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &ciphertext
);

namespace stats {

class collector {
public:
    virtual void add(int64_t v) = 0;
    virtual int64_t reset() = 0;
    virtual ~collector() = default;
};

class mean_collector : public collector {
    private:
        uintmax_t sum = 0;
        uintmax_t n = 0;
    public:
        void add(int64_t v) override;
        int64_t reset() override;
};

class median_collector : public collector {
    private:
        std::vector<int64_t> values;
    public:
        void add(int64_t v) override;
        int64_t reset() override;
};

}

namespace timed {

enum class progress { MEASUREMENT, BLOCK , BYTE};

struct measurements {
    int64_t good_time = 0;
    int64_t bad_time = 0;
    int64_t error = 0;
    bool measure_error = false;
    unsigned iter = 0;
    bool guess = false;
    int64_t current = 0;
    std::vector<uint8_t> plaintext;
};

/**
    Measures time taken by decryption op
    in hope to figure out the timing for padding oracle

    Implement measure() in a way that measures only decryption time where possible.
    Handle payload preparation, connections to target etc in constructor-destructor.

    Does not rely on a specific time unit, pick any.
*/
class decryptor {
    public:
        virtual int64_t measure() = 0;
        virtual ~decryptor() = default;
};

/**
    Factory of timed decryptors.
    if you need to store something between different payloads - do it here.
*/
class decryptor_factory {
    public:
        virtual std::unique_ptr<decryptor> get(const std::vector<uint8_t> &data) = 0;
        virtual void on_progress(progress event, measurements &m) = 0;
        virtual ~decryptor_factory() = default;
};

/**
    Somewhat convenient implementation of decryptor_factory
*/
template<typename T, bool verbose>
class decryptor_factory_default : public decryptor_factory {
    public:
        std::unique_ptr<decryptor> get(const std::vector<uint8_t> &data) override
        {
            return std::make_unique<T>(data);
        }

        void on_progress(progress event, measurements &m) override
        {
            switch(event) {
                case progress::BLOCK:
                    printf("good: %ld bad: %ld diff: %ld measured_error: %ld\n",
                            m.good_time,
                            m.bad_time,
                            m.good_time - m.bad_time,
                            m.error);
                break;
                case progress::BYTE:
                    printf("Known block plaintext:");
                    for(auto i : m.plaintext)
                        printf("%02X", i);
                    printf("\n");
                break;
                case progress::MEASUREMENT:
                    if (verbose) {
                        printf("iter: %u timing: %ld padding is %s\n",
                            m.iter,
                            m.current,
                            m.guess ? "good" : "bad");
                    }
                break;
            }
        }
};

/**
    porc_provider implementation for timing-based padding oracles.
    It will measure time for known good and likely bad padding,
    then use stats::collector to compute mean/average over N tries.
    Measurements are repeated for each block to adjust for natural timing changes.
    This good and bad case timing will be used to decide if mean/average of N decryption attempts
    looks like good or bad padding.

    It is important to have high enough measurement_repetitions.
    Try using decryptor_factory_default to guess needed reps.
    Increase until you see that "measured_error" is about 10 times smaller than "diff"
    i.e. two measurements for the same data differ much less than difference between good and bad padding.
    It should work on closer timing too, but in practice, timing seems to fluctuate A LOT.

    Note the wording for "likely bad" padding, there is more than 1/256 chance that
    supposedly bad padding is actually good. Then the attack will fail, try another ciphertext.

    Doesn't own any of it's dependencies, caller must keep decryptor_factory and collector alive.
*/
class timed_porc : public porc::porc_pkcs7  {
    private:
        measurements measured;

        unsigned reps;
        porc::stats::collector *stats;
        decryptor_factory *decryptor;

        int64_t measure_decryptions(const std::vector<uint8_t> &a);

        bool is_good(int64_t current);

    public:
        timed_porc(
            porc::stats::collector *st,
            decryptor_factory *dec,
            unsigned measurement_repetitions,
            bool measure_error);

        void on_new_byte(
            const std::vector<uint8_t> &block_pt,
            size_t pt_start_ind) override;

        void on_new_block(
            const std::vector<uint8_t> &orig_ct,
            const std::vector<uint8_t> &playground_ct) override;

        bool is_well_padded(
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &data) override;
};

}








}
