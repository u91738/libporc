#include <vector>
#pragma once

namespace porc {

class porc_provider {
    public:
        virtual bool is_well_padded(
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &data) = 0;

        virtual uint8_t get_padding_byte(size_t pad_pos, size_t pad_len) = 0;

        virtual ~porc_provider() = default;

};

class porc_pkcs7 : public porc_provider {
    public:
        uint8_t get_padding_byte(size_t pad_pos, size_t pad_len) override
        {
            (void)pad_pos;
            return pad_len;
        }
};

std::vector<uint8_t> decrypt(
    porc_provider &config,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &ciphertext
);

}
