#include <deque>
#include <optional>
#include <vector>
#include <string>
#include <cstdint>

#pragma once

/*
    Common encryption, key, data, prints for examples
    Nothing related to attack details
*/

const std::vector<uint8_t> iv = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

const std::vector<uint8_t> key = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

const std::vector<uint8_t> data_2blocks = {
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4
};

const std::vector<uint8_t> data2_1block = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4
};

void hexdump(const std::string &header, const std::vector<uint8_t> &v);
void hexdump(const std::string &header, const std::deque<uint8_t> &v);

std::vector<uint8_t> cbc_aes256_encrypt(
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &data);

std::optional<std::vector<uint8_t>> cbc_aes256_decrypt(
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &data);
