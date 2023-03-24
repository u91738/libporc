# libporc
Library to help in padding oracle attacks on symmetric ciphers.
Allows user to perform direct or timing-based attacks.
Flexible enough to let user handle unreliable oracles (see `examples/unreliable.cpp`).

To help with timing measurements, use `porc::stats` namespace to
- get mean / median of multiple measurements
- build a distribution of timings to check correlation with a sample with known good/bad padding (see `examples/timing-corrcoef.cpp`)

To use it in your PoC, `make` then link with `libporc.a`.

Basic use looks like this
```C++
bool is_padded(const porc::cipher_desc &opt) {
    // whatever you do with opt.iv and opt.ciphertext
    // to figure out if ciphertext's padding is good
}

std::vector<uint8_t> iv = // ...
std::vector<uint8_t> ciphertext = // ...
porc::decryptor p(iv, ciphertext, porc::pkcs7_get_byte);
while (p.status() != porc::dec_status::DONE) {
    auto o = std::find_if(p.begin(), p.end(), porc::check_opt_f(is_padded));
    p.step(o);
}
hexdump("plaintext: ", p.plaintext());
```

See `examples/` for more complex usage examples.

Not intended for any illegal activities, but you know I can't stop you :-(
