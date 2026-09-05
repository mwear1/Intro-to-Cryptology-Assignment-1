// Matthew Wear
// Intro to Crypto
// 9/2/2026
// Test Suite

#include <iostream>
#include <cassert>
#include <stdexcept>
#include "xor_vigenere.hpp"

void test_known_vectors()
{
    // Test Vector 1
    ByteString plaintext1 =
        hex_to_bytes("41747461636b206174206461776e21");

    ByteString key1 =
        hex_to_bytes("494345");

    ByteString ciphertext1 =
        xor_repeating(plaintext1, key1);

    assert(
        bytes_to_hex(ciphertext1) ==
        "08373128202e6922316927243e2d64"
    );


    // Test Vector 2
    ByteString plaintext2 =
        hex_to_bytes("68656c6c6f");

    ByteString key2 =
        hex_to_bytes("6b6579");

    ByteString ciphertext2 =
        xor_repeating(plaintext2, key2);

    assert(
        bytes_to_hex(ciphertext2) ==
        "030015070a"
    );


    // Test Vector 3
    ByteString plaintext3 =
        hex_to_bytes("00010203feff");

    ByteString key3 =
        hex_to_bytes("a55a");

    ByteString ciphertext3 =
        xor_repeating(plaintext3, key3);

    assert(
        bytes_to_hex(ciphertext3) ==
        "a55ba7595ba5"
    );
}

void test_round_trip()
{
    ByteString data = hex_to_bytes("48656c6c6f");
    ByteString key = hex_to_bytes("4b6579");

    ByteString encrypted = xor_repeating(data, key);
    ByteString decrypted = xor_repeating(encrypted, key);

    assert(decrypted == data);
}

void test_empty_message()
{
    ByteString data;
    ByteString key = hex_to_bytes("49");

    ByteString result = xor_repeating(data, key);

    assert(result.empty());
}

void test_key_repeats()
{
    ByteString data = hex_to_bytes("010203040506");
    ByteString key = hex_to_bytes("aabb");

    ByteString encrypted = xor_repeating(data, key);
    ByteString decrypted = xor_repeating(encrypted, key);

    assert(decrypted == data);
}

void test_key_longer_than_message()
{
    ByteString data = hex_to_bytes("0102");
    ByteString key = hex_to_bytes("aabbccddeeff");

    ByteString encrypted = xor_repeating(data, key);
    ByteString decrypted = xor_repeating(encrypted, key);

    assert(decrypted == data);
}

void test_arbitrary_bytes()
{
    ByteString data = {
        0x00,
        0xff,
        0x80,
        0x01,
        0xfe
    };

    ByteString key = {
        0xaa,
        0x55
    };

    ByteString encrypted = xor_repeating(data, key);
    ByteString decrypted = xor_repeating(encrypted, key);

    assert(decrypted == data);
}

void test_empty_key_rejected()
{
    ByteString data = {0x41};
    ByteString key;

    bool threw = false;

    try {
        xor_repeating(data, key);
    }
    catch (const std::invalid_argument&) {
        threw = true;
    }

    assert(threw);
}

void test_odd_length_hex_rejected()
{
    bool threw = false;

    try {
        hex_to_bytes("123");
    }
    catch (const std::invalid_argument&) {
        threw = true;
    }

    assert(threw);
}

void test_invalid_hex_rejected()
{
    bool threw = false;

    try {
        hex_to_bytes("12G4");
    }
    catch (const std::invalid_argument&) {
        threw = true;
    }

    assert(threw);
}

void test_valid_utf8()
{
    ByteString ascii = {
        0x68, 0x65, 0x6c, 0x6c, 0x6f
    };

    assert(is_valid_utf8(ascii));
}

void test_multibyte_utf8()
{
    // UTF-8 bytes for "café"
    ByteString data = {
        0x63, 0x61, 0x66, 0xC3, 0xA9
    };

    ByteString key = hex_to_bytes("4b6579");

    ByteString encrypted = xor_repeating(data, key);
    ByteString decrypted = xor_repeating(encrypted, key);

    assert(decrypted == data);
    assert(is_valid_utf8(decrypted));
}

void test_invalid_utf8()
{
    ByteString data = {
        0xC3, 0x28
    };

    assert(!is_valid_utf8(data));
}

void test_key_generation()
{
    std::size_t length = 16;

    ByteString key = generate_key(length);

    // Check that exactly 16 bytes were generated
    assert(key.size() == length);

    // Convert to the command-line representation
    std::string hex = bytes_to_hex(key);

    // 16 bytes should produce 32 hex characters
    assert(hex.size() == length * 2);

    // Output must contain only lowercase hexadecimal characters
    for (char c : hex) {
        bool valid =
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f');

        assert(valid);
    }
}

void test_zero_length_key_generation_rejected()
{
    bool threw = false;

    try {
        generate_key(0);
    }
    catch (const std::invalid_argument&) {
        threw = true;
    }

    assert(threw);
}

void test_whitespace_hex_rejected()
{
    bool threw = false;

    try {
        hex_to_bytes(" 49 ");
    }
    catch (const std::invalid_argument&) {
        threw = true;
    }

    assert(threw);
}

int main()
{
    test_known_vectors();
    test_round_trip();
    test_empty_message();
    test_key_repeats();
    test_key_longer_than_message();
    test_arbitrary_bytes();
    test_empty_key_rejected();
    test_odd_length_hex_rejected();
    test_invalid_hex_rejected();
    test_valid_utf8();
    test_multibyte_utf8();
    test_invalid_utf8();
    test_key_generation();
    test_zero_length_key_generation_rejected();

    std::cout << "All tests passed.\n";

    return 0;
}