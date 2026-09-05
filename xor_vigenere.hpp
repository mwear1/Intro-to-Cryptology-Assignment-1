// Matthew Wear
// Intro to Crypto
// 9/2/2026

#ifndef XOR_VIGENERE_HPP
#define XOR_VIGENERE_HPP

#include <vector>
#include <string>

// For brevity and ease of use
using Byte = unsigned char;
using ByteString = std::vector<Byte>;

ByteString xor_repeating(const ByteString& data, const ByteString& key);

ByteString hex_to_bytes(const std::string& hex);

std::string bytes_to_hex(const ByteString& bytes);

bool is_valid_utf8(const ByteString& bytes);

ByteString generate_key(std::size_t length);

std::string to_utf8(const std::string& text);

#endif