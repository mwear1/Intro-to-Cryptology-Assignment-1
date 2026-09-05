// Matthew Wear
// Intro to Crypto
// 9/2/2026

#include "xor_vigenere.hpp"

#include <stdexcept>
#include <windows.h>
#include <bcrypt.h>
#include <limits>

ByteString xor_repeating(const ByteString& data, const ByteString& key)
{
    if (key.empty()) {
        throw std::invalid_argument("key cannot be empty");
    }

    ByteString result(data.size());

    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ key[i % key.size()];   //cipher 
    }

    return result;
}

int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    throw std::invalid_argument("invalid hexadecimal character");
}

ByteString hex_to_bytes(const std::string& hex)
{
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hexadecimal input must have even length");
    }

    ByteString bytes;

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int high = hex_value(hex[i]);
        int low = hex_value(hex[i + 1]);

        Byte byte = static_cast<Byte>((high << 4) | low);

        bytes.push_back(byte);
    }

    return bytes;
}

std::string bytes_to_hex(const ByteString& bytes)
{
    const char hex_chars[] = "0123456789abcdef";

    std::string result;

    for (Byte byte : bytes) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }

    return result;
}

bool is_valid_utf8(const ByteString& bytes)
{
    std::size_t i = 0;

    while (i < bytes.size()) {
        Byte byte = bytes[i];

        // 1-byte ASCII character
        if (byte <= 0x7F) {
            i++;
        }

        // 2-byte UTF-8 character
        else if (byte >= 0xC2 && byte <= 0xDF) {
            if (i + 1 >= bytes.size()) {
                return false;
            }

            if ((bytes[i + 1] & 0xC0) != 0x80) {
                return false;
            }

            i += 2;
        }

        // 3-byte UTF-8 character
        else if (byte >= 0xE0 && byte <= 0xEF) {
            if (i + 2 >= bytes.size()) {
                return false;
            }

            Byte second = bytes[i + 1];
            Byte third = bytes[i + 2];

            if ((second & 0xC0) != 0x80 ||
                (third & 0xC0) != 0x80) {
                return false;
            }

            // Prevent overlong encodings
            if (byte == 0xE0 && second < 0xA0) {
                return false;
            }

            // UTF-16 surrogate range is invalid in UTF-8
            if (byte == 0xED && second >= 0xA0) {
                return false;
            }

            i += 3;
        }

        // 4-byte UTF-8 character
        else if (byte >= 0xF0 && byte <= 0xF4) {
            if (i + 3 >= bytes.size()) {
                return false;
            }

            Byte second = bytes[i + 1];
            Byte third = bytes[i + 2];
            Byte fourth = bytes[i + 3];

            if ((second & 0xC0) != 0x80 ||
                (third & 0xC0) != 0x80 ||
                (fourth & 0xC0) != 0x80) {
                return false;
            }

            // Prevent overly long encodings
            if (byte == 0xF0 && second < 0x90) {
                return false;
            }

            // UTF-8 cannot represent values above U+10FFFF
            if (byte == 0xF4 && second > 0x8F) {
                return false;
            }

            i += 4;
        }

        // Anything else is invalid
        else {
            return false;
        }
    }

    return true;
}

ByteString generate_key(std::size_t length)
{
    if (length == 0) {
        throw std::invalid_argument("key length must be positive");
    }

    if (length > std::numeric_limits<ULONG>::max()) {
        throw std::invalid_argument("key length is too large");
    }

    ByteString key(length);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        key.data(),
        static_cast<ULONG>(length),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status < 0) {
        throw std::runtime_error("secure random key generation failed");
    }

    return key;
}

std::string to_utf8(const std::string& text)
{
    if (text.empty()) {
        return "";
    }

    int wide_length = MultiByteToWideChar(
        CP_ACP,
        0,
        text.c_str(),
        -1,
        nullptr,
        0
    );

    if (wide_length == 0) {
        throw std::runtime_error("failed to convert text to UTF-8");
    }

    std::wstring wide(wide_length, L'\0');

    MultiByteToWideChar(
        CP_ACP,
        0,
        text.c_str(),
        -1,
        wide.data(),
        wide_length
    );

    int utf8_length = WideCharToMultiByte(
        CP_UTF8,
        0,
        wide.c_str(),
        -1,
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (utf8_length == 0) {
        throw std::runtime_error("failed to convert text to UTF-8");
    }

    std::string utf8(utf8_length, '\0');

    WideCharToMultiByte(
        CP_UTF8,
        0,
        wide.c_str(),
        -1,
        utf8.data(),
        utf8_length,
        nullptr,
        nullptr
    );

    utf8.pop_back();

    return utf8;
}