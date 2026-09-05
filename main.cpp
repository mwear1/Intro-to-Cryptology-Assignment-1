// Matthew Wear
// Intro to Crypto
// 9/2/2026

#include <iostream>
#include <string>
#include <stdexcept>
#include <windows.h>
#include "xor_vigenere.hpp"

int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    try {
        // Make sure a command was provided
        if (argc < 2) {
            std::cerr << "error: missing command\n";
            return 1;
        }

        std::string command = argv[1];

        if (command == "keygen") {

            // Expected:
            // xor_vigenere keygen --length <positive integer>
            if (argc != 4) {
                std::cerr
                    << "usage: xor_vigenere keygen "
                    << "--length <positive integer>\n";

                return 1;
            }

            if (std::string(argv[2]) != "--length") {
                std::cerr
                    << "usage: xor_vigenere keygen "
                    << "--length <positive integer>\n";

                return 1;
            }

            std::string length_text = argv[3];

            // Make sure it contains only decimal digits
            if (length_text.empty()) {
                throw std::invalid_argument(
                    "key length must be a positive integer"
                );
            }

            for (char c : length_text) {
                if (c < '0' || c > '9') {
                    throw std::invalid_argument(
                        "key length must be a positive integer"
                    );
                }
            }

            std::size_t length;

            try {
                length = std::stoull(length_text);
            }

            catch (const std::exception&) {
                throw std::invalid_argument(
                    "key length must be a positive integer"
                );
            }

            if (length == 0) {
                throw std::invalid_argument(
                    "key length must be a positive integer"
                );
            }

            ByteString key = generate_key(length);

            std::cout << bytes_to_hex(key) << '\n';

            return 0;
        }

        if (command == "encrypt") {

            std::string key_hex;
            std::string text;

            if (argc == 6 &&
                std::string(argv[2]) == "--key" &&
                std::string(argv[4]) == "--text") {

                key_hex = argv[3];
                text = argv[5];
            }
            else if (argc == 5 &&
                std::string(argv[2]) == "--key" &&
                std::string(argv[3]) == "--text") {

                // PowerShell dropped an empty key argument
                key_hex = "";
                text = argv[4];
            }
            else if (argc == 5 &&
                std::string(argv[2]) == "--key" &&
                std::string(argv[4]) == "--text") {

                // PowerShell dropped an empty text argument
                key_hex = argv[3];
                text = "";
            }
            else {
                std::cerr
                    << "usage: xor_vigenere encrypt "
                    << "--key <hex> --text <text>\n";

                return 1;
            }

            ByteString key = hex_to_bytes(key_hex);

            std::string utf8_text = to_utf8(text);

            ByteString plaintext(
                utf8_text.begin(),
                utf8_text.end()
            );

            ByteString ciphertext =
                xor_repeating(plaintext, key);

            std::cout << bytes_to_hex(ciphertext) << '\n';

            return 0;
        }

        if (command == "decrypt") {

            std::string key_hex;
            std::string ciphertext_hex;

            // Normal arguments
            if (argc == 6 &&
                std::string(argv[2]) == "--key" &&
                std::string(argv[4]) == "--ciphertext") {

                key_hex = argv[3];
                ciphertext_hex = argv[5];
            }

            // PowerShell dropped an empty key
            else if (argc == 5 &&
                    std::string(argv[2]) == "--key" &&
                    std::string(argv[3]) == "--ciphertext") {

                key_hex = "";
                ciphertext_hex = argv[4];
            }

            // PowerShell dropped an empty ciphertext argument
            else if (argc == 5 &&
                    std::string(argv[2]) == "--key" &&
                    std::string(argv[4]) == "--ciphertext") {

                key_hex = argv[3];
                ciphertext_hex = "";
            }

            else {
                std::cerr
                    << "usage: xor_vigenere decrypt "
                    << "--key <hex> --ciphertext <hex>\n";

                return 1;
            }

            ByteString key = hex_to_bytes(key_hex);
            ByteString ciphertext = hex_to_bytes(ciphertext_hex);

            ByteString plaintext =
                xor_repeating(ciphertext, key);

            if (!is_valid_utf8(plaintext)) {
                throw std::invalid_argument(
                    "decrypted bytes are not valid UTF-8"
                );
            }

            std::string text(
                plaintext.begin(),
                plaintext.end()
            );

            std::cout << text << '\n';

            return 0;
        }

        std::cerr << "error: unknown command\n";
        return 1;
    }
    
    catch (const std::invalid_argument& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}