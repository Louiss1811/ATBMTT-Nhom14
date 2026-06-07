#ifndef DES_CRYPTO_H
#define DES_CRYPTO_H

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/des.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

class DESCrypto {
private:
    static std::string Base64Encode(const std::vector<unsigned char>& data) {
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_write(bio, data.data(), data.size());
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        std::string result(bufferPtr->data, bufferPtr->length);
        BIO_free_all(bio);
        return result;
    }

    static std::vector<unsigned char> Base64Decode(const std::string& in) {
        std::string cleaned = "";
        for (char c : in) {
            if (c != '\n' && c != '\r' && c != ' ' && c != '\t' && c != '\0') {
                cleaned += c;
            }
        }
        BIO *bio, *b64;
        int decodeLen = cleaned.length();
        std::vector<unsigned char> buffer(decodeLen + 1);
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new_mem_buf(cleaned.c_str(), decodeLen);
        bio = BIO_push(b64, bio);
        int len = BIO_read(bio, buffer.data(), decodeLen);
        if (len < 0) len = 0;
        buffer.resize(len);
        BIO_free_all(bio);
        return buffer;
    }

    static std::string HexEncode(const std::vector<unsigned char>& data) {
        std::stringstream ss;
        for (unsigned char b : data) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return ss.str();
    }

    static std::vector<unsigned char> HexDecode(const std::string& hex) {
        std::vector<unsigned char> bytes;
        std::string cleaned = "";
        for (char c : hex) {
            if (isxdigit(c)) cleaned += c;
        }
        for (size_t i = 0; i < cleaned.length(); i += 2) {
            if (i + 1 >= cleaned.length()) break;
            std::string byteString = cleaned.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

public:
    static std::string Encrypt(const std::vector<unsigned char>& plainBytes, const std::string& keyStr, bool useHex = false) {
        DES_cblock key;
        std::string finalKey = keyStr;
        finalKey.resize(8, '0'); 
        memcpy(key, finalKey.c_str(), 8);

        // ĐÃ SỬA LỖI SỐ 3: Ép cấu trúc Parity lẻ chuẩn hóa bit dữ liệu DES cho chuỗi ASCII
        DES_set_odd_parity(&key);

        // ĐÃ SỬA LỖI SỐ 1: Thay sang hàm Unchecked để bỏ qua bộ chặn khóa yếu của OpenSSL
        DES_key_schedule schedule;
        DES_set_key_unchecked(&key, &schedule);

        std::vector<unsigned char> data = plainBytes;
        size_t padding = 8 - (data.size() % 8);
        for (size_t i = 0; i < padding; ++i) {
            data.push_back((unsigned char)padding);
        }

        std::vector<unsigned char> cipherText(data.size());
        for (size_t i = 0; i < data.size(); i += 8) {
            DES_cblock input, output;
            memcpy(input, data.data() + i, 8);
            DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);
            memcpy(cipherText.data() + i, output, 8);
        }

        if (useHex) return HexEncode(cipherText);
        return Base64Encode(cipherText);
    }

    static std::vector<unsigned char> Decrypt(const std::string& cipherInput, const std::string& keyStr, bool useHex = false) {
        std::vector<unsigned char> cipherText;
        if (useHex) {
            cipherText = HexDecode(cipherInput);
        } else {
            cipherText = Base64Decode(cipherInput);
        }
        
        if (cipherText.empty() || cipherText.size() % 8 != 0) return std::vector<unsigned char>();

        DES_cblock key;
        std::string finalKey = keyStr;
        finalKey.resize(8, '0');
        memcpy(key, finalKey.c_str(), 8);

        // ĐÃ SỬA ĐỒNG BỘ: Ép parity bit và dùng Unchecked tại hàm Giải mã
        DES_set_odd_parity(&key);

        DES_key_schedule schedule;
        DES_set_key_unchecked(&key, &schedule);

        std::vector<unsigned char> plainBytes(cipherText.size());
        for (size_t i = 0; i < cipherText.size(); i += 8) {
            DES_cblock input, output;
            memcpy(input, cipherText.data() + i, 8);
            DES_ecb_encrypt(&input, &output, &schedule, DES_DECRYPT);
            memcpy(plainBytes.data() + i, output, 8);
        }

        // ĐÃ TỐI ƯU LỖI SỐ 2: Kiểm tra bóc đệm chuỗi byte nhị phân thô
        if (!plainBytes.empty()) {
            size_t padding = (size_t)plainBytes.back();
            if (padding > 0 && padding <= 8) {
                bool valid = true;
                for (size_t i = plainBytes.size() - padding; i < plainBytes.size(); ++i) {
                    if (plainBytes[i] != padding) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    plainBytes.resize(plainBytes.size() - padding);
                } else {
                    return std::vector<unsigned char>(); 
                }
            } else {
                return std::vector<unsigned char>();
            }
        }
        
        return plainBytes;
    }
};

#endif // DES_CRYPTO_H