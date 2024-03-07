#include <iostream>
#include <boost/asio.hpp>
#include <boost/scoped_array.hpp>
#include <vector>
#include <stdexcept>
#include <string>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include "RLSDK/SdkHeaders.hpp"
#include <cbor.h>
#include <cstring>

using boost::asio::ip::udp;

class AESDecryption {
public:
    // This function, akin to a portal between realms, accepts a vector of unsigned char and returns a string.
    std::string vectorUnsignedCharToString(const std::vector<unsigned char>& vec) {
        std::string result;
        // Each unsigned char, a piece of the tangible, is woven back into the tapestry of the abstract.
        for (unsigned char c : vec) {
            result.push_back(static_cast<char>(c)); // The essence of each element is translated back into a character.
        }
        return result; // The string, now reborn from its journey, carries the essence of its transformation.
    }

    std::vector<unsigned char> hexStringToBytes(std::string hex) {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Manually defined CBOR float width indicators
    enum CBORFloatWidth {
        CBOR_FLOAT_0 = 0, // Half-precision floating point (placeholder, not used in standard C++)
        CBOR_FLOAT_1 = 1, // Single-precision floating point (float in C++)
        CBOR_FLOAT_2 = 2  // Double-precision floating point (double in C++)
    };

    // Recursively prints information about a cbor_item_t
    void print_cbor_item(cbor_item_t* item) {
        switch (cbor_typeof(item)) {
        case CBOR_TYPE_UINT:
            std::cout << "Unsigned Integer: " << cbor_get_uint64(item) << std::endl;
            break;
        case CBOR_TYPE_NEGINT:
            std::cout << "Negative Integer: -" << (cbor_get_uint64(item) + 1) << std::endl;
            break;
        case CBOR_TYPE_BYTESTRING: {
            unsigned char* bytes = cbor_bytestring_handle(item);
            size_t length = cbor_bytestring_length(item);
            std::cout << "Byte String of length " << length << ": ";
            for (size_t i = 0; i < length; ++i) {
                printf("%02X", bytes[i]);
            }
            std::cout << std::endl;
            break;
        }
        case CBOR_TYPE_STRING: {
            size_t length;
            unsigned char* str = cbor_string_handle(item);
            length = cbor_string_length(item);
            std::cout << "String: " << std::string(str, str + length) << std::endl;
            break;
        }
        case CBOR_TYPE_ARRAY: {
            size_t n = cbor_array_size(item);
            std::cout << "Array of " << n << " items" << std::endl;
            for (size_t i = 0; i < n; ++i) {
                cbor_item_t* subitem = cbor_array_get(item, i);
                print_cbor_item(subitem);
            }
            break;
        }
        case CBOR_TYPE_MAP: {
            size_t n = cbor_map_size(item);
            std::cout << "Map of " << n << " pairs" << std::endl;
            for (size_t i = 0; i < n; ++i) {
                cbor_pair* pair = cbor_map_handle(item);
                print_cbor_item(pair[i].key);
                std::cout << " : ";
                print_cbor_item(pair[i].value);
                std::cout << std::endl;
            }
            break;
        }
        case CBOR_TYPE_TAG: {
            cbor_item_t* tagged_item = cbor_tag_item(item);
            uint64_t tag = cbor_tag_value(item);
            std::cout << "Tagged item with tag: " << tag << std::endl;
            print_cbor_item(tagged_item);
            break;
        }
        case CBOR_TYPE_FLOAT_CTRL: {
            if (cbor_is_float(item)) {
                if (cbor_float_get_width(item) == CBOR_FLOAT_0) {
                    std::cout << "Float: " << cbor_float_get_float2(item) << std::endl;
                }
                else if (cbor_float_get_width(item) == CBOR_FLOAT_1) {
                    std::cout << "Float: " << cbor_float_get_float4(item) << std::endl;
                }
                else if (cbor_float_get_width(item) == CBOR_FLOAT_2) {
                    std::cout << "Float: " << cbor_float_get_float8(item) << std::endl;
                }
            }
            //else if (cbor_is_bool(item)) {
            //    std::cout << "Boolean: " << (cbor_ctrl_is_bool(item) ? "true" : "false") << std::endl;
            //}
            else if (cbor_is_undef(item)) {
                std::cout << "Undefined" << std::endl;
            }
            else if (cbor_is_null(item)) {
                std::cout << "Null" << std::endl;
            }
            else {
                std::cout << "Unknown float or control type" << std::endl;
            }
            break;
        }
        default:
            std::cout << "Unsupported CBOR type" << std::endl;
            break;
        }
    }

    // Parses CBOR data and prints information about its contents
    void parse_cbor_data(const unsigned char* data, size_t size) {
        struct cbor_load_result result;
        cbor_item_t* item = cbor_load(data, size, &result);

        if (item != nullptr) {
            print_cbor_item(item);
            cbor_decref(&item);
        }
        else {
            std::cerr << "Failed to parse CBOR data." << std::endl;
        }
    }

    AESDecryption() {}
public:
    std::string aes_encrypt(const std::string& plaintext, const unsigned char key[], const unsigned char iv[]) {
        EVP_CIPHER_CTX* ctx;
        std::string ciphertext;
        int len;
        int ciphertext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        /* Initialise the encryption operation. IMPORTANT - ensure you use a key
         * and IV size appropriate for your cipher
         * In this example we are using 256 bit AES (i.e. a 256 bit key). The
         * IV size for *most* modes is the same as the block size. For AES this
         * is 128 bits */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(ctx);
            exit(1);
        }

        boost::scoped_array<unsigned char> cipher_buf(new unsigned char[plaintext.length() + EVP_MAX_BLOCK_LENGTH]);

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_EncryptUpdate(ctx, cipher_buf.get(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.length())) {
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(ctx);
            exit(1);
        }
        ciphertext_len = len;

        /* Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
        if (1 != EVP_EncryptFinal_ex(ctx, cipher_buf.get() + len, &len)) {
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(ctx);
            exit(1);
        }
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        /* Convert the encrypted bytes back to a string */
        ciphertext.assign(reinterpret_cast<char*>(cipher_buf.get()), ciphertext_len);

        return ciphertext;
    }

    std::vector<unsigned char> decrypt(const std::string& message, std::vector<unsigned char> ivData, std::vector<unsigned char> keyData)
    {
        // Create and initialise the context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        // Check if everything went fine
        if (!ctx) {
            throw std::runtime_error("Failed to create new EVP_CIPHER_CTX");
        }

        // Initialise the decryption operation
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyData.data(), ivData.data())) {
            throw std::runtime_error("Failed to initialise decryption operation");
        }

        // Provide the message to be decrypted, and obtain the plaintext output
        std::vector<unsigned char> plaintext(message.size());
        int len;
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(message.data()), message.size())) {
            throw std::runtime_error("Failed to update decryption operation");
        }

        int plaintext_len = len;

        // Finalise the decryption
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
            throw std::runtime_error("Failed to finalise decryption operation");
        }

        plaintext_len += len;

        // Clean up
        EVP_CIPHER_CTX_free(ctx);

        // Remove padding
        plaintext.resize(plaintext_len);

        return plaintext;
    }

private:
    //const unsigned char* ivData;
    //const unsigned char* keyData;
};

class UDPServer {
public:
    UDPServer(boost::asio::io_context& io_context, unsigned short port, unsigned short usPort, const std::string& usAddress, const std::string& siv, const std::string& skey, const std::string& shmackey, const std::string& ssessionid, const std::string& scurrentitle)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
        upstreamPort_(usPort),
        upstreamAddress_(usAddress),
        iv(siv),
        key(skey),
        hmac(shmackey),
        sessionid(ssessionid),
        currentitle(scurrentitle)
    {
        do_receive();
    }

    // Get the most current/active instance of a class. Example: UEngine* engine = GetInstanceOf<UEngine>();
    template<typename T> T* GetInstanceOfA()
    {
        if (std::is_base_of<UObject, T>::value)
        {
            UClass* staticClass = T::StaticClass();

            if (staticClass && UObject::GObjObjects())
            {
                int32_t numObjects = UObject::GObjObjects()->Num();
                for (int32_t i = numObjects - 1; i >= 0; i--)
                {
                    if (i >= numObjects)
                        continue;

                    UObject* uObject = UObject::GObjObjects()->At(i);

                    if (uObject && uObject->IsA(staticClass))
                    {
                        if (uObject->GetFullName().find("Default__") == std::string::npos)
                        {
                            return static_cast<T*>(uObject);
                        }
                    }
                }
            }
        }

        return nullptr;
    }

    // Get the default constructor of a class type. Example: UGameData_TA* gameData = GetDefaultInstanceOf<UGameData_TA>();
    template<typename T> T* GetDefaultInstanceOfA()
    {
        UClass* staticClass = T::StaticClass();

        for (int32_t i = UObject::GObjObjects()->Num(); i > 0; i--)
        {
            UObject* uObject = UObject::GObjObjects()->At(i);

            if (uObject && uObject->IsA(staticClass))
            {
                if (std::string(uObject->GetFullName()).find("Default") != std::string::npos)
                {
                    return reinterpret_cast<T*>(uObject);
                }
            }
        }

        return nullptr;
    }

    UScriptGroup_ORS* scriptORS = nullptr;

    template<typename T> T* CreateInstanceOfA()
    {
        if (!scriptORS) {
            scriptORS = GetInstanceOfA<UScriptGroup_ORS>();

            if (!scriptORS)
                return nullptr;
        }

        T* returnObject = nullptr;

        if (std::is_base_of<UObject, T>::value)
        {
            //T* defaultObject = GetDefaultInstanceOf<T>();
            UClass* staticClass = T::StaticClass();
            UObject* outer = staticClass->Outer;

            if (staticClass)
            {
                returnObject = static_cast<T*>(scriptORS->CreateObject(staticClass, outer));
            }
        }

        return returnObject;
    }
public:
    const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    static inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    std::string base64_decode(std::string const& encoded_string) {
        int in_len = encoded_string.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::string ret;

        while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++)
                    char_array_4[i] = base64_chars.find(char_array_4[i]);

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; (i < 3); i++)
                    ret += char_array_3[i];
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++)
                char_array_4[j] = 0;

            for (j = 0; j < 4; j++)
                char_array_4[j] = base64_chars.find(char_array_4[j]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
        }

        return ret;
    }

    bool ReplaceString(std::string& str, const std::string& from, const std::string& to) {
        size_t start_pos = 0;
        while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }
        return true;
    }

    void do_receive()
    {
        socket_.async_receive_from(
            boost::asio::buffer(data_, max_length), remote_endpoint_,
            [this](boost::system::error_code ec, std::size_t bytes_recvd)
            {
                if (!ec && remote_endpoint_.address().to_string() == "127.0.0.1") {
                    std::cout << "Message downstream..." << std::endl;

                    downstreamPort_ = remote_endpoint_.port();

                    std::string datasub(data_, bytes_recvd);

                    std::vector<unsigned char> keyVector(key.begin(), key.end());
                    std::vector<unsigned char> ivVector(iv.begin(), iv.end());

                    AESDecryption decryptor;

                    std::vector<unsigned char> decryptedbytes;

                    decryptedbytes = decryptor.decrypt(datasub, ivVector, keyVector);

                    std::string decrypted(decryptedbytes.begin(), decryptedbytes.end());

                    if (decrypted.find(decryptor.aes_encrypt(currentitle, (const unsigned char*)key.data(), (const unsigned char*)iv.data())) != std::string::npos) {                     
                        std::cout << "[" << std::to_string(bytes_recvd) << "] " << decrypted << std::endl;
                    }

                    std::string encrypted = decryptor.aes_encrypt(decrypted, (const unsigned char*)key.data(), (const unsigned char*)iv.data());

                    do_send(encrypted.data(), bytes_recvd, upstreamPort_, upstreamAddress_);
                }
                else {
                    std::cout << "Message upstream..." << std::endl;

                    std::string datasub(data_, bytes_recvd);

                    std::vector<unsigned char> keyVector(key.begin(), key.end());
                    std::vector<unsigned char> ivVector(iv.begin(), iv.end());

                    AESDecryption decryptor;

                    std::vector<unsigned char> decryptedbytes;

                    decryptedbytes = decryptor.decrypt(datasub, ivVector, keyVector);

                    std::string decrypted(decryptedbytes.begin(), decryptedbytes.end());

                    do_send(datasub.data(), bytes_recvd, downstreamPort_);
                }

                do_receive();
            });
    }

    void do_send(const char* data, std::size_t length, unsigned short port, const std::string& address = "127.0.0.1")
    {
        auto executor = socket_.get_executor();

        boost::asio::io_context io = (boost::asio::io_context)(uintptr_t)&executor.context();

        udp::resolver resolver(io);
        udp::resolver::query query(udp::v4(), address, std::to_string(port));
        udp::endpoint endpoint = *resolver.resolve(query);

        socket_.async_send_to(boost::asio::buffer(data, length), endpoint,
            [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/)
            {
                // Handle the completion of the send operation if needed
            });
    }

    udp::socket socket_;
    udp::endpoint remote_endpoint_;
    enum { max_length = 1024 };
    char data_[max_length];
    unsigned short upstreamPort_;
    std::string upstreamAddress_;
    unsigned short downstreamPort_;
    std::string iv;
    std::string key;
    std::string hmac;
    std::string sessionid;
    std::string currentitle;
};