#include <iostream>
#include <boost/asio.hpp>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include "RLSDK/SdkHeaders.hpp"

using boost::asio::ip::udp;

class AESDecryption {
public:
    AESDecryption(std::string siv, std::string skey) {
        ivData = std::vector<uint8_t>(siv.begin(), siv.end());
        keyData = std::vector<uint8_t>(skey.begin(), skey.end());
    }
public:
    std::vector<unsigned char> decrypt(const std::string& message)
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
    std::vector<uint8_t> ivData;
    std::vector<uint8_t> keyData;
};

struct UDPPacket {
    std::vector<uint8_t> data;
};

class UDPServer {
public:
    UDPServer(boost::asio::io_context& io_context, unsigned short port, unsigned short usPort, const std::string& usAddress, const std::string& siv, const std::string& skey)
        : socket_(io_context, udp::endpoint(udp::v4(), port)),
        upstreamPort_(usPort),
        upstreamAddress_(usAddress),
        iv(base64_decode(siv)),
        key(base64_decode(skey))
    {
        do_receive();
    }

    std::vector<UDPPacket> downstream;
private:
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

    void do_receive()
    {
        socket_.async_receive_from(
            boost::asio::buffer(data_, max_length), remote_endpoint_,
            [this](boost::system::error_code ec, std::size_t bytes_recvd)
            {
                if (!ec && remote_endpoint_.address().to_string() == "127.0.0.1") {
                    std::cout << "Message downstream..." << std::endl;

                    downstreamPort_ = remote_endpoint_.port();

                   // std::cout << data_ << std::endl;

                    try {
                        AESDecryption decryptor(iv, key);

                        std::string packetData(data_, data_ + bytes_recvd);

                        if (!packetData.empty()) {
                            std::vector<uint8_t> decryptedbytes = decryptor.decrypt(packetData);

                            int size = decryptedbytes.size();

                            FMessagePacket packet = *(FMessagePacket*)decryptedbytes.data();

                            for (auto value : packet.Values)
                            {
                                std::cout << value.IntValue << std::endl;
                                std::cout << value.NameValue.ToString() << std::endl;
                                if (value.ObjectValue)
                                    std::cout << value.ObjectValue->GetFullName() << std::endl;
                                std::cout << value.StringValue.ToString() << std::endl;
                                std::cout << value.ValueType << std::endl;
                            }

                            UMessage_TA* message = packet.Message;
                            if (message)
                            {
                                std::cout << message->GetFullName() << std::endl;
                            }

                            //std::cout << "Pushing back decrypted packet " << std::endl;

                            std::cout << "[" << size << "] " << decryptedbytes.data() << std::endl;

                            downstream.push_back({ decryptedbytes });
                        }
                    }
                    catch (const std::exception& e) {
                        std::cout << "Key: " << key << std::endl;
                        std::cerr << e.what() << std::endl;
                    }

                    do_send(data_, bytes_recvd, upstreamPort_, upstreamAddress_);
                }
                else {
                    std::cout << "Message upstream..." << std::endl;

                    try {
                        AESDecryption decryptor(iv, key);

                        std::string packetData(data_, data_ + bytes_recvd);

                        if (!packetData.empty()) {
                            std::vector<uint8_t> decryptedbytes = decryptor.decrypt(packetData);

                            int size = decryptedbytes.size();

                            //std::cout << "Pushing back decrypted packet " << std::endl;

                            std::cout << "[" << size << "] " << decryptedbytes.data() << std::endl;

                            downstream.push_back({ decryptedbytes });
                        }
                    }
                    catch (const std::exception& e) {
                        std::cout << "Key: " << key << std::endl;
                        std::cerr << e.what() << std::endl;
                    }

                    do_send(data_, bytes_recvd, downstreamPort_);
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
};
