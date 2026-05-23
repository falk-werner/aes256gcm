#include "aes256gcm/aes256gcm.hpp"
#include <gtest/gtest.h>

using aes256gcm::secure_string;

namespace
{

secure_string generate_key(
    char * password,
    std::string & salt)
{
    std::string digest;
    unsigned int iterations;
    aes256gcm::pbkdf2_generate_params(salt, digest, iterations);

    return aes256gcm::pbkdf2(std::move(secure_string(password)), salt, digest, iterations);
}

}

TEST(aes256gcm, encrypt_and_decrypt)
{
    char password[] = "secret";
    std::string salt;
    auto enc_key = generate_key(password, salt);
    auto dec_key = enc_key;

    aes256gcm::encrypter encrypter(std::move(enc_key));
    std::vector<char> const plaintext = {1, 2, 3, 4};
    std::vector<char> encrypted(plaintext.size());

    encrypter.update(plaintext.data(), encrypted.data(), plaintext.size());
    auto tag = encrypter.finalize();
    auto const & nonce = encrypter.nonce();

    aes256gcm::decrypter decrypter(std::move(dec_key), nonce, tag);
    std::vector<char> decrypted(plaintext.size());
    
    decrypter.update(encrypted.data(), decrypted.data(), decrypted.size());
    bool is_okay = decrypter.finalize();
    
    ASSERT_TRUE(is_okay);
    ASSERT_EQ(plaintext.size(), decrypted.size());
    for(size_t i = 0; i < plaintext.size(); i++)
    {
        ASSERT_EQ(plaintext[i], decrypted[i]);
    }
}

TEST(aes256gcm, encrypt_and_decrypt_inplace)
{
    char password[] = "secret";
    std::string salt;
    auto enc_key = generate_key(password, salt);
    auto dec_key = enc_key;

    aes256gcm::encrypter encrypter(std::move(enc_key));
    char buffer[] = {1, 2, 3, 4};

    encrypter.update_inplace(buffer, 4);
    auto tag = encrypter.finalize();
    auto const & nonce = encrypter.nonce();

    ASSERT_NE(1, buffer[0]);
    ASSERT_NE(2, buffer[1]);
    ASSERT_NE(3, buffer[2]);
    ASSERT_NE(4, buffer[3]);

    aes256gcm::decrypter decrypter(std::move(dec_key), nonce, tag);
    std::vector<char> decrypted;
    
    decrypter.update_inplace(buffer, 4);
    bool is_okay = decrypter.finalize();
    
    ASSERT_EQ(1, buffer[0]);
    ASSERT_EQ(2, buffer[1]);
    ASSERT_EQ(3, buffer[2]);
    ASSERT_EQ(4, buffer[3]);
}

TEST(aes256gcm, decrypt_fails_with_invalid_tag)
{
    char password[] = "secret";
    std::string salt;
    auto enc_key = generate_key(password, salt);
    auto dec_key = enc_key;

    aes256gcm::encrypter encrypter(std::move(enc_key));
    std::vector<char> const plaintext = {1, 2, 3, 4};
    std::vector<char> encrypted(plaintext.size());

    encrypter.update(plaintext.data(), encrypted.data(), plaintext.size());
    auto tag = encrypter.finalize();
    auto const & nonce = encrypter.nonce();

    // corrupt tag
    tag[0]++;

    aes256gcm::decrypter decrypter(std::move(dec_key), nonce, tag);
    std::vector<char> decrypted(plaintext.size());
    
    decrypter.update(encrypted.data(), decrypted.data(), encrypted.size());
    bool is_okay = decrypter.finalize();
    
    // decrypt fails, but ...
    ASSERT_FALSE(is_okay);

    // ... decrypted data is still valid
    ASSERT_EQ(plaintext.size(), decrypted.size());
    for(size_t i = 0; i < plaintext.size(); i++)
    {
        ASSERT_EQ(plaintext[i], decrypted[i]);
    }
}

TEST(aes256gcm, decrypt_fails_with_invalid_key)
{
    char password[] = "secret";
    std::string salt;
    auto key = generate_key(password, salt);

    aes256gcm::encrypter encrypter(std::move(key));
    std::vector<char> const plaintext = {1, 2, 3, 4};
    std::vector<char> encrypted(plaintext.size());

    encrypter.update(plaintext.data(), encrypted.data(), plaintext.size());
    auto tag = encrypter.finalize();
    auto const & nonce = encrypter.nonce();

    char invalid_password[] = "invalid";
    auto invalid_key = generate_key(invalid_password, salt);

    aes256gcm::decrypter decrypter(std::move(invalid_key), nonce, tag);
    std::vector<char> decrypted(plaintext.size());
    
    decrypter.update(encrypted.data(), decrypted.data(), encrypted.size());
    bool is_okay = decrypter.finalize();
    
    ASSERT_FALSE(is_okay);
}

TEST(aes256gcm, decrypt_fails_with_invalid_nonce)
{
    char password[] = "secret";
    std::string salt;
    auto enc_key = generate_key(password, salt);
    auto dec_key = enc_key;

    aes256gcm::encrypter encrypter(std::move(enc_key));
    std::vector<char> const plaintext = {1, 2, 3, 4};
    std::vector<char> encrypted(plaintext.size());

    encrypter.update(plaintext.data(), encrypted.data(), plaintext.size());
    auto tag = encrypter.finalize();
    auto nonce = encrypter.nonce();

    // corrupt nonce
    nonce[0]++;

    aes256gcm::decrypter decrypter(std::move(dec_key), nonce, tag);
    std::vector<char> decrypted(plaintext.size());
    
    decrypter.update(encrypted.data(), decrypted.data(), encrypted.size());
    bool const is_okay = decrypter.finalize();
    
    ASSERT_FALSE(is_okay);
}
