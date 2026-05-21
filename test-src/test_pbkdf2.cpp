#include "aes256gcm/pbkdf2.hpp"
#include <gtest/gtest.h>

constexpr int const iterations = 600 * 1000;

TEST(pbsdf2, derive_key)
{
    std::string password = "secret";
    auto const key = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "sha256", iterations);
    ASSERT_EQ(32, key.size());
}

TEST(pbsdf2, derive_key_fails_with_invalid_digest)
{
    ASSERT_ANY_THROW({
        std::string password = "secret";
        aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "invalid-digest", iterations);
    });
}

TEST(pbsdf2, generates_different_keys_for_different_passwords)
{
    std::string password = "secret";
    auto const key1 = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "sha256", iterations);
    password = "SECRET";
    auto const key2 = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "sha256", iterations);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbsdf2, generates_different_keys_for_different_nonces)
{
    std::string password = "secret";
    auto const key1 = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "sha256", iterations);
    password = "secret";
    auto const key2 = aes256gcm::pbkdf2(password, {0,1,2,3,4,5,6,7}, "sha256", iterations);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbsdf2, generates_different_keys_for_different_iterations)
{
    std::string password = "secret";
    auto const key1 = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "sha256", iterations);
    password = "secret";
    auto const key2 = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "sha256", iterations / 2);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbsdf2, generates_different_keys_for_different_digests)
{
    std::string password = "secret";
    auto const key1 = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "sha256", iterations);
    password = "secret";
    auto const key2 = aes256gcm::pbkdf2(password, {1,2,3,4,5,6,7,8}, "md5"   , iterations);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

