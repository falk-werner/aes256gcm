#include "aes256gcm/pbkdf2.hpp"
#include <gtest/gtest.h>

using aes256gcm::secure_string;

constexpr int const iterations = 2048;

TEST(pbkdf2, derive_key)
{
    char password[] = "secret";
    auto const key = aes256gcm::pbkdf2(std::move(secure_string(password)), {1,2,3,4,5,6,7,8}, "sha256", iterations);
    ASSERT_EQ(32, key.size());
}

TEST(pbkdf2, derive_key_fails_with_invalid_digest)
{
    ASSERT_ANY_THROW({
        char password[] = "secret";
        aes256gcm::pbkdf2(std::move(secure_string(password)), {1,2,3,4,5,6,7,8}, "invalid-digest", iterations);
    });
}

TEST(pbkdf2, generates_different_keys_for_different_passwords)
{
    char password1[] = "secret";
    auto const key1 = aes256gcm::pbkdf2(std::move(secure_string(password1)), {1,2,3,4,5,6,7,8}, "sha256", iterations);
    char password2[] = "SECRET";
    auto const key2 = aes256gcm::pbkdf2(std::move(secure_string(password2)), {1,2,3,4,5,6,7,8}, "sha256", iterations);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbkdf2, generates_different_keys_for_different_nonces)
{
    char password1[] = "secret";
    auto const key1 = aes256gcm::pbkdf2(std::move(secure_string(password1)), {1,2,3,4,5,6,7,8}, "sha256", iterations);
    char password2[] = "secret";
    auto const key2 = aes256gcm::pbkdf2(std::move(secure_string(password2)), {0,1,2,3,4,5,6,7}, "sha256", iterations);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbkdf2, generates_different_keys_for_different_iterations)
{
    char password1[] = "secret";
    auto const key1 = aes256gcm::pbkdf2(std::move(secure_string(password1)), {1,2,3,4,5,6,7,8}, "sha256", iterations);
    char password2[] = "secret";
    auto const key2 = aes256gcm::pbkdf2(std::move(secure_string(password2)), {1,2,3,4,5,6,7,8}, "sha256", iterations / 2);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbkdf2, generates_different_keys_for_different_digests)
{
    char password1[] = "secret";
    auto const key1 = aes256gcm::pbkdf2(std::move(secure_string(password1)), {1,2,3,4,5,6,7,8}, "sha256", iterations);
    char password2[] = "secret";
    auto const key2 = aes256gcm::pbkdf2(std::move(secure_string(password2)), {1,2,3,4,5,6,7,8}, "md5"   , iterations);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

