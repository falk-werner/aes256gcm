#include "aes256gcm/secure_string.hpp"
#include <gtest/gtest.h>
#include <cstring>

using aes256gcm::secure_string;

TEST(secure_string, default_construct)
{
    secure_string value;
    ASSERT_STREQ("", value.c_str());
    ASSERT_EQ(0, value.size());
}

TEST(secure_string, construct_with_c_str)
{
    char secret[] = "foo";
    secure_string value(secret);

    ASSERT_STREQ("foo", value.c_str());
    ASSERT_EQ(3, value.size());

    ASSERT_EQ(0, strlen(secret));
}

TEST(secure_string, construct_with_size)
{
    char secret[] = "foobar";
    secure_string value(secret, 3);

    ASSERT_STREQ("foo", value.c_str());
    ASSERT_EQ(3, value.size());

    ASSERT_EQ(0, strlen(secret));
}

TEST(secure_string, copy_construct)
{
    char secret[] = "secret";
    secure_string const value_a(secret);
    secure_string value_b(value_a);

    ASSERT_STREQ("secret", value_a.c_str());
    ASSERT_EQ(6, value_a.size());

    ASSERT_STREQ("secret", value_b.c_str());
    ASSERT_EQ(6, value_b.size());
}

TEST(secure_string, move_construct)
{
    char secret[] = "secret";
    secure_string value_a(secret);
    secure_string value_b(std::move(value_a));

    ASSERT_STREQ("", value_a.c_str());
    ASSERT_EQ(0, value_a.size());

    ASSERT_STREQ("secret", value_b.c_str());
    ASSERT_EQ(6, value_b.size());

}

TEST(secure_string, copy_assign)
{
    char secret_a[] = "secret";
    secure_string value_a(secret_a);

    char secret_b[] = "SECRET";
    secure_string value_b(secret_b);
    ASSERT_STREQ("SECRET", value_b.c_str());

    value_b = value_a;
    ASSERT_STREQ("secret", value_a.c_str());
    ASSERT_EQ(6, value_a.size());

    ASSERT_STREQ("secret", value_b.c_str());
    ASSERT_EQ(6, value_b.size());
}

TEST(secrue_string, move_assign)
{
    char secret_a[] = "secret";
    secure_string value_a(secret_a);

    char secret_b[] = "SECRET";
    secure_string value_b(secret_b);
    ASSERT_STREQ("SECRET", value_b.c_str());

    value_b = std::move(value_a);
    ASSERT_STREQ("", value_a.c_str());
    ASSERT_EQ(0, value_a.size());

    ASSERT_STREQ("secret", value_b.c_str());
    ASSERT_EQ(6, value_b.size());
}

TEST(secure_string, equal)
{
    char secret_a[] = "secret";
    secure_string value_a(secret_a);

    char secret_b[] = "secret";
    secure_string value_b(secret_b);
    ASSERT_EQ(value_a, value_b);

    char secret_c[] = "SECRET";
    secure_string value_c(secret_c);
    ASSERT_NE(value_a, value_c);

    char secret_d[] = "foo";
    secure_string value_d(secret_d);
    ASSERT_NE(value_a, value_d);
}

TEST(secure_string, assign_c_str)
{
    secure_string value;
    ASSERT_STREQ("", value.c_str());
    ASSERT_EQ(0, value.size());

    char secret[] = "secret";
    value = secret;
    ASSERT_STREQ("secret", value.c_str());
    ASSERT_EQ(6, value.size());

    ASSERT_EQ(0, strlen(secret));
}

TEST(secure_string, clear)
{
    char secret[] = "secret";
    secure_string value(secret);

    ASSERT_STREQ("secret", value.c_str());
    ASSERT_EQ(6, value.size());

    value.clear();
    ASSERT_STREQ("", value.c_str());
    ASSERT_EQ(0, value.size());
}