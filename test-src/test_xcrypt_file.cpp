#include "aes256gcm/aes256gcm.hpp"
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

using aes256gcm::secure_string;
using aes256gcm::proprietary::decrypt_file;
using aes256gcm::proprietary::encrypt_file;
using aes256gcm::proprietary::decrypt_file_inplace;
using aes256gcm::proprietary::encrypt_file_inplace;

namespace
{

void write_all_text(std::string const & filename, std::string const & contents)
{
    std::ofstream out(filename, std::ios::binary);
    out << contents;
    out.close();
}

std::string read_all_text(std::string const & filename)
{
    std::ifstream in(filename, std::ios::binary);
    std::stringstream contents;
    contents << in.rdbuf();
    in.close();
    return contents.str(); 
}

}

TEST(aes256gcm, encrypt_and_decrypt_file)
{
    std::string const expected = "Sample";
    write_all_text("unencrypted.txt", expected);

    char password1[] = "secret";
    encrypt_file("unencrypted.txt", "encrypted.txt", std::move(secure_string(password1)));

    char password2[] = "secret";
    decrypt_file("encrypted.txt", "decrypted.txt", std::move(secure_string(password2)));

    auto const actual = read_all_text("decrypted.txt");
    ASSERT_EQ(expected, actual);
}

TEST(aes256gcm, encrypt_and_decrypt_file_inplace)
{
    std::string const expected = "Sample";
    std::string const filename = "xcrypt.txt";
    write_all_text(filename, expected);

    char password1[] = "secret";
    encrypt_file_inplace(filename, std::move(secure_string(password1)));

    char password2[] = "secret";
    decrypt_file_inplace(filename, std::move(secure_string(password2)));

    auto const actual = read_all_text("decrypted.txt");
    ASSERT_EQ(expected, actual);
}