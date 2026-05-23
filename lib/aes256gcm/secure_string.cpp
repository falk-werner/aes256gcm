#include "aes256gcm/secure_string.hpp"
#include <openssl/crypto.h>
#include <fstream>
#include <cstring>

namespace aes256gcm
{

secure_string::secure_string()
{
    size_ = 0;
    value_ = nullptr;
}

secure_string::secure_string(char * value)
{   
    size_ = strlen(value);
    if (size_ > 0)
    {
        value_ = new char[size_ + 1];
        memcpy(value_, value, size_);
        value_[size_] = '\0';

        OPENSSL_cleanse(value, size_ + 1);
        value[0] = '\0';
    }
    else {
        value_ = nullptr;
    }
}

secure_string::secure_string(char * value, size_t size)
{
    size_ = size;
    if (size > 0) {
        value_ = new char[size + 1];
        memcpy(value_, value, size_);
        value_[size_] = '\0';

        OPENSSL_cleanse(value, size);        
    }
    else {
        value_ = nullptr;
    }

}

secure_string secure_string::from_file(std::string const & filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("failed to open file");
    }

    file.seekg(0, file.end);
    size_t const size = file.tellg();
    file.seekg(0, file.beg);
    char * value = new char[size + 1];
    file.read(value, size);
    value[size] = '\0';

    secure_string result;
    result.size_ = size;
    result.value_ = value;
    return std::move(result);
}


secure_string::~secure_string()
{
    if (value_ != nullptr)
    {
        OPENSSL_cleanse(value_, size_ + 1);
        delete[] value_;
    }
}

secure_string::secure_string(secure_string const & other)
{
    size_ = other.size_;
    if (size_ > 0) {
        value_ = new char[other.size_ + 1];
        memcpy(value_, other.value_, size_);
        value_[size_] = '\0';
    }
    else {
        value_ = nullptr;
    }
}

secure_string& secure_string::operator=(secure_string const & other)
{
    if (this != &other) {

        auto const size = other.size_;
        char * value = nullptr;
        if (size > 0) {
            value = new char[size + 1];
            memcpy(value, other.value_, size);
            value[size] = '\0';
        }

        if (value_ != nullptr) {
            OPENSSL_cleanse(value_, size_ + 1);
            delete[] value_;
        }
        value_ = value;
        size_ = size;
    }

    return *this;
}

secure_string::secure_string(secure_string && other)
{
    size_ = other.size_;
    value_ = other.value_;

    other.size_ = 0;
    other.value_ = nullptr;
}

secure_string& secure_string::operator=(secure_string && other)
{
    if (this != &other)
    {
        if (value_ != nullptr)
        {
            OPENSSL_cleanse(value_, size_ + 1);
            delete[] value_;
        }

        size_ = other.size_;
        value_ = other.value_;

        other.size_ = 0;
        other.value_ = nullptr;
    }

    return *this;
}

bool secure_string::operator==(secure_string const & other) const
{
    return (size_ == other.size_) && (0 == CRYPTO_memcmp(value_, other.value_, size_));
}

bool secure_string::operator!=(secure_string const & other) const
{
    return !(*this == other);
}


secure_string& secure_string::operator=(char * value)
{
    auto const size = strlen(value);
    char* v = nullptr;
    if (size > 0) {
        v= new char[size + 1];
        memcpy(v, value, size);
        v[size] = '\0';

        OPENSSL_cleanse(value, size);
        value[0] = '\0';
    }

    if (value_ != nullptr) {
        OPENSSL_cleanse(value_, size_ + 1);
        delete[] value_;
    }
    size_ = size;
    value_ = v;

    return *this;
}


char const * secure_string::c_str() const
{
    return (value_ != nullptr) ? value_ : "";
}

size_t secure_string::size() const
{
    return size_;
}

void secure_string::clear()
{
    if (value_ != nullptr) {
        OPENSSL_cleanse(value_, size_ + 1);
        delete[] value_;
    }
    value_ = nullptr;
    size_ = 0;
}

}