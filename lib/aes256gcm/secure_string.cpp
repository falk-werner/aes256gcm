#include "aes256gcm/secure_string.hpp"
#include <openssl/crypto.h>
#include <cstring>

namespace aes256gcm
{

secure_string::secure_string()
{
    size_ = 0;
    value_ = new char[1];
    value_[0] = '\0';
}

secure_string::secure_string(char * value)
{   
    size_ = strlen(value);
    value_ = new char[size_ + 1];
    memcpy(value_, value, size_);
    value_[size_] = '\0';

    OPENSSL_cleanse(value, size_ + 1);
    value[0] = '\0';
}

secure_string::secure_string(char * value, size_t size)
{
    size_ = size;
    value_ = new char[size + 1];

    if (size > 0)
    {
        memcpy(value_, value, size_);
        OPENSSL_cleanse(value, size);        
    }

    value_[size_] = '\0';
}


secure_string::~secure_string()
{
    OPENSSL_cleanse(value_, size_ + 1);
    delete[] value_;
}

secure_string::secure_string(secure_string const & other)
{
    size_ = other.size_;
    value_ = new char[other.size_ + 1];
    memcpy(value_, other.value_, size_);
    value_[size_] = '\0';
}

secure_string& secure_string::operator=(secure_string const & other)
{
    if (this != &other)
    {
        OPENSSL_cleanse(value_, size_ + 1);
        delete[] value_;

        size_ = other.size_;
        value_ = new char[other.size_ + 1];
        memcpy(value_, other.value_, size_);
        value_[size_] = '\0';
    }

    return *this;
}

secure_string::secure_string(secure_string && other)
{
    size_ = other.size_;
    value_ = other.value_;

    other.size_ = 0;
    other.value_ = new char[1];
    other.value_[0] = '\0';
}

secure_string& secure_string::operator=(secure_string && other)
{
    if (this != &other)
    {
        OPENSSL_cleanse(value_, size_ + 1);
        delete[] value_;

        size_ = other.size_;
        value_ = other.value_;

        other.size_ = 0;
        other.value_ = new char[1];
        other.value_[0] = '\0';
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
    OPENSSL_cleanse(value_, size_ + 1);
    delete[] value_;

    size_ = strlen(value);
    value_ = new char[size_ + 1];
    memcpy(value_, value, size_);
    value_[size_] = '\0';

    OPENSSL_cleanse(value, size_);
    value[0] = '\0';

    return *this;
}


char const * secure_string::c_str() const
{
    return value_;
}

size_t secure_string::size() const
{
    return size_;
}

void secure_string::clear()
{
    OPENSSL_cleanse(value_, size_ + 1);
    value_[0] = '\0';
    size_ = 0;
}

}