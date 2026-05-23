#include "aes256gcm/openssl_error.hpp"
#include <openssl/err.h>
#include <sstream>

namespace aes256gcm
{

openssl_error::openssl_error()
{
    std::stringstream message;
    constexpr size_t const buffer_size = 256;
    char buffer[buffer_size];

    m_error_code = ERR_get_error();
    ERR_error_string_n(m_error_code, buffer, buffer_size);
    message << buffer;

    auto error_code = ERR_get_error();
    if (error_code != 0) {
        message << '(';
        while (error_code != 0) {
            ERR_error_string_n(error_code, buffer, buffer_size);
            message << ' ' << buffer;

            error_code = ERR_get_error();
        }
        message << ')';
    }
    
    

    m_error_message = message.str();
}

char const * openssl_error::what() const noexcept
{
    return m_error_message.c_str();
}

unsigned long openssl_error::error_code() const noexcept
{
    return m_error_code;
}

}