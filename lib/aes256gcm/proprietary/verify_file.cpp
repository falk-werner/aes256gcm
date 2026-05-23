#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/proprietary/memmapped_file.hpp"
#include "aes256gcm/decrypter.hpp"
#include "aes256gcm/verifier.hpp"
#include "aes256gcm/pbkdf2.hpp"

#include <fstream>
#include <stdexcept>
#include <filesystem>

#include <iostream>

namespace aes256gcm::proprietary
{
    
void verify_file(
    std::string const & input_filename,
    secure_string && password)
{
    encryption_info info;
    if (!get_encryption_info(input_filename, info))
    {
        throw std::runtime_error("verifcation failed: invalid file format");
    }

    auto key = pbkdf2(std::move(password), info.kdf.salt, info.kdf.digest, info.kdf.iterations);
    verifier v(std::move(key), info.nonce, info.tag, info.additional_data);
    memmapped_file file(input_filename, true);
    auto remaining = file.size() - info.size;

    v.update(file.address(), remaining);
    if (!v.finalize())
    {
        throw std::runtime_error("failed to verify file");
    }

}

}
