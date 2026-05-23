#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/proprietary/memmapped_file.hpp"

#include "aes256gcm/decrypter.hpp"
#include "aes256gcm/verifier.hpp"
#include "aes256gcm/pbkdf2.hpp"

#include <iostream>
#include <filesystem>


namespace aes256gcm::proprietary
{

void decrypt_file_inplace(
    std::string const & filename,
    secure_string && password)
{
    encryption_info info;
    get_encryption_info(filename, info);

    auto key = pbkdf2(std::move(password), info.kdf.salt, info.kdf.digest, info.kdf.iterations);

    size_t data_size;
    {
        auto verification_key = key;
        verifier v(std::move(verification_key), info.nonce, info.tag, info.additional_data);
        memmapped_file file(filename);
        data_size = file.size() - info.size;

        v.update(file.address(), data_size);
        if (!v.finalize())
        {
            throw std::runtime_error("failed to verify file");
        }

        decrypter dec(std::move(key), info.nonce, info.tag, info.additional_data);
        dec.update_inplace(file.address(), data_size);

        if (!dec.finalize())
        {
            throw std::runtime_error("failed to decrypt file");
        }
    }

    std::filesystem::resize_file(filename, data_size);
}
    
}
