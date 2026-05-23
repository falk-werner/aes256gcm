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

int decrypt_file_inplace(
    std::string const & filename,
    secure_string && password)
{
    encryption_info info;
    if (!get_encryption_info(filename, info))
    {
        return EXIT_FAILURE;
    }

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
            std::cerr << "error: failed to verify file (file data corrupted)" << std::endl;
            return EXIT_FAILURE;
        }

        decrypter dec(std::move(key), info.nonce, info.tag, info.additional_data);
        dec.update_inplace(file.address(), data_size);

        if (!dec.finalize())
        {
            std::cerr << "error: failed to decrypt file (file data corrupted)" << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::filesystem::resize_file(filename, data_size);
    return EXIT_SUCCESS;
}
    
}
