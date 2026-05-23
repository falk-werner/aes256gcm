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

    
int decrypt_file(
    std::string const & input_filename,
    std::string const & output_filename,
    secure_string && password)
{
    encryption_info info;
    if (!get_encryption_info(input_filename, info))
    {
        return EXIT_FAILURE;
    }

    auto key = pbkdf2(std::move(password), info.kdf.salt, info.kdf.digest, info.kdf.iterations);
    auto verification_key = key;
    decrypter dec(std::move(key), info.nonce, info.tag, info.additional_data);

    {
        verifier v(std::move(verification_key), info.nonce, info.tag, info.additional_data);
        memmapped_file file(input_filename);
        auto remaining = file.size() - info.size;

        v.update(file.address(), remaining);
        if (!v.finalize())
        {
            std::cerr << "error: failed to verify file (file data corrupted)" << std::endl;
            return EXIT_FAILURE;
        }

        std::ofstream out(output_filename, std::ios::binary);

        constexpr size_t const buffer_size = 100 * 1024;
        char const * in_buffer = file.address();
        std::vector<char> out_buffer(buffer_size);

        while ((out) && (remaining > 0))
        {
            auto const chunk_size = std::min(remaining, buffer_size);

            if (chunk_size > 0)
            {
                dec.update(in_buffer, out_buffer.data(), chunk_size);
                out.write(out_buffer.data(), chunk_size);
                remaining -= chunk_size;
                in_buffer += chunk_size;
            }
        }

        if (out.bad())
        {
            throw std::runtime_error("failed to write to file");
        }
    }

    if (!dec.finalize())
    {
        std::filesystem::remove(output_filename);
        std::cerr << "error: failed to decrypt file" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


}