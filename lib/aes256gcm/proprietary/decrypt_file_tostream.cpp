#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/proprietary/memmapped_file.hpp"
#include "aes256gcm/decrypter.hpp"
#include "aes256gcm/verifier.hpp"
#include "aes256gcm/pbkdf2.hpp"
#include "aes256gcm/secure_string.hpp"

#include <fstream>
#include <stdexcept>
#include <filesystem>

namespace aes256gcm::proprietary
{

void decrypt_file_tostream(
    std::string const & input_filename,
    std::ostream & out,
    secure_string && password)
{
    encryption_info info;
    get_encryption_info(input_filename, info);

    auto key = pbkdf2(std::move(password), info.kdf.salt, info.kdf.digest, info.kdf.iterations);
    auto verification_key = key;
    decrypter dec(std::move(key), info.nonce, info.tag, info.additional_data);

    {
        verifier v(std::move(verification_key), info.nonce, info.tag, info.additional_data);
        memmapped_file file(input_filename, true);
        auto remaining = file.size() - info.size;

        v.update(file.address(), remaining);
        if (!v.finalize())
        {
            throw std::runtime_error("failed to verify file (file data corrupted)");
        }

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
        throw std::runtime_error("error: failed to decrypt file");
    }
}

}