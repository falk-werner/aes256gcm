#include "aes256gcm/cli.hpp"
#include "aes256gcm/proprietary.hpp"

using aes256gcm::proprietary::decrypt_file;
using aes256gcm::proprietary::decrypt_file_inplace;

namespace aes256gcm::cli
{

int decrypt(
    std::string const & input_file,
    std::string const & output_file,
    secure_string && key)
{
    if (output_file.empty())
    {
        return decrypt_file_inplace(input_file, std::move(key));
    }

    return decrypt_file(input_file, output_file, std::move(key));
}

}