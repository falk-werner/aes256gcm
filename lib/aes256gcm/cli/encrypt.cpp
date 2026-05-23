#include "aes256gcm/cli.hpp"
#include "aes256gcm/proprietary.hpp"

using aes256gcm::proprietary::encrypt_file;
using aes256gcm::proprietary::encrypt_file_inplace;

namespace aes256gcm::cli
{

void encrypt(
    std::string const & input_file,
    std::string const & output_file,
    secure_string && key)
{
    if (output_file.empty())
    {
        encrypt_file_inplace(input_file, std::move(key));
    }
    else
    {
        encrypt_file(input_file, output_file, std::move(key));
    }
}

}
