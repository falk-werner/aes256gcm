#include "aes256gcm/cli.hpp"
#include "aes256gcm/proprietary.hpp"

using aes256gcm::proprietary::decrypt_file;
using aes256gcm::proprietary::decrypt_file_inplace;
using aes256gcm::proprietary::decrypt_file_tostream;

namespace aes256gcm::cli
{

int decrypt(
    std::string const & input_file,
    std::string const & output_file,
    secure_string && key,
    std::ostream & out)
{
    if (output_file.empty())
    {
        return decrypt_file_inplace(input_file, std::move(key));
    }

    if (output_file == "-")
    {
        return decrypt_file_tostream(input_file, out, std::move(key));
    }

    return decrypt_file(input_file, output_file, std::move(key));
}

}