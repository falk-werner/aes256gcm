#include "aes256gcm/cli.hpp"
#include "aes256gcm/proprietary.hpp"

#include <iomanip>

using aes256gcm::proprietary::get_encryption_info;
using aes256gcm::proprietary::encryption_info;

namespace
{

    void print_hex(std::string const & caption, std::string const & value, std::ostream & out)
{
    out << caption;
    for (char const c: value)
    {
        out << std::setfill('0') << std::hex << (static_cast<int>(c) & 0xff);
    }
    out << std::endl;
}

}

namespace aes256gcm::cli
{

void print_info(std::string const & filename, std::ostream & out, std::ostream & err)
{
    encryption_info info;
    get_encryption_info(filename, info);

    out <<    "Encryption Info Size: " << std::dec << info.size << std::endl;
    out <<    "Key Derivation Function:" << std::endl;
    out <<    "    Algorithm: " << info.kdf.algorithm << std::endl;
    print_hex("    Salt: ", info.kdf.salt, out);
    out <<    "    Digest: " << info.kdf.digest << std::endl;
    out <<    "    Iterations: " << std::dec << info.kdf.iterations << std::endl;
    out <<    "Encryption Settings:" << std::endl;
    out <<    "    Encryption Method: " << info.encryption_method << std::endl;
    print_hex("    Nonce: ", info.nonce, out);
    print_hex("    Tag: ", info.tag, out);
    print_hex("    Additional Data: ", info.additional_data, out);
}

}