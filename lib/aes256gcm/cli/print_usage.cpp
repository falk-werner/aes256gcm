#include "aes256gcm/cli.hpp"
#include "aes256gcm/version.hpp"

namespace aes256gcm::cli
{

void print_usage(std::ostream & out)
{
    out << "aes256gcm, V" << aes256gcm::version() << ", (C) 2026 Falk Werner <github.com/falk-werner>" << std::endl;
    out << R"(Encrypt and decrypt files using AES-256 GCM

Usage:
    encrypt <command> -i INFILE [-o OUTFILE] [-k KEY]

Commands:
    -e, --encrypt encrypt file
    -d, --decrypt decrypt file
    -p, --print   print info of encrypted file
    -v, --version print version

Options:
    -i, --infile  FILE specify input file name
    -o, --outfile FILE specify output file name
                       if not specified, file is encrypted / descripted inplace
    -k, --key     KEY  specify encryption key
                       if not specified, empty key is used
    -K, --keyfile FILE specify the file to read the key from
    -E, --keyenv  NAME specify environment variable to read key from
)";
}

int print_version(std::ostream & out)
{
    out << aes256gcm::version() << std::endl;
    return EXIT_SUCCESS;
}

}