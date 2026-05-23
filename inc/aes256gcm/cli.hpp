#ifndef AES256GCM_CLI_HPP
#define AES256GCM_CLI_HPP

#include <aes256gcm/secure_string.hpp>

#include <iostream>
#include <string>

namespace aes256gcm::cli
{

enum class command
{
    encrypt,
    decrypt,
    verify,
    print_info,
    print_version,
    print_help
};

struct context
{
    context(int argc, char* argv[], std::ostream & err);

    command cmd;
    int exit_code;
    std::string infile;
    std::string outfile;
    secure_string key;
};

int run(int argc, char* argv[], std::istream & in, std::ostream & out, std::ostream & err) noexcept;

void print_usage(std::ostream & out);

int print_version(std::ostream & out);

int print_info(std::string const & filename, std::ostream & out, std::ostream & err);

void encrypt(
    std::string const & input_file,
    std::string const & output_file,
    secure_string && key,
    std::ostream & out);

int decrypt(
    std::string const & input_file,
    std::string const & output_file,
    secure_string && key,
    std::ostream & out);

int verify(
    std::string const & input_file,
    secure_string && key,
    std::ostream & out,
    std::ostream & err);

}

#endif
