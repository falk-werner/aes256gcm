#include "aes256gcm/cli.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    return aes256gcm::cli::run(argc, argv, std::cin, std::cout, std::cerr);
}