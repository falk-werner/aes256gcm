#include "aes256gcm/cli.hpp"
#include <gtest/gtest.h>
#include <sstream>

TEST(cli, print_usage)
{
    std::stringstream in;
    std::stringstream out;
    std::stringstream err;    
    char arg0[] = "aes256gcm";
    char arg1[] = "--help";
    char * args[] = { arg0, arg1, nullptr }; 
    auto const result = aes256gcm::cli::run(2, args, in, out, err);

    ASSERT_EQ(0, result);
    ASSERT_NE("", out.str());
    ASSERT_EQ("", err.str());
}