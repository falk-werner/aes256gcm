#include "aes256gcm/cli.hpp"
#include "aes256gcm/proprietary.hpp"

using aes256gcm::proprietary::verify_file;

namespace aes256gcm::cli
{

int verify(
    std::string const & input_file,
    secure_string && key,
    std::ostream & out,
    std::ostream & err)
{
    try {
        verify_file(input_file, std::move(key));
        out << "OK" << std::endl;
        return EXIT_SUCCESS;
    }
    catch (std::exception const & ex) {
        err << "error: " << ex.what() << std::endl;
        out << "FAILED" << std::endl;
        return EXIT_FAILURE;
    }
    catch (...) {
        err << "error: verification failed" << std::endl;
        out << "FAILED" << std::endl;
        return EXIT_FAILURE;
    }
}

}