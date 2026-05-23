#include "aes256gcm/cli.hpp"

#include <getopt.h>

namespace aes256gcm::cli
{

context::context(int argc, char* argv[], std::ostream & err)
{
    static option const long_opts[] = {
        {"encrypt", no_argument, nullptr, 'e'},
        {"decrypt", no_argument, nullptr, 'd'},
        {"verify" , no_argument, nullptr, 't'},
        {"print"  , no_argument, nullptr, 'p'},
        {"version", no_argument, nullptr, 'v'},
        {"infile" , required_argument, nullptr, 'i'},
        {"outfile", required_argument, nullptr, 'o'},
        {"key"    , required_argument, nullptr, 'k'},
        {"keyfile", required_argument, nullptr, 'K'},
        {"keyenv" , required_argument, nullptr, 'E'},
        {"help"   , no_argument, nullptr, 'h'},
        {nullptr  , 0, nullptr, 0}
    };

    cmd = command::print_help;
    exit_code = EXIT_SUCCESS;

    optind = 0;
    opterr = 0;

    bool done = false;
    while (!done)
    {
        int idx = 0;
        int const c = getopt_long(argc, argv, "edtpvi:o:k:K:E:h", long_opts, &idx);
        switch (c)
        {
            case -1:
                done = true;
                break;
            case 'e':
                cmd = command::encrypt;
                break;
            case 'd':
                cmd = command::decrypt;
                break;
            case 'p':
                cmd = command::print_info;
                break;
            case 'v':
                cmd = command::print_version;
                break;
            case 't':
                cmd = command::verify;
                break;
            case 'i':
                infile = optarg;
                break;
            case 'o':
                outfile = optarg;
                break;
            case 'k':
                key = optarg;
                break;
            case 'K':
                {
                    try {
                        key = secure_string::from_file(optarg);
                    }
                    catch (std::exception const &ex) {
                        err << "error: failed to read key file: " << ex.what() << std::endl;
                        exit_code = EXIT_FAILURE;
                        cmd = command::print_help;
                        done = true;
                    }
                    catch (...) {
                        err << "error: failed to read key file" << std::endl;
                        exit_code = EXIT_FAILURE;
                        cmd = command::print_help;
                        done = true;
                    }
                }
                break;
            case 'E':
                {
                    char * value = secure_getenv(optarg);
                    if (value != nullptr) {
                        key = value;
                    }
                    else {
                        err << "error: environment variable not set" << std::endl;
                        exit_code = EXIT_FAILURE;
                        cmd = command::print_help;
                        done = true;
                    }
                }
                break;
            case 'h':
                cmd = command::print_help;
                done = true;
                break;
            default:
                err << "error: unrecognized option" << std::endl;
                exit_code = EXIT_FAILURE;
                cmd = command::print_help;
                done = true;
                break;
        }
    }

    if ((cmd != command::print_help) && (cmd != command::print_version) && (infile.empty())) {
        err << "error: missing required option -i" << std::endl;
        exit_code = EXIT_FAILURE;
        cmd = command::print_help;
    }
}


}