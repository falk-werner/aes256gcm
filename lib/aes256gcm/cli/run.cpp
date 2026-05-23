#include "aes256gcm/cli.hpp"

namespace aes256gcm::cli
{

int run(int argc, char* argv[], std::istream & in, std::ostream & out, std::ostream & err) noexcept
{
    context ctx(argc, argv, err);

    try
    {
        switch (ctx.cmd)
        {
            case command::encrypt:
                encrypt(ctx.infile, ctx.outfile, std::move(ctx.key), out);
                break;
            case command::decrypt:
                ctx.exit_code = decrypt(ctx.infile, ctx.outfile, std::move(ctx.key), out);
                break;
            case command::print_info:
                ctx.exit_code = print_info(ctx.infile, out, err);
                break;
            case command::print_version:
                ctx.exit_code = print_version(out);
                break;
            case command::print_help:
                // fall-through
            default:
                print_usage(out);
                break;
        }
    }
    catch (std::exception const & ex)
    {
        err << "error: " << ex.what() << std::endl;
        ctx.exit_code = EXIT_FAILURE;
    }
    catch (...)
    {
        err << "fatal: unexpected error" << std::endl;
        ctx.exit_code = EXIT_FAILURE;
    }

    return ctx.exit_code;
}

}
