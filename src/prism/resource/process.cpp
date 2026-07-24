#include <prism/resource/process.hpp>


namespace psm::resource
{

process::process(options opts)
    : cfg(std::move(opts.cfg))
    , ssl(std::move(opts.ssl))
    , accounts(std::move(opts.accounts))
{
}

} // namespace psm::resource
