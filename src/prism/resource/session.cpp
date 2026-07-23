#include <prism/resource/session.hpp>


namespace psm::resource
{

session::session(options opts)
    : worker(std::move(opts.worker))
    , conn(opts.conn)
    , buffer(opts.buffer)
    , inbound(std::move(opts.inbound))
    , outbound(nullptr)
    , detected{}
    , lease()
    , meta(std::move(opts.meta))
    , trace(std::move(opts.trace))
    , arena()
    , src(opts.src)
{
}

auto session::alive() const noexcept
    -> bool
{
    return worker ? worker->alive() : false;
}

} // namespace psm::resource
