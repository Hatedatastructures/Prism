/** @file Dial.cpp @brief 上游拨号中间件实现。 */
#include <Prism/Runtime/Middleware/Builtin/Dial.hpp>

#include <utility>

namespace Prism::Middleware::Builtin
{
    auto DialMiddleware::Handle(Prism::SharedTransmission&, Context& ctx)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        if (!Dial_)
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::NotSupported};
        }
        auto Result = co_await Dial_(ctx.Target());
        if (!Result)
        {
            co_return Result.error();
        }
        if (!*Result)
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::BadGateway};
        }
        ctx.Outbound = std::move(*Result);
        co_return Prism::Fault::Failure{};
    }
}
