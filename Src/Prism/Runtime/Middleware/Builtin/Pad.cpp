/** @file Pad.cpp @brief 按会话策略安装填充传输实现。 */
#include <Prism/Runtime/Middleware/Builtin/Pad.hpp>

#include <Prism/Transport/Pad.hpp>

#include <memory>
#include <utility>

namespace Prism::Middleware::Builtin
{
    auto PadMiddleware::Handle(Prism::SharedTransmission& Inbound, Context& Operation)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        if (Operation.Pad && Operation.Pad->Enabled && Inbound)
        {
            if (!Operation.Pad->Policy || !Operation.Bytes)
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
            }
            Inbound = std::make_shared<Prism::Transport::PadTransport>(std::move(Inbound),
                Prism::Transport::PadOptions{Operation.Pad->Policy, Operation.Bytes, {}});
        }
        co_return Prism::Fault::Failure{};
    }
}
