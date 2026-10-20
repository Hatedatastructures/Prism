/** @file Pipeline.cpp @brief 中间件顺序编排实现。 */
#include <Prism/Runtime/Middleware/Pipeline.hpp>

#include <Prism/Runtime/Middleware/Context.hpp>

#include <string>
#include <utility>

namespace Prism::Middleware
{
    auto Pipeline::Add(SharedMiddleware mw) -> Pipeline&
    {
        Chain_.push_back(std::move(mw));
        return *this;
    }

    auto Context::UserForLog() const -> std::string
    {
        if (!DataPlane.DisplayIdentity.empty())
        {
            return DataPlane.DisplayIdentity;
        }
        if (DataPlane.AccountId)
        {
            return std::to_string(DataPlane.AccountId.Value());
        }
        return {};
    }

    auto Pipeline::Run(Context& ctx) -> Net::awaitable<Prism::Fault::Failure>
    {
        for (const auto& mw : Chain_)
        {
            const auto Failure = co_await mw->Handle(ctx.Inbound(), ctx);
            if (Failure.Failed())
            {
                co_return Failure;
            }
        }
        co_return Prism::Fault::Failure{};
    }
}
