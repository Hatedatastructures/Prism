/**
 * @file executor.cpp
 * @brief 伪装方案执行器实现
 */

#include <prism/stealth/executor.hpp>
#include <prism/agent/context.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/trace.hpp>
#include <algorithm>

namespace psm::stealth
{
    scheme_executor::scheme_executor(const scheme_registry &registry)
        : schemes_(registry.all().begin(), registry.all().end())
    {
    }

    auto scheme_executor::pass_through(scheme_context &ctx, const scheme_result &res) -> void
    {
        if (res.transport)
            ctx.inbound = res.transport;
        if (!res.preread.empty() && ctx.inbound)
        {
            auto preread_span = std::span(res.preread.data(), res.preread.size());
            auto *mr = ctx.session ? ctx.session->frame_arena.get() : nullptr;
            ctx.inbound = std::make_shared<pipeline::primitives::preview>(ctx.inbound, preread_span, mr);
        }
    }

    auto scheme_executor::execute_single(const shared_scheme scheme, scheme_context ctx)
        -> net::awaitable<scheme_result>
    {
        auto result = co_await scheme->execute(std::move(ctx));
        result.executed_scheme = memory::string(scheme->name());
        co_return result;
    }

    auto scheme_executor::execute_pipeline(const memory::vector<memory::string> &order, scheme_context ctx) const
        -> net::awaitable<scheme_result>
    {
        scheme_result result;

        for (const auto &name : order)
        {
            const auto scheme = find_scheme(name);
            if (!scheme)
            {
                trace::warn("[SchemeExecutor] Scheme '{}' not found", name);
                continue;
            }

            if (!scheme->is_enabled(*ctx.cfg))
            {
                trace::debug("[SchemeExecutor] Scheme '{}' disabled, skipping", name);
                continue;
            }

            trace::debug("[SchemeExecutor] Executing scheme '{}'", name);

            auto exec_result = co_await execute_single(scheme, scheme_context{ctx});

            // 成功：内层协议已识别
            if (exec_result.detected != protocol::protocol_type::tls &&
                exec_result.detected != protocol::protocol_type::unknown &&
                exec_result.transport && !fault::failed(exec_result.error))
            {
                trace::debug("[SchemeExecutor] Scheme '{}' succeeded, protocol: {}",
                             name, static_cast<int>(exec_result.detected));
                co_return exec_result;
            }

            // 返回 TLS 表示"不是我"，传递上下文继续下一个
            if (exec_result.detected == protocol::protocol_type::tls)
            {
                trace::debug("[SchemeExecutor] Scheme '{}' returned TLS, continuing to next", name);
                pass_through(ctx, exec_result);
                continue;
            }

            // 其他错误，终止
            if (fault::failed(exec_result.error))
            {
                trace::warn("[SchemeExecutor] Scheme '{}' failed with error: {}",
                            name, fault::describe(exec_result.error));
                co_return exec_result;
            }
        }

        result.error = fault::code::not_supported;
        co_return result;
    }

    auto scheme_executor::execute_by_analysis(const recognition::analysis_result &analysis, scheme_context ctx) const
        -> net::awaitable<scheme_result>
    {
        // 候选为空时按注册顺序执行
        if (analysis.candidates.empty())
        {
            trace::debug("[SchemeExecutor] No candidates from analysis, executing by default priority");

            memory::vector<memory::string> default_order; // 默认顺序
            for (const auto &scheme : schemes_)
                default_order.emplace_back(scheme->name());

            auto result = co_await execute_pipeline(default_order, std::move(ctx));

            // 全部失败则 native 兜底
            if (fault::failed(result.error) && !result.transport)
            {
                trace::debug("[SchemeExecutor] All candidates failed, executing native fallback");
                if (const auto native = find_scheme("native"))
                    co_return co_await execute_single(native, std::move(ctx));
            }

            co_return result;
        }

        // 按分析结果顺序执行
        co_return co_await execute_pipeline(analysis.candidates, std::move(ctx));
    }

    auto scheme_executor::execute(const memory::vector<memory::string> &candidates, scheme_context ctx) const
        -> net::awaitable<scheme_result>
    {
        co_return co_await execute_pipeline(candidates, std::move(ctx));
    }

    auto scheme_executor::find_scheme(const std::string_view name) const -> shared_scheme
    {
        for (const auto &scheme : schemes_)
        {
            if (scheme->name() == name)
                return scheme;
        }
        return nullptr;
    }

} // namespace psm::stealth
