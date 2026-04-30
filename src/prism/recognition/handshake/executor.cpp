/**
 * @file executor.cpp
 * @brief 伪装方案执行器实现
 */

#include <prism/recognition/handshake/executor.hpp>
#include <prism/stealth.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/trace.hpp>
#include <algorithm>

namespace psm::recognition::handshake
{
    scheme_executor::scheme_executor(std::vector<stealth::shared_scheme> schemes)
        : schemes_(std::move(schemes))
    {
    }

    // 将 transport 和 preread 数据传递给下一个方案，避免数据丢失
    auto scheme_executor::pass_through(stealth::scheme_context &ctx, const stealth::scheme_result &res)
        -> void
    {
        if (res.transport)
            ctx.inbound = res.transport;
        if (!res.preread.empty() && ctx.inbound)
        {
            auto preread_span = std::span(res.preread.data(), res.preread.size());
            ctx.inbound = std::make_shared<pipeline::primitives::preview>(
                ctx.inbound, preread_span, nullptr);
        }
    }

    // 执行单个方案，将 executed_scheme 写入结果
    auto scheme_executor::execute_single(const stealth::shared_scheme scheme, stealth::scheme_context ctx)
        -> net::awaitable<stealth::scheme_result>
    {
        auto result = co_await scheme->execute(std::move(ctx));
        result.executed_scheme = memory::string(scheme->name());
        co_return result;
    }

    // 核心管道：按给定名称列表逐个执行方案
    auto scheme_executor::execute_pipeline(const memory::vector<memory::string> &order, stealth::scheme_context ctx) const
        -> net::awaitable<stealth::scheme_result>
    {
        stealth::scheme_result result;

        for (const auto &name : order)
        {   // 按照信任程度重试
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

            auto exec_result = co_await execute_single(scheme, stealth::scheme_context{ctx});

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

    auto scheme_executor::execute_by_analysis(const analysis_result &analysis, stealth::scheme_context ctx) const
        -> net::awaitable<stealth::scheme_result>
    {
        // 候选为空时回退到默认顺序
        if (analysis.candidates.empty())
        {
            trace::debug("[SchemeExecutor] No candidates from analysis, executing by default priority");

            memory::vector<memory::string> default_order;
            default_order.emplace_back("reality");
            default_order.emplace_back("shadowtls");
            default_order.emplace_back("restls");
            default_order.emplace_back("native");

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

    auto scheme_executor::execute_by_priority(const execution_priority &priority, stealth::scheme_context ctx) const
        -> net::awaitable<stealth::scheme_result>
    {
        co_return co_await execute_pipeline(priority.order, std::move(ctx));
    }

    auto scheme_executor::register_scheme(stealth::shared_scheme scheme) -> void
    {
        schemes_.push_back(std::move(scheme));
    }

    // 注册顺序即为默认优先级：reality → shadowtls → restls → native
    auto scheme_executor::create_default() -> std::unique_ptr<scheme_executor>
    {
        std::vector<stealth::shared_scheme> schemes;
        schemes.push_back(std::make_shared<stealth::reality::scheme>());
        schemes.push_back(std::make_shared<stealth::shadowtls::scheme>());
        schemes.push_back(std::make_shared<stealth::restls::scheme>());
        schemes.push_back(std::make_shared<stealth::schemes::native>());

        return std::make_unique<scheme_executor>(std::move(schemes));
    }

    auto scheme_executor::find_scheme(const std::string_view name) const
        -> stealth::shared_scheme
    {
        for (const auto &scheme : schemes_)
        {
            if (scheme->name() == name)
                return scheme;
        }
        return nullptr;
    }
} // namespace psm::recognition::handshake
