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

    auto scheme_executor::execute_by_analysis(const analysis_result &analysis, stealth::scheme_context ctx) const
        -> net::awaitable<execution_result>
    {
        execution_result result;

        // 获取候选方案列表
        memory::vector<memory::string> candidates = analysis.candidates;

        // 如果没有候选（confidence=none），按默认优先级顺序执行所有方案
        // ShadowTLS/RestLS 无 ClientHello 特征，需要实际握手验证
        if (candidates.empty())
        {
            trace::debug("[SchemeExecutor] No candidates from analysis, executing by default priority");

            // 默认执行顺序：reality → shadowtls → restls → native
            memory::vector<memory::string> default_order;
            default_order.emplace_back("reality");
            default_order.emplace_back("shadowtls");
            default_order.emplace_back("restls");
            default_order.emplace_back("native");

            for (const auto &name : default_order)
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

                trace::debug("[SchemeExecutor] Executing scheme '{}' (fallback priority)", name);

                // 复制 ctx 传递给 execute_single，保留原 ctx 用于后续更新
                auto exec_ctx = ctx;
                result = co_await execute_single(scheme, std::move(exec_ctx));

                if (result.success)
                {
                    trace::debug("[SchemeExecutor] Scheme '{}' succeeded, protocol: {}",
                                 name, static_cast<int>(result.scheme_result.detected));
                    co_return result;
                }

                // 如果方案返回 TLS 类型（表示"不是我"），继续下一个
                if (result.scheme_result.detected == psm::protocol::protocol_type::tls)
                {
                    trace::debug("[SchemeExecutor] Scheme '{}' returned TLS, continuing to next", name);
                    // 更新 ctx 为下一个方案准备
                    if (result.scheme_result.transport)
                        ctx.inbound = result.scheme_result.transport;
                    // 如果有 preread 数据，重新包装 preview
                    if (!result.scheme_result.preread.empty() && ctx.inbound)
                    {
                        auto preread_span = std::span<const std::byte>(
                            result.scheme_result.preread.data(), result.scheme_result.preread.size());
                        ctx.inbound = std::make_shared<pipeline::primitives::preview>(
                            ctx.inbound, preread_span, nullptr);
                    }
                    continue;
                }

                // 其他错误，终止执行
                if (fault::failed(result.scheme_result.error))
                {
                    trace::warn("[SchemeExecutor] Scheme '{}' failed with error: {}",
                                name, fault::describe(result.scheme_result.error));
                    co_return result;
                }
            }

            // 所有方案都失败
            result.scheme_result.error = fault::code::not_supported;
            co_return result;
        }

        // 按候选顺序执行
        for (const auto &name : candidates)
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

            trace::debug("[SchemeExecutor] Executing scheme '{}' (analysis-driven)", name);

            // 复制 ctx 传递给 execute_single，保留原 ctx 用于后续更新
            auto exec_ctx = ctx;
            result = co_await execute_single(scheme, std::move(exec_ctx));

            if (result.success)
            {
                trace::debug("[SchemeExecutor] Scheme '{}' succeeded, protocol: {}",
                             name, static_cast<int>(result.scheme_result.detected));
                co_return result;
            }

            // 如果方案返回 TLS 类型（表示"不是我"），继续下一个
            if (result.scheme_result.detected == psm::protocol::protocol_type::tls)
            {
                trace::debug("[SchemeExecutor] Scheme '{}' returned TLS, continuing to next", name);
                // 更新 ctx 为下一个方案准备
                if (result.scheme_result.transport)
                    ctx.inbound = result.scheme_result.transport;
                // 如果有 preread 数据，重新包装 preview
                if (!result.scheme_result.preread.empty() && ctx.inbound)
                {
                    auto preread_span = std::span<const std::byte>(
                        result.scheme_result.preread.data(), result.scheme_result.preread.size());
                    ctx.inbound = std::make_shared<pipeline::primitives::preview>(
                        ctx.inbound, preread_span, nullptr);
                }
                continue;
            }

            // 其他错误，终止执行
            if (fault::failed(result.scheme_result.error))
            {
                trace::warn("[SchemeExecutor] Scheme '{}' failed with error: {}",
                            name, fault::describe(result.scheme_result.error));
                co_return result;
            }
        }

        // 所有候选方案都失败，执行 Native 兜底
        trace::debug("[SchemeExecutor] All candidates failed, executing native fallback");
        if (const auto native = find_scheme("native"))
        {
            co_return co_await execute_single(native, std::move(ctx));
        }

        result.scheme_result.error = fault::code::not_supported;
        co_return result;
    }

    auto scheme_executor::execute_by_priority(const execution_priority &priority, stealth::scheme_context ctx) const
        -> net::awaitable<execution_result>
    {
        execution_result result;

        // 按配置顺序执行
        for (const auto &name : priority.order)
        {
            const auto scheme = find_scheme(name);
            if (!scheme)
            {
                trace::warn("[SchemeExecutor] Scheme '{}' not found in priority order", name);
                continue;
            }

            if (!scheme->is_enabled(*ctx.cfg))
            {
                trace::debug("[SchemeExecutor] Scheme '{}' disabled (config-driven)", name);
                continue;
            }

            trace::debug("[SchemeExecutor] Executing scheme '{}' (config-driven)", name);

            // 复制 ctx 传递给 execute_single，保留原 ctx 用于后续更新
            auto exec_ctx = ctx;
            result = co_await execute_single(scheme, std::move(exec_ctx));

            if (result.success)
            {
                co_return result;
            }

            // "不是我"则继续
            if (result.scheme_result.detected == protocol::protocol_type::tls)
            {
                if (result.scheme_result.transport)
                    ctx.inbound = result.scheme_result.transport;
                // 如果有 preread 数据，重新包装 preview
                if (!result.scheme_result.preread.empty() && ctx.inbound)
                {
                    auto preread_span = std::span<const std::byte>(
                        result.scheme_result.preread.data(), result.scheme_result.preread.size());
                    ctx.inbound = std::make_shared<pipeline::primitives::preview>(
                        ctx.inbound, preread_span, nullptr);
                }
                continue;
            }

            // 错误终止
            if (fault::failed(result.scheme_result.error))
            {
                co_return result;
            }
        }

        result.scheme_result.error = fault::code::not_supported;
        co_return result;
    }

    auto scheme_executor::register_scheme(stealth::shared_scheme scheme) -> void
    {
        schemes_.push_back(std::move(scheme));
    }

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

    auto scheme_executor::execute_single(const stealth::shared_scheme scheme, stealth::scheme_context ctx)
        -> net::awaitable<execution_result>
    {
        execution_result result;
        result.executed_scheme = memory::string(scheme->name());

        auto scheme_result = co_await scheme->execute(std::move(ctx));
        result.scheme_result = std::move(scheme_result);

        // 判断成功：协议已识别且不是 TLS/unknown
        if (result.scheme_result.detected != protocol::protocol_type::tls &&
            result.scheme_result.detected != protocol::protocol_type::unknown &&
            result.scheme_result.transport &&
            !fault::failed(result.scheme_result.error))
        {
            result.success = true;
        }

        co_return result;
    }
} // namespace psm::recognition::handshake