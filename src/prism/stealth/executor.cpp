#include <prism/stealth/executor.hpp>

#include <prism/connect/util.hpp>
#include <prism/context/context.hpp>
#include <prism/trace.hpp>
#include <prism/transport/preview.hpp>
#include <prism/transport/snapshot.hpp>

#include <algorithm>

namespace psm::stealth
{

    scheme_executor::scheme_executor(const scheme_registry &registry)
        : schemes_(registry.all().begin(), registry.all().end())
    {
    }

    void scheme_executor::pass_through(handshake_context &ctx, const handshake_result &res)
    {
        if (res.transport)
            ctx.inbound = res.transport;
        if (!res.preread.empty() && ctx.inbound)
        {
            auto preread_span = std::span(res.preread.data(), res.preread.size());
            memory::resource_pointer mr = nullptr;
            if (ctx.session)
                mr = ctx.session->frame_arena.get();
            ctx.inbound = std::make_shared<transport::preview>(ctx.inbound, preread_span, mr);
        }
    }

    void scheme_executor::ensure_snapshot(handshake_context &ctx)
    {
        if (!ctx.inbound)
            return;
        if (connect::as<transport::snapshot>(ctx.inbound))
            return;
        ctx.inbound = transport::make_snapshot(std::move(ctx.inbound));
    }

    auto scheme_executor::try_rewind(handshake_context &ctx, rewind_mode mode)
        -> bool
    {
        if (mode == rewind_mode::polluted)
            return false;
        if (!ctx.inbound)
            return false;
        auto *snap = connect::as<transport::snapshot>(ctx.inbound);
        if (!snap || !snap->can_rewind())
            return false;
        snap->rewind();
        return true;
    }

    auto scheme_executor::execute_single(const shared_scheme scheme, handshake_context ctx)
        -> net::awaitable<handshake_result>
    {
        auto result = co_await scheme->handshake(std::move(ctx));
        result.scheme = memory::string(scheme->name());
        co_return result;
    }

    auto scheme_executor::execute_pipeline(const memory::vector<memory::string> &order, handshake_context ctx) const
        -> net::awaitable<handshake_result>
    {
        handshake_result result;

        for (const auto &name : order)
        {
            const auto scheme = find_scheme(name);
            if (!scheme)
            {
                trace::warn("[SchemeExecutor] Scheme '{}' not found", name);
                continue;
            }

            if (!scheme->active(*ctx.cfg))
            {
                trace::debug("[SchemeExecutor] Scheme '{}' disabled, skipping", name);
                continue;
            }

            ensure_snapshot(ctx);

            trace::debug("[SchemeExecutor] Executing scheme '{}'", name);

            auto exec_result = co_await execute_single(scheme, handshake_context{ctx});

            if (exec_result.detected != protocol::protocol_type::tls &&
                exec_result.detected != protocol::protocol_type::unknown &&
                exec_result.transport && !fault::failed(exec_result.error))
            {
                trace::debug("[SchemeExecutor] Scheme '{}' succeeded, protocol: {}",
                             name, static_cast<int>(exec_result.detected));
                co_return exec_result;
            }

            if (exec_result.detected == protocol::protocol_type::tls)
            {
                trace::debug("[SchemeExecutor] Scheme '{}' returned TLS, continuing to next", name);
                rewind_mode rw_mode;
                if (exec_result.polluted)
                {
                    rw_mode = rewind_mode::polluted;
                }
                else
                {
                    rw_mode = rewind_mode::clean;
                }
                if (!try_rewind(ctx, rw_mode))
                    pass_through(ctx, exec_result);
                continue;
            }

            if (fault::failed(exec_result.error))
            {
                rewind_mode rw_mode;
                if (exec_result.polluted)
                {
                    rw_mode = rewind_mode::polluted;
                }
                else
                {
                    rw_mode = rewind_mode::clean;
                }
                if (try_rewind(ctx, rw_mode))
                {
                    trace::debug("[SchemeExecutor] Scheme '{}' failed but snapshot rewound, trying next", name);
                    continue;
                }
                trace::warn("[SchemeExecutor] Scheme '{}' failed with error: {}",
                            name, fault::describe(exec_result.error));
                co_return exec_result;
            }

            if (!try_rewind(ctx))
                pass_through(ctx, exec_result);
        }

        result.error = fault::code::not_supported;
        co_return result;
    }

    auto scheme_executor::execute_by_analysis(const recognition::analysis_result &analysis, handshake_context ctx) const
        -> net::awaitable<handshake_result>
    {
        if (analysis.candidates.empty())
        {
            trace::debug("[SchemeExecutor] No candidates from analysis, executing by default priority");

            memory::vector<memory::string> default_order; // 默认顺序
            for (const auto &scheme : schemes_)
                default_order.emplace_back(scheme->name());

            auto native_ctx = handshake_context{ctx};
            auto result = co_await execute_pipeline(default_order, std::move(ctx));

            if (fault::failed(result.error) && !result.transport)
            {
                trace::debug("[SchemeExecutor] All candidates failed, executing native fallback");
                if (const auto native = find_scheme("native"))
                    co_return co_await execute_single(native, std::move(native_ctx));
            }

            co_return result;
        }

        co_return co_await execute_pipeline(analysis.candidates, std::move(ctx));
    }

    auto scheme_executor::execute(const memory::vector<memory::string> &candidates, handshake_context ctx) const
        -> net::awaitable<handshake_result>
    {
        co_return co_await execute_pipeline(candidates, std::move(ctx));
    }

    auto scheme_executor::find_scheme(const std::string_view name) const
        -> shared_scheme
    {
        for (const auto &scheme : schemes_)
        {
            if (scheme->name() == name)
                return scheme;
        }
        return nullptr;
    }

} // namespace psm::stealth