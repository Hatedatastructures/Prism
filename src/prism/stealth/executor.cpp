#include <prism/stealth/executor.hpp>

#include <prism/net/connect/util.hpp>
#include <prism/context/context.hpp>
#include <prism/stealth/tracker.hpp>
#include <prism/stealth/recognition/probe/analyzer.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>
#include <prism/net/transport/snapshot.hpp>

#include <algorithm>

using namespace psm::trace;

namespace psm::stealth
{

    namespace
    {

        [[nodiscard]] auto secondary_probe(const memory::vector<std::byte> &preread)
            -> protocol::protocol_type
        {
            if (preread.empty())
            {
                return protocol::protocol_type::unknown;
            }

            auto view = std::string_view(
                reinterpret_cast<const char *>(preread.data()),
                preread.size());
            auto detected = recognition::probe::detect_tls(view);
            // SS2022 的 AEAD 加密载荷无特征，detect_tls() 无法识别，回退到 shadowsocks
            if (detected == protocol::protocol_type::unknown)
            {
                return protocol::protocol_type::shadowsocks;
            }
            return detected;
        }

    } // namespace

    scheme_executor::scheme_executor(const scheme_registry &registry)
        : schemes_(registry.all().begin(), registry.all().end())
    {
    }


    void scheme_executor::pass_through(handshake_context &ctx, const handshake_result &res)
    {
        if (res.transport)
            ctx.transport = res.transport;
        if (!res.preread.empty() && ctx.transport)
        {
            auto preread_span = std::span(res.preread.data(), res.preread.size());
            ctx.transport = std::make_shared<transport::preview>(ctx.transport, preread_span);
        }
    }


    void scheme_executor::ensure_snapshot(handshake_context &ctx)
    {
        if (!ctx.transport)
            return;
        if (connect::as<transport::snapshot>(ctx.transport))
            return;
        ctx.transport = transport::make_snapshot(std::move(ctx.transport));
    }


    auto scheme_executor::try_rewind(handshake_context &ctx, rewind_mode mode)
        -> bool
    {
        if (mode == rewind_mode::polluted)
            return false;
        if (!ctx.transport)
            return false;
        auto *snap = connect::as<transport::snapshot>(ctx.transport);
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
                trace::warn<flt::conn | flt::protocol>(ctx.trace, "Scheme '{}' not found", name);
                continue;
            }

            if (!scheme->active(*ctx.cfg))
            {
                trace::debug<flt::conn | flt::protocol>(ctx.trace, "Scheme '{}' disabled, skipping", name);
                continue;
            }

            ensure_snapshot(ctx);

            trace::debug<flt::conn | flt::protocol>(ctx.trace, "Executing scheme '{}'", name);

            auto exec_result = co_await execute_single(scheme, handshake_context{ctx});

            // Stack 方案：成功即终止，不传 transport
            if (scheme->category() == scheme_category::stack)
            {
                if (!fault::failed(exec_result.error) && !exec_result.transport)
                {
                    trace::debug<flt::conn | flt::protocol>(ctx.trace, "Stack scheme '{}' handled connection", name);
                    co_return exec_result;
                }
                // Stack 失败 → rewind 并尝试下一个
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
                {
                    pass_through(ctx, exec_result);
                }
                continue;
            }

            // Facade detected==tls → "不是我的"，尝试下一个（优先于成功判断）
            if (exec_result.detected == protocol::protocol_type::tls)
            {
                trace::debug<flt::conn | flt::protocol>(ctx.trace, "Scheme '{}' returned TLS, continuing to next", name);
                rewind_mode rw_mode2;
                if (exec_result.polluted)
                {
                    rw_mode2 = rewind_mode::polluted;
                }
                else
                {
                    rw_mode2 = rewind_mode::clean;
                }
                if (!try_rewind(ctx, rw_mode2))
                    pass_through(ctx, exec_result);
                continue;
            }

            // Facade 方案：transport 非空且无错误即成功
            if (exec_result.transport && !fault::failed(exec_result.error))
            {
                // preread 非空时做二次探测覆盖 detected；preread 为空保留原值
                if (!exec_result.preread.empty())
                {
                    exec_result.detected = secondary_probe(exec_result.preread);
                }
                trace::debug<flt::conn | flt::protocol>(ctx.trace, "Facade scheme '{}' succeeded, inner: {}",
                             name, static_cast<std::int32_t>(exec_result.detected));
                co_return exec_result;
            }

            if (fault::failed(exec_result.error))
            {
                // RFC-065: 认证失败时记录探测行为
                if (tracker_ && !exec_result.polluted)
                {
                    address_hash src_ip;
                    std::memcpy(src_ip.bytes.data(), ctx.src_ip_raw.data(), 16);
                    tracker_->record(src_ip, scheme->tier());

                    // 探测次数达到阈值时触发挑战-响应
                    if (tracker_->should_challenge(src_ip))
                    {
                        trace::debug<flt::conn | flt::protocol>(
                            ctx.trace, "triggering challenge for scheme '{}'", name);
                        auto ch_result = co_await scheme->challenge(handshake_context{ctx});
                        if (ch_result.triggered && ch_result.success)
                        {
                            trace::debug<flt::conn | flt::protocol>(
                                ctx.trace, "challenge passed, retrying handshake");
                            tracker_->reset(src_ip);
                            exec_result = co_await execute_single(scheme, handshake_context{ctx});
                            if (exec_result.transport && !fault::failed(exec_result.error))
                            {
                                if (!exec_result.preread.empty())
                                    exec_result.detected = secondary_probe(exec_result.preread);
                                trace::debug<flt::conn | flt::protocol>(
                                    ctx.trace, "Facade scheme '{}' succeeded after challenge", name);
                                co_return exec_result;
                            }
                        }
                        else if (ch_result.triggered)
                        {
                            trace::warn<flt::conn | flt::protocol>(
                                ctx.trace, "challenge failed for scheme '{}'", name);
                        }
                    }
                }

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
                    trace::debug<flt::conn | flt::protocol>(ctx.trace, "Scheme '{}' failed but snapshot rewound, trying next", name);
                    continue;
                }
                trace::warn<flt::conn | flt::protocol>(ctx.trace, "Scheme '{}' failed with error: {}",
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
            trace::debug<flt::conn | flt::protocol>(ctx.trace, "No candidates from analysis, executing by default priority");

            memory::vector<memory::string> default_order; // 默认顺序
            for (const auto &scheme : schemes_)
                default_order.emplace_back(scheme->name());

            auto native_ctx = handshake_context{ctx};
            auto result = co_await execute_pipeline(default_order, std::move(ctx));

            if (fault::failed(result.error) && !result.transport)
            {
                trace::debug<flt::conn | flt::protocol>(ctx.trace, "All candidates failed, executing native fallback");
                if (const auto native = find_scheme("native"))
                {
                    co_return co_await execute_single(native, std::move(native_ctx));
                }
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
