/**
 * @file recognition.cpp
 * @brief Recognition 模块入口
 */

#include <prism/recognition/recognition.hpp>
#include <prism/stealth.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/stealth/executor.hpp>
#include <prism/protocol/tls/signal.hpp>
#include <prism/trace.hpp>
#include <prism/pipeline/primitives.hpp>

namespace psm::recognition
{
    auto identify(identify_context ctx) -> net::awaitable<identify_result>
    {
        identify_result result;

        trace::debug("[Recognition] Starting identify lifecycle");

        // Phase 1: 读取完整 ClientHello
        auto [read_ec, raw_record] = co_await protocol::tls::read_tls_record(*ctx.transport, ctx.preread);
        if (fault::failed(read_ec))
        {
            trace::error("[Recognition] read_tls_record failed: {}", fault::describe(read_ec));
            result.error = read_ec;
            co_return result;
        }

        trace::debug("[Recognition] Read {} bytes ClientHello", raw_record.size());

        // Phase 2: 解析 ClientHello 特征
        auto [parse_ec, features] = protocol::tls::parse_client_hello(raw_record);
        if (fault::failed(parse_ec))
        {
            trace::error("[Recognition] parse_client_hello failed: {}", fault::describe(parse_ec));
            result.error = parse_ec;
            co_return result;
        }

        // Phase 3: 让每个 scheme 做 detect()
        auto &registry = stealth::scheme_registry::instance();

        // 收集候选方案及其置信度
        struct candidate_entry
        {
            memory::string name;
            confidence conf;
        };
        memory::vector<candidate_entry> entries;

        for (const auto &scheme : registry.all())
        {
            if (!scheme->is_enabled(*ctx.cfg))
                continue;

            auto [confidence, reason] = scheme->detect(features, *ctx.cfg);
            trace::debug("[Recognition] Scheme '{}': confidence={}, reason={}",
                         scheme->name(), static_cast<int>(confidence), reason);

            // confidence 枚举：high=0, medium=1, low=2, none=3
            // 只排除 none（值最大）
            if (confidence != confidence::none)
                entries.push_back({memory::string(scheme->name()), confidence});
        }
        auto func = [](const auto &a, const auto &b)
        {
            return a.conf < b.conf;
        };

        // 按置信度排序（值小的在前：high → medium → low）
        std::ranges::sort(entries, std::move(func));

        memory::vector<memory::string> candidates;
        candidates.reserve(entries.size());
        for (auto &[name, conf] : entries)
            candidates.push_back(std::move(name));

        // Phase 4: 构建 preview transport
        auto preread_span = std::span(reinterpret_cast<const std::byte *>(raw_record.data()), raw_record.size());
        auto preview_transport = std::make_shared<pipeline::primitives::preview>(
            ctx.transport, preread_span, ctx.frame_arena ? ctx.frame_arena->get() : memory::current_resource());

        // Phase 5: 按候选顺序执行 scheme
        stealth::scheme_context scheme_ctx{
            .inbound = preview_transport,
            .cfg = ctx.cfg,
            .router = ctx.router,
            .session = ctx.session};

        auto executor = stealth::scheme_executor(registry);

        analysis_result analysis;
        analysis.candidates = std::move(candidates);

        auto scheme_result = co_await executor.execute_by_analysis(analysis, std::move(scheme_ctx));

        result.transport = std::move(scheme_result.transport);
        result.detected = scheme_result.detected;
        result.preread = std::move(scheme_result.preread);
        result.error = scheme_result.error;
        result.executed_scheme = std::move(scheme_result.executed_scheme);
        result.success = !fault::failed(scheme_result.error);

        if (result.success)
        {
            trace::debug("[Recognition] Identify succeeded: scheme={}, protocol={}",
                         result.executed_scheme, static_cast<int>(result.detected));
        }
        else
        {
            trace::warn("[Recognition] Identify failed: error={}", fault::describe(result.error));
        }

        co_return result;
    }

    auto recognize(const recognize_context ctx) -> net::awaitable<recognize_result>
    {
        recognize_result result;

        trace::debug("[Recognition] Starting recognize lifecycle");

        if (!ctx.transport)
        {
            trace::error("[Recognition] transport is null");
            result.error = fault::code::not_supported;
            co_return result;
        }

        auto probe_res = co_await probe::probe(*ctx.transport, 24);
        if (fault::failed(probe_res.ec))
        {
            trace::warn("[Recognition] Probe failed: {}", fault::describe(probe_res.ec));
            result.error = probe_res.ec;
            co_return result;
        }

        trace::debug("[Recognition] Probe result: type={}", protocol::to_string_view(probe_res.type));

        result.detected = probe_res.type;
        result.preread.assign(probe_res.pre_read_data.begin(), probe_res.pre_read_data.begin() + probe_res.pre_read_size);

        if (probe_res.type == protocol::protocol_type::tls)
        {
            const auto preread_span = probe_res.preload_bytes();

            auto id_result = co_await identify(identify_context{
                .transport = ctx.transport,
                .cfg = ctx.cfg,
                .preread = preread_span,
                .router = ctx.router,
                .session = ctx.session,
                .frame_arena = ctx.frame_arena});

            if (id_result.success)
            {
                result.transport = std::move(id_result.transport);
                result.detected = id_result.detected;
                result.preread = std::move(id_result.preread);
                result.executed_scheme = std::move(id_result.executed_scheme);
                result.success = true;

                trace::debug("[Recognition] Recognize succeeded: scheme={}, protocol={}",
                             result.executed_scheme, protocol::to_string_view(result.detected));
            }
            else
            {
                result.error = id_result.error;
                trace::warn("[Recognition] Identify failed: {}", fault::describe(result.error));
            }
        }
        else
        {
            result.transport = ctx.transport;
            result.success = probe_res.success();

            trace::debug("[Recognition] Recognize succeeded (non-TLS): protocol={}",
                         protocol::to_string_view(result.detected));
        }

        co_return result;
    }

} // namespace psm::recognition
