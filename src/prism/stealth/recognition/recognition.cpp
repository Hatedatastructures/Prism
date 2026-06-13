#include <prism/stealth/recognition/recognition.hpp>

#include <prism/stealth/recognition/pipeline.hpp>
#include <prism/stealth/recognition/routes.hpp>
#include <prism/stealth/recognition/tls/signal.hpp>
#include <prism/stealth/stealth.hpp>
#include <prism/stealth/executor.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <algorithm>

using namespace psm::trace;

namespace psm::recognition
{

    auto identify(identify_context ctx)
        -> net::awaitable<identify_result>
    {
        identify_result result;

        auto *pfx = trace::active_prefix;

        trace::debug<flt::conn | flt::protocol>("starting identify lifecycle");

        // Phase 1: 读取完整 ClientHello
        auto [read_ec, raw_record] = co_await recognition::tls::read_tls_record(*ctx.transport, ctx.preread);
        if (fault::failed(read_ec))
        {
            trace::error<flt::conn | flt::protocol>(
                "read_tls_record failed: {}", fault::describe(read_ec));
            result.error = read_ec;
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>("read {} bytes ClientHello", raw_record.size());

        // Phase 2: 解析 ClientHello 特征
        auto [parse_ec, features] = recognition::tls::parse_client_hello(raw_record);
        if (fault::failed(parse_ec))
        {
            trace::error<flt::conn | flt::protocol>(
                "parse_client_hello failed: {}", fault::describe(parse_ec));
            result.error = parse_ec;
            co_return result;
        }

        // Phase 3: SNI 路由匹配
        auto route_table = route_table::build(*ctx.cfg);
        auto matched_scheme_names = route_table.lookup(features.server_name);

        // 从 registry 获取匹配的 scheme 实例
        auto &registry = stealth::scheme_registry::instance();
        std::vector<stealth::shared_scheme> matched_schemes;
        for (const auto &name : matched_scheme_names)
        {
            auto scheme = registry.find(std::string_view(name));
            if (scheme && scheme->active(*ctx.cfg))
                matched_schemes.push_back(scheme);
        }

        // Phase 4: 分层检测
        auto raw_ch_span = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(raw_record.data()), raw_record.size());
        auto bitmap = recognition::tls::build_bitmap(features);

        auto pipeline = layered_detection_pipeline(registry.all());
        auto pipeline_result = pipeline.detect(
            detect_input{bitmap, features, raw_ch_span, *ctx.cfg},
            matched_schemes);

        // Phase 5: 构建 preview transport
        auto preread_span = std::span(reinterpret_cast<const std::byte *>(raw_record.data()), raw_record.size());
        auto preview_transport = std::make_shared<transport::preview>(
            ctx.transport, preread_span);

        // Phase 6: 按候选顺序执行 scheme
        memory::vector<std::byte> preread_bytes(raw_record.size());
        std::transform(raw_record.begin(), raw_record.end(), preread_bytes.begin(),
                       [](std::uint8_t b)
                       { return static_cast<std::byte>(b); });

        stealth::handshake_context scheme_ctx{
            .inbound = preview_transport,
            .cfg = ctx.cfg,
            .router = ctx.router,
            .session = ctx.session,
            .session_keepalive = std::move(ctx.session_keepalive),
            .preread = std::move(preread_bytes)};

        auto executor = stealth::scheme_executor(registry);

        // 确定性命中：直接执行
        if (pipeline_result.deterministic_hit)
        {
            trace::debug<flt::conn | flt::protocol>(
                "deterministic hit: {}", pipeline_result.exclusive_scheme);
            memory::vector<memory::string> single_candidate;
            single_candidate.push_back(pipeline_result.exclusive_scheme);

            auto scheme_result = co_await executor.execute(single_candidate, std::move(scheme_ctx));
            result.transport = std::move(scheme_result.transport);
            result.detected = scheme_result.detected;
            result.preread = std::move(scheme_result.preread);
            result.error = scheme_result.error;
            result.executed_scheme = std::move(scheme_result.scheme);
            result.success = !fault::failed(scheme_result.error);

            // 写入 scheme 名到 prefix
            if (result.success && pfx && !result.executed_scheme.empty())
            {
                std::strncpy(pfx->scheme_name, result.executed_scheme.c_str(),
                             sizeof(pfx->scheme_name) - 1);
            }

            co_return result;
        }

        // 多候选：按顺序执行
        memory::vector<memory::string> candidates;
        candidates.reserve(pipeline_result.candidates.size());
        for (const auto &entry : pipeline_result.candidates)
            candidates.push_back(entry.name);

        analysis_result analysis;
        analysis.candidates = std::move(candidates);

        auto scheme_result = co_await executor.execute_by_analysis(analysis, std::move(scheme_ctx));

        result.transport = std::move(scheme_result.transport);
        result.detected = scheme_result.detected;
        result.preread = std::move(scheme_result.preread);
        result.error = scheme_result.error;
        result.executed_scheme = std::move(scheme_result.scheme);
        result.success = !fault::failed(scheme_result.error);

        if (result.success)
        {
            // 写入 scheme 名到 prefix
            if (pfx && !result.executed_scheme.empty())
            {
                std::strncpy(pfx->scheme_name, result.executed_scheme.c_str(),
                             sizeof(pfx->scheme_name) - 1);
            }
            trace::debug<flt::conn | flt::protocol>(
                "identify succeeded: {} -> {}",
                result.executed_scheme,
                protocol::to_string_view(result.detected));
        }
        else
        {
            trace::warn<flt::conn | flt::protocol>(
                "identify failed: {}", fault::describe(result.error));
        }

        co_return result;
    }

    auto recognize(const recognize_context ctx)
        -> net::awaitable<recognize_result>
    {
        recognize_result result;

        if (!ctx.transport)
        {
            trace::error<flt::conn | flt::protocol>("transport is null");
            result.error = fault::code::not_supported;
            co_return result;
        }

        auto probe_res = co_await probe::probe(*ctx.transport, 24);
        if (fault::failed(probe_res.ec))
        {
            trace::warn<flt::conn | flt::protocol>(
                "probe failed: {}", fault::describe(probe_res.ec));
            result.error = probe_res.ec;
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>("probe result: {}", protocol::to_string_view(probe_res.type));

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
                .session_keepalive = std::move(ctx.session_keepalive),
                .frame_arena = ctx.frame_arena});

            if (id_result.success)
            {
                result.transport = std::move(id_result.transport);
                result.detected = id_result.detected;
                result.preread = std::move(id_result.preread);
                result.executed_scheme = std::move(id_result.executed_scheme);
                result.success = true;

                trace::info<flt::conn | flt::protocol>(
                    "recognized: {} -> {}",
                    result.executed_scheme,
                    protocol::to_string_view(result.detected));
            }
            else
            {
                result.error = id_result.error;
                trace::warn<flt::conn | flt::protocol>(
                    "identify failed: {}", fault::describe(result.error));
            }
        }
        else
        {
            result.transport = ctx.transport;
            result.success = probe_res.success();

            trace::debug<flt::conn | flt::protocol>(
                "recognized (non-TLS): {}", protocol::to_string_view(result.detected));
        }

        co_return result;
    }

} // namespace psm::recognition
