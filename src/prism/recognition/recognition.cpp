/**
 * @file recognition.cpp
 * @brief Recognition 模块入口
 * @details 实现完整的协议识别生命周期：读取 → 解析 → 分析 → 分流 → 执行。
 */

#include <prism/recognition/recognition.hpp>
#include <prism/stealth/reality/request.hpp>
#include <prism/stealth/reality/constants.hpp>
#include <prism/stealth.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>
#include <prism/pipeline/primitives.hpp>
#include <cstring>

namespace psm::recognition
{
    namespace tls = stealth::reality::tls;

    /**
     * @brief 读取完整 TLS ClientHello 记录
     */
    auto read_arrival(const channel::transport::shared_transmission transport, const std::span<const std::byte> preread)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
    {
        if (!transport)
        {
            trace::error("[Recognition] transport is null");
            co_return std::pair{fault::code::not_supported, memory::vector<std::uint8_t>{}};
        }

        // 如果预读数据不足 5 字节，先补读
        if (constexpr std::size_t MIN_HEADER_SIZE = 5; preread.size() < MIN_HEADER_SIZE)
        {
            trace::debug("[Recognition] preread too small ({} bytes), need at least 5", preread.size());

            memory::vector<std::uint8_t> buffer(MIN_HEADER_SIZE);
            std::memcpy(buffer.data(), preread.data(), preread.size());

            std::size_t read_offset = preread.size();
            while (read_offset < MIN_HEADER_SIZE)
            {
                std::error_code ec;
                const auto buf_span = std::span(reinterpret_cast<std::byte *>(buffer.data() + read_offset), MIN_HEADER_SIZE - read_offset);
                const auto n = co_await transport->async_read_some(buf_span, ec);
                if (ec || n == 0)
                {
                    trace::error("[Recognition] read header failed: {}", ec.message());
                    co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
                }
                read_offset += n;
            }

            const auto record_length = static_cast<std::uint16_t>(buffer[3]) << 8 | static_cast<std::uint16_t>(buffer[4]);
            const std::size_t total = MIN_HEADER_SIZE + record_length;
            buffer.resize(total);

            while (read_offset < total)
            {
                std::error_code ec;
                const auto buf_span = std::span(reinterpret_cast<std::byte *>(buffer.data() + read_offset), total - read_offset);
                const auto n = co_await transport->async_read_some(buf_span, ec);
                if (ec || n == 0)
                {
                    trace::error("[Recognition] read body failed: {}", ec.message());
                    co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
                }
                read_offset += n;
            }

            co_return std::pair{fault::code::success, std::move(buffer)};
        }

        // 预读数据已足够解析 header
        const auto *raw = reinterpret_cast<const std::uint8_t *>(preread.data());

        if (const auto content_type = raw[0]; content_type != tls::CONTENT_TYPE_HANDSHAKE)
        {
            trace::error("[Recognition] not a handshake record: 0x{:02x}", content_type);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        const auto record_length = static_cast<std::uint16_t>(raw[3]) << 8 | static_cast<std::uint16_t>(raw[4]);

        if (record_length > tls::MAX_RECORD_PAYLOAD)
        {
            trace::error("[Recognition] record too large: {}", record_length);
            co_return std::pair{fault::code::reality_tls_record_error, memory::vector<std::uint8_t>{}};
        }

        const std::size_t total = tls::RECORD_HEADER_LEN + record_length;

        // 预读数据已包含完整 ClientHello
        if (preread.size() >= total)
        {
            trace::debug("[Recognition] preread contains full ClientHello ({} bytes)", total);
            memory::vector<std::uint8_t> buffer(total);
            std::memcpy(buffer.data(), raw, total);
            co_return std::pair{fault::code::success, std::move(buffer)};
        }

        // 需要补读剩余数据
        trace::debug("[Recognition] preread partial ({} bytes), need {} total", preread.size(), total);

        memory::vector<std::uint8_t> buffer(total);
        std::memcpy(buffer.data(), raw, preread.size());

        std::size_t read_offset = preread.size();
        while (read_offset < total)
        {
            std::error_code ec;
            const auto buf_span = std::span(reinterpret_cast<std::byte *>(buffer.data() + read_offset), total - read_offset);
            const auto n = co_await transport->async_read_some(buf_span, ec);
            if (ec || n == 0)
            {
                trace::error("[Recognition] read remaining failed at offset {}: {}", read_offset, ec.message());
                co_return std::pair{fault::to_code(ec), memory::vector<std::uint8_t>{}};
            }
            read_offset += n;
        }

        co_return std::pair{fault::code::success, std::move(buffer)};
    }

    /**
     * @brief 解析 TLS ClientHello 并提取特征
     */
    [[nodiscard]] auto parse_arrival(const std::span<const std::uint8_t> raw_arrival)
        -> arrival_features
    {
        arrival_features features;

        auto [error, info] = stealth::reality::parse_client_hello(raw_arrival);
        if (fault::failed(error))
        {
            trace::error("[Recognition] parse_arrival failed: {}", fault::describe(error));
            return features;
        }

        features.server_name = memory::string(info.server_name);
        features.session_id_len = static_cast<std::uint8_t>(info.session_id.size());
        features.session_id.assign(info.session_id.begin(), info.session_id.end());
        features.has_x25519_key_share = info.has_client_public_key;
        if (info.has_client_public_key)
        {
            features.x25519_public_key = info.client_public_key;
        }
        features.supported_versions.assign(info.supported_versions.begin(), info.supported_versions.end());
        features.random = info.random;
        features.raw_handshake_message.assign(info.raw_message.begin(), info.raw_message.end());

        features.raw_arrival.resize(raw_arrival.size());
        std::memcpy(features.raw_arrival.data(), raw_arrival.data(), raw_arrival.size());

        trace::debug("[Recognition] ClientHello parsed: SNI='{}', session_id_len={}, x25519={}",
                     features.server_name, features.session_id_len, features.has_x25519_key_share);

        return features;
    }

    /**
     * @brief 执行完整的协议识别生命周期
     */
    auto identify(identify_context ctx) -> net::awaitable<identify_result>
    {
        identify_result result;

        trace::debug("[Recognition] Starting identify lifecycle");

        // ═══════════════════════════════════════════════════════════════
        // Phase 1: Read（读取 ClientHello）
        // ═══════════════════════════════════════════════════════════════
        auto [read_ec, raw_arrival] = co_await read_arrival(ctx.transport, ctx.preread);
        if (fault::failed(read_ec))
        {
            trace::error("[Recognition] read_arrival failed: {}", fault::describe(read_ec));
            result.error = read_ec;
            co_return result;
        }

        trace::debug("[Recognition] Read {} bytes ClientHello", raw_arrival.size());

        // ═══════════════════════════════════════════════════════════════
        // Phase 2: Parse（解析特征）
        // ═══════════════════════════════════════════════════════════════
        auto features = parse_arrival(raw_arrival);
        if (features.server_name.empty() && features.raw_arrival.empty())
        {
            trace::error("[Recognition] parse failed, empty features");
            result.error = fault::code::reality_tls_record_error;
            co_return result;
        }

        // ═══════════════════════════════════════════════════════════════
        // Phase 3: Analyze（分析置信度）
        // ═══════════════════════════════════════════════════════════════
        auto &registry = arrival::analyzer_registry::instance();
        auto analysis = registry.analyze(features, *ctx.cfg);

        trace::debug("[Recognition] Analysis result: confidence={}, candidates={}",
                     static_cast<int>(analysis.confidence), analysis.candidates.size());

        // ═══════════════════════════════════════════════════════════════
        // Phase 4: 构建执行上下文
        // ═══════════════════════════════════════════════════════════════
        auto preread_span = std::span(reinterpret_cast<const std::byte *>(raw_arrival.data()), raw_arrival.size());

        // 包装传输层，包含已读取的 ClientHello
        auto preview_transport = std::make_shared<pipeline::primitives::preview>(
            ctx.transport, preread_span, ctx.frame_arena ? ctx.frame_arena->get() : memory::current_resource());

        stealth::scheme_context scheme_ctx{
            .inbound = preview_transport,
            .cfg = ctx.cfg,
            .router = ctx.router,
            .session = ctx.session};

        // ═══════════════════════════════════════════════════════════════
        // Phase 5: Dispatch & Execute（分流执行）
        // ═══════════════════════════════════════════════════════════════
        auto executor = handshake::scheme_executor::create_default();
        auto [scheme_result, executed_scheme, success] = co_await executor->execute_by_analysis(analysis, std::move(scheme_ctx));

        // ═══════════════════════════════════════════════════════════════
        // Phase 6: 返回结果
        // ═══════════════════════════════════════════════════════════════
        result.transport = std::move(scheme_result.transport);
        result.detected = scheme_result.detected;
        result.preread = std::move(scheme_result.preread);
        result.error = scheme_result.error;
        result.executed_scheme = std::move(executed_scheme);
        result.success = success;

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

    // ═══════════════════════════════════════════════════════════════════════
    // 统一入口：recognize()
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @brief 执行完整协议识别流程
     * @details 封装外层探测 + TLS 伪装方案识别
     */
    auto recognize(const recognize_context ctx) -> net::awaitable<recognize_result>
    {
        recognize_result result;

        trace::debug("[Recognition] Starting recognize lifecycle");

        // ═══════════════════════════════════════════════════════════════
        // Phase 1: Probe（外层协议探测）
        // ═══════════════════════════════════════════════════════════════
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

        // 保存探测结果
        result.detected = probe_res.type;
        result.preread.assign(probe_res.pre_read_data.begin(), probe_res.pre_read_data.begin() + probe_res.pre_read_size);

        // ═══════════════════════════════════════════════════════════════
        // Phase 2: Identify（仅当 TLS）
        // ═══════════════════════════════════════════════════════════════
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
            // 非 TLS 协议，探测成功即识别成功
            result.transport = ctx.transport;
            result.success = probe_res.success();

            trace::debug("[Recognition] Recognize succeeded (non-TLS): protocol={}",
                         protocol::to_string_view(result.detected));
        }

        co_return result;
    }

} // namespace psm::recognition