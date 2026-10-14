#pragma once

/**
 * @file AnytlsSessionDeepSupport.hpp
 * @brief AnyTLS 会话测试共享帧构造辅助。
 */

namespace
{
    auto make_frame_bytes(anytls::command cmd, std::uint32_t stream_id,
                          std::span<const std::uint8_t> payload = {}) -> std::vector<std::byte>
    {
        anytls::frame_header hdr;
        hdr.cmd = cmd;
        hdr.stream_id = stream_id;
        hdr.length = static_cast<std::uint16_t>(payload.size());
        auto ser = hdr.serialize();
        std::vector<std::byte> out;
        out.reserve(7 + payload.size());
        for (auto b : ser)
        {
            out.push_back(static_cast<std::byte>(b));
        }
        for (auto b : payload)
        {
            out.push_back(static_cast<std::byte>(b));
        }
        return out;
    }

    auto make_settings_payload(std::string_view text) -> std::vector<std::uint8_t>
    {
        return {text.begin(), text.end()};
    }

    struct SessionFixture
    {
        std::shared_ptr<ProductionMockTransport> transport;
        std::shared_ptr<anytls::anytls_session> session;
        anytls::anytls_session::stream_callback last_callback;
        bool callback_called{false};
        std::uint32_t cb_stream_id{0};
        std::shared_ptr<psm::transport::transmission> cb_transport;
        psm::memory::vector<std::uint8_t> cb_preread;

        SessionFixture() : cb_preread(psm::memory::current_resource())
        {
        }

        void init(std::shared_ptr<anytls::padding_factory> padding = nullptr)
        {
            transport = std::make_shared<ProductionMockTransport>();
            auto cb = [this](std::uint32_t sid, std::shared_ptr<psm::transport::transmission> trans,
                             psm::memory::vector<std::uint8_t> preread)
            {
                callback_called = true;
                cb_stream_id = sid;
                cb_transport = std::move(trans);
                cb_preread = std::move(preread);
            };
            session = std::make_shared<anytls::anytls_session>(transport, std::move(padding), std::move(cb));
        }

        auto &ioc()
        {
            return transport->GetIoContext();
        }
    };

    // ─── constructor + close + get_stream_channel ──
} // namespace

