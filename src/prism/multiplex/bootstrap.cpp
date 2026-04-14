#include <prism/multiplex/bootstrap.hpp>
#include <prism/multiplex/smux/craft.hpp>
#include <prism/multiplex/yamux/craft.hpp>
#include <prism/trace.hpp>

constexpr std::string_view tag = "[Mux.Bootstrap]";

using transmission = psm::channel::transport::transmission;

namespace psm::multiplex
{
    namespace
    {
        /**
         * @brief 执行 sing-mux 协议协商
         * @param transport 已建立的传输层连接
         * @param mr PMR 内存资源，用于 padding 缓冲区分配
         * @return 协商结果对：(error_code, protocol_type)，成功时 error_code 为空
         * @details 从 transport 读取 sing-mux 协议头并消费。Protocol 字段指示
         * 客户端选择的多路复用协议类型（0=smux, 1=yamux）。
         */
        auto negotiate(transmission &transport, const memory::resource_pointer mr)
            -> net::awaitable<std::pair<std::error_code, protocol_type>>
        {
            std::error_code ec;

            // 读取协议头：[Version 1B][Protocol 1B]
            std::array<std::byte, 2> header{};
            const auto n = co_await transport.async_read(header, ec);
            if (ec)
            {
                co_return std::make_pair(ec, protocol_type::smux);
            }
            if (n < 2)
            {
                co_return std::make_pair(std::make_error_code(std::errc::connection_reset), protocol_type::smux);
            }

            // 解析客户端选择的协议类型
            const auto protocol = static_cast<protocol_type>(header[1]);

            // Version > 0 表示有 padding
            if (const auto version = static_cast<std::uint8_t>(header[0]); version > 0)
            {
                // 读取 2 字节 padding 长度（大端序）
                std::array<std::byte, 2> padding_len_buf{};
                const auto pn = co_await transport.async_read(padding_len_buf, ec);
                if (ec)
                {
                    co_return std::make_pair(ec, protocol_type::smux);
                }
                if (pn < 2)
                {
                    co_return std::make_pair(std::make_error_code(std::errc::connection_reset), protocol_type::smux);
                }

                const auto padding_len = static_cast<std::uint16_t>(padding_len_buf[0]) << 8 | static_cast<std::uint16_t>(padding_len_buf[1]);
                if (padding_len > 0)
                {
                    memory::vector<std::byte> padding(mr);
                    padding.resize(padding_len);
                    const auto padding_n = co_await transport.async_read(padding, ec);
                    if (ec || padding_n < padding_len)
                    {
                        co_return std::make_pair(ec ? ec : std::make_error_code(std::errc::connection_reset), protocol_type::smux);
                    }
                }
            }

            trace::debug("{} sing-mux handshake completed, protocol={}", tag, protocol == protocol_type::yamux ? "yamux" : "smux");
            co_return std::make_pair(std::error_code{}, protocol);
        }
    } // namespace

    auto bootstrap(channel::transport::shared_transmission transport, resolve::router &router, const config &cfg, memory::resource_pointer mr)
        -> net::awaitable<std::shared_ptr<core>>
    {
        // 执行 sing-mux 协商，获取客户端选择的协议类型
        auto [ec, protocol] = co_await negotiate(*transport, mr);
        if (ec)
        {
            trace::warn("{} sing-mux negotiate failed: {}", tag, ec.message());
            co_return nullptr;
        }

        // 根据协商结果创建对应协议实例
        try
        {
            switch (protocol)
            {
            case protocol_type::yamux:
                trace::info("{} constructing yamux session", tag);
                {
                    std::shared_ptr<core> session = std::make_shared<yamux::craft>(std::move(transport), router, cfg, mr);
                    trace::info("{} yamux session constructed", tag);
                    co_return session;
                }

            case protocol_type::smux:
            default:
                trace::info("{} constructing smux session", tag);
                {
                    std::shared_ptr<core> session = std::make_shared<smux::craft>(std::move(transport), router, cfg, mr);
                    trace::info("{} smux session constructed", tag);
                    co_return session;
                }
            }
        }
        catch (const std::exception &e)
        {
            trace::error("{} create_session exception: {}", tag, e.what());
            co_return nullptr;
        }
        catch (...)
        {
            trace::error("{} create_session unknown exception", tag);
            co_return nullptr;
        }
    }
} // namespace psm::multiplex
