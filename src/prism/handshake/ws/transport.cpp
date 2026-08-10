/**
 * @file transport.cpp
 * @brief WebSocket 帧传输装饰器实现
 */

#include <prism/handshake/ws/transport.hpp>
#include <prism/protocol/common/read.hpp>

#include <cstring>

namespace psm::handshake::ws
{

    transport::transport(psm::transport::shared_transmission next_layer,
                         const memory::resource_pointer mr)
        : next_layer_(std::move(next_layer))
        , mr_(mr)
        , frame_buf_(mr_)
    {
    }

    auto transport::executor() const -> executor_type
    {
        return next_layer_->executor();
    }

    auto transport::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        // 当前帧消费完则解析下一帧
        while (frame_offset_ >= frame_buf_.size())
        {
            if (closed_)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }

            // 从累积缓冲解析完整帧
            memory::vector<std::byte> raw(mr_);
            while (true)
            {
                // 防恶意客户端无限累积（内存上限 4MB）
                if (raw.size() > 4 * 1024 * 1024)
                {
                    ec = std::make_error_code(std::errc::message_size);
                    co_return 0;
                }
                codec::frame_header header;
                if (codec::parse_frame_header(raw, header))
                {
                    const auto total = header.header_len + static_cast<std::size_t>(header.payload_len);
                    if (raw.size() >= total)
                    {
                        // 完整帧：处理控制帧
                        if (header.opcode == static_cast<std::uint8_t>(codec::opcode::close))
                        {
                            ec = psm::fault::make_error_code(psm::fault::code::eof);
                            co_return 0;
                        }
                        if (header.opcode == static_cast<std::uint8_t>(codec::opcode::ping))
                        {
                            // 回 pong（不 mask）
                            std::array<std::byte, 2> pong{std::byte{0x8A}, std::byte{0x00}};
                            std::error_code w_ec;
                            co_await next_layer_->async_write_some(pong, w_ec);
                            // 消费该帧后继续
                            raw.erase(raw.begin(),
                                      raw.begin() + static_cast<std::ptrdiff_t>(total));
                            continue;
                        }

                        if (header.opcode != static_cast<std::uint8_t>(codec::opcode::binary) &&
                            header.opcode != static_cast<std::uint8_t>(codec::opcode::text) &&
                            header.opcode != static_cast<std::uint8_t>(codec::opcode::continuation))
                        {
                            // 未知控制帧：跳过载荷
                            raw.erase(raw.begin(),
                                      raw.begin() + static_cast<std::ptrdiff_t>(total));
                            continue;
                        }

                        // 提取载荷
                        frame_buf_.assign(
                            raw.begin() + static_cast<std::ptrdiff_t>(header.header_len),
                            raw.begin() + static_cast<std::ptrdiff_t>(total));
                        raw.erase(raw.begin(),
                                  raw.begin() + static_cast<std::ptrdiff_t>(total));

                        // 客户端掩码去掩码
                        if (header.masked)
                        {
                            for (std::size_t i = 0; i < frame_buf_.size(); ++i)
                            {
                                frame_buf_[i] = static_cast<std::byte>(
                                    static_cast<std::uint8_t>(frame_buf_[i])
                                    ^ header.mask[i % 4]);
                            }
                        }
                        frame_offset_ = 0;
                        break;
                    }
                }

                // 需要更多数据
                std::array<std::byte, 2048> chunk{};
                std::error_code read_ec;
                const auto n = co_await next_layer_->async_read_some(chunk, read_ec);
                if (read_ec || n == 0)
                {
                    ec = read_ec ? read_ec : std::make_error_code(std::errc::bad_message);
                    co_return 0;
                }
                raw.insert(raw.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            }
        }

        // 消费当前帧
        const auto n = std::min(buffer.size(), frame_buf_.size() - frame_offset_);
        std::memcpy(buffer.data(), frame_buf_.data() + frame_offset_, n);
        frame_offset_ += n;
        ec = {};
        co_return n;
    }

    auto transport::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (closed_)
        {
            ec = std::make_error_code(std::errc::not_connected);
            co_return 0;
        }

        // 封装 binary 帧（服务端不掩码）
        memory::vector<std::byte> frame(mr_);
        frame.resize(14 + buffer.size());
        const auto encoded = codec::encode_frame(codec::opcode::binary, true, buffer, frame);
        if (encoded == 0)
        {
            ec = std::make_error_code(std::errc::message_size);
            co_return 0;
        }
        frame.resize(encoded);

        co_await psm::transport::async_write(*next_layer_, frame, ec);
        if (ec)
            co_return 0;
        co_return buffer.size();
    }

    void transport::close()
    {
        closed_ = true;
        if (next_layer_)
            next_layer_->close();
    }

    void transport::cancel()
    {
        closed_ = true;
        if (next_layer_)
            next_layer_->cancel();
    }

} // namespace psm::handshake::ws
