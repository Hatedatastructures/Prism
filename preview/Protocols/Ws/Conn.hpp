/**
 * @file Conn.hpp
 * @brief WebSocket 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 WebSocket 连接（对齐 mihomo transport/ws）：
 * 1. WriteHandshake / ReadHandshake：HTTP 升级握手
 *    （Sec-WebSocket-Key/Accept 交换）
 * 2. 数据面：帧编解码（Codec.hpp 纯函数），本类负责帧边界恢复
 * @note 与 ws.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Ws/Codec.hpp>
#include <preview/Protocols/Ws/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Ws
{

    /**
     * @class Conn
     * @brief WebSocket 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面
     * 为帧边界恢复后的裸流。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission,
                 public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;
        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         */
        explicit Conn(SharedTransmission upstream)
            : NextLayer_(std::move(upstream))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发送 Upgrade 请求并等待 101 响应
         * @param key Sec-WebSocket-Key（base64 24 字符）
         * @param host 目标主机
         * @return 错误码；bad_auth = Accept 不匹配
         */
        [[nodiscard]] auto WriteHandshake(std::string_view key, std::string_view host)
        -> net::awaitable<Error>
        {
            std::string Header;
            Header.reserve(128 + host.size() + key.size());
            Header += "GET / HTTP/1.1\r\n";
            Header += "Host: " + std::string(host) + "\r\n";
            Header += "Upgrade: websocket\r\n";
            Header += "Connection: Upgrade\r\n";
            Header += "Sec-WebSocket-Key: " + std::string(key) + "\r\n";
            Header += "Sec-WebSocket-Version: 13\r\n";
            Header += "\r\n";
            if (co_await SendBytes(AsU8Span(Header)))
                co_return Error::IoError;

            // 等待 101 响应并校验 Accept
            std::array<std::uint8_t, 256> chunk{};
            std::string resp;
            for (int I = 0; I < 16; ++I)
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || N == 0)
                    break;
                resp.append(reinterpret_cast<const char *>(chunk.data()), N);
                if (resp.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            if (resp.find("101") == std::string::npos)
                co_return Error::BadMagic;
            const auto Expected = ComputeAccept(key);
            if (resp.find("Sec-WebSocket-Accept: " + Expected) == std::string::npos)
                co_return Error::BadAuth;
            Accept_ = Expected;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析 Upgrade 请求并回复 Accept
         * @param key 输出客户端 Sec-WebSocket-Key
         * @return 错误码；bad_magic = 非 Upgrade 请求
         */
        [[nodiscard]] auto ReadHandshake(std::string &key)
        -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 256> chunk{};
            std::string Header;
            for (int I = 0; I < 16; ++I)
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || N == 0)
                    break;
                Header.append(reinterpret_cast<const char *>(chunk.data()), N);
                if (Header.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            if (Header.find("Upgrade: websocket") == std::string::npos)
                co_return Error::BadMagic;

            const auto KeyPos = Header.find("Sec-WebSocket-Key: ");
            if (KeyPos == std::string::npos)
                co_return Error::BadMagic;
            const auto KeyStart = KeyPos + 19;
            const auto KeyEnd = Header.find("\r\n", KeyStart);
            key = Header.substr(KeyStart, KeyEnd - KeyStart);

            const auto Accept = ComputeAccept(key);
            std::string resp = "HTTP/1.1 101 Switching Protocols\r\n";
            resp += "Upgrade: websocket\r\n";
            resp += "Connection: Upgrade\r\n";
            resp += "Sec-WebSocket-Accept: " + Accept + "\r\n";
            resp += "\r\n";
            if (co_await SendBytes(AsU8Span(resp)))
                co_return Error::IoError;
            Accept_ = Accept;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（帧边界恢复后的裸流）
         * @details 简化：直接透传底层数据（帧编解码由上层负责）。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取 Sec-WebSocket-Accept（握手后有效）
         */
        [[nodiscard]] auto Accept() const -> const std::string &
        {
            return Accept_;
        }

    private:
        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
        -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_write_some(AsBytes(Data.subspan(Done)), ec);
                if (ec)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        std::string Accept_;              ///< Sec-WebSocket-Accept（握手后）
        bool Handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Ws
