/**
 * @file Conn.hpp
 * @brief gRPC (gun) 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 gun 连接（对齐 mihomo transport/gun）：
 * 1. WriteHandshake / ReadHandshake：HTTP/2 CONNECT 握手（简化）
 * 2. 数据面：gun-lite 模式裸透传（帧编解码由上层 h2 会话负责，
 *    Codec.hpp 纯函数供需要帧边界的测试直接使用）
 * @note 与 gun.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Gun/Codec.hpp>
#include <preview/Protocols/Gun/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Gun
{

    /**
     * @class Conn
     * @brief gRPC (gun) 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
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
        [[nodiscard]] auto Executor() const 
            -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发送 CONNECT 帧（简化）
         * @param host 目标主机
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(std::string_view host)
            -> net::awaitable<Error>
        {
            const std::string Header = "CONNECT " + std::string(host) + " HTTP/2\r\n\r\n";
            if (co_await SendBytes(AsU8Span(Header)))
                co_return Error::IoError;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析 CONNECT 帧（简化）
         * @param host 输出目标主机
         * @return 错误码；bad_magic = 非 CONNECT 帧
         */
        [[nodiscard]] auto ReadHandshake(std::string &host)
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
            if (Header.find("CONNECT ") != 0)
                co_return Error::BadMagic;
            const auto FirstLineEnd = Header.find("\r\n");
            host = Header.substr(8, FirstLineEnd - 8);
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样）
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
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
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
        [[nodiscard]] auto NextLayer() noexcept
            -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept 
            -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() 
            -> SharedTransmission override
        {
            return std::move(NextLayer_);
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
        bool Handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Gun
