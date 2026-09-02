/**
 * @file Dgram.hpp
 * @brief VMess UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层流连接（Vmess::Conn，chunk 即包
 * 边界）包装为包级 API。包级 API 无地址参数（目标固定来自指令头）。
 * 一次 AsyncSendTo = 加密并发送一个数据分块（长度密文 + 载荷
 * 密文）；AsyncReceiveFrom 读到该分块即完整数据报。
 * @note 继承 Preview::Transmission，构造函数传入底层流连接（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Vmess/Conn.hpp>

namespace Preview::Vmess
{

    /**
     * @class Dgram
     * @brief VMess UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层流连接（Vmess::Conn，已握手）的独占所有权，
     * 对外暴露包级 API（AsyncSendTo / AsyncReceiveFrom）。
     * 由工厂（ConnectPacket / AcceptPacket）创建。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission, public std::enable_shared_from_this<Dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Stream 底层流连接（已握手，所有权移交）
         */
        explicit Dgram(SharedTransmission Stream) : NextLayer_(std::move(Stream))
        {
        }

        /**
         * @brief 获取执行器（委托底层流连接）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 传输类型（经底层委托，TCP 承载数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（加密一个 chunk）
         * @param payload 数据报载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(std::span<const std::uint8_t> payload) -> net::awaitable<Error>
        {
            return AsyncSendDatagramImpl(payload);
        }

        /**
         * @brief 接收一个 UDP 数据报（解密一个 chunk）
         * @param payload 输出数据报载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(std::vector<std::uint8_t> &payload) -> net::awaitable<Error>
        {
            return AsyncReceiveDatagramImpl(payload);
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（底层流原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层流连接
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
         * @brief 获取底层流连接
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        /**
         * @brief 转调底层数据报发送（chunk 加密）
         */
        [[nodiscard]] auto AsyncSendDatagramImpl(std::span<const std::uint8_t> payload)
            -> net::awaitable<Error>
        {
            auto *c = dynamic_cast<Conn<Memory> *>(NextLayer_.get());
            if (!c)
            {
                co_return Error::NotOpen;
            }
            co_return co_await c->AsyncSendDatagram(payload);
        }

        /**
         * @brief 转调底层数据报接收（chunk 解密）
         */
        [[nodiscard]] auto AsyncReceiveDatagramImpl(std::vector<std::uint8_t> &payload)
            -> net::awaitable<Error>
        {
            auto *c = dynamic_cast<Conn<Memory> *>(NextLayer_.get());
            if (!c)
            {
                co_return Error::NotOpen;
            }
            co_return co_await c->AsyncReceiveDatagram(payload);
        }

        SharedTransmission NextLayer_; ///< 底层流连接（嵌入，同一条 TCP）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Vmess
