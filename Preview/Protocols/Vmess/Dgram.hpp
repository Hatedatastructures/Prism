/**
 * @file Dgram.hpp
 * @brief VMess UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层流连接（Vmess::Conn，chunk 即包
 * 边界）包装为包级 API。包级 API 无地址参数（目标固定来自指令头）。
 * 一次 AsyncSendTo = 加密并发送一个数据分块（长度掩码 + 载荷
 * 密文）；AsyncReceiveFrom 读到该分块即完整数据报。
 * @note 继承 Preview::Transmission，构造函数传入底层流连接（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Contract/Io/PacketTransferResult.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vmess/Conn.hpp>

namespace Preview::Vmess
{

    /**
     * @class Dgram
     * @brief VMess UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层流连接（Vmess::Conn，已握手）的独占所有权，
     * 对外暴露固定目标包级 API（AsyncSendDatagram / AsyncReceiveDatagram）。
     * 由工厂（ConnectPacket / AcceptPacket）创建。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Stream 底层流连接（已握手，所有权移交）
         */
        explicit Dgram(SharedTransmission Stream)
            : Preview::Transmission(Stream ? Stream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Stream))
        {
        }

        /**
         * @brief 获取执行器（委托底层流连接）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Preview::Transmission::Executor();
            }
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
         * @brief 向握手固定目标发送一个 UDP 数据报（加密一个 chunk）。
         * @param Payload 数据报载荷
         * @return 载荷完成量、真实 chunk wire 完成量与完整 Failure/native cause。
         */
        [[nodiscard]] auto AsyncSendDatagram(
            std::span<const std::uint8_t> Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            return AsyncSendDatagramImpl(Payload);
        }

        /**
         * @brief 接收一个 UDP 数据报（解密一个 chunk）。
         * @param Payload 输出数据报载荷
         * @return 载荷完成量、真实 chunk wire 完成量与完整 Failure/native cause。
         */
        [[nodiscard]] auto AsyncReceiveDatagram(
            std::vector<std::uint8_t> &Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            return AsyncReceiveDatagramImpl(Payload);
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 透传写入（底层流原样）
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层流；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 关闭底层流连接
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /**
         * @brief 取消挂起操作
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
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

        /** @brief 返回此 VMess 数据报实际拥有的协议连接，用于读取认证会话事实。 */
        [[nodiscard]] auto SessionConnection() const noexcept -> std::shared_ptr<Conn<Memory>>
        {
            return std::dynamic_pointer_cast<Conn<Memory>>(NextLayer_);
        }

    private:
        /**
         * @brief 转调底层数据报发送（chunk 加密）
         */
        [[nodiscard]] auto AsyncSendDatagramImpl(
            std::span<const std::uint8_t> Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            if (!NextLayer_)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }
            auto Connection = SessionConnection();
            if (!Connection)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }
            co_return co_await Connection->AsyncSendDatagram(Payload);
        }

        /**
         * @brief 转调底层数据报接收（chunk 解密）
         */
        [[nodiscard]] auto AsyncReceiveDatagramImpl(
            std::vector<std::uint8_t> &Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            if (!NextLayer_)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }
            auto Connection = SessionConnection();
            if (!Connection)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }
            co_return co_await Connection->AsyncReceiveDatagram(Payload);
        }

        SharedTransmission NextLayer_; ///< 底层流连接（嵌入，同一条 TCP）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Vmess
