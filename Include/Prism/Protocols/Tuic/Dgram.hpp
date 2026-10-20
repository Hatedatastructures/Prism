/**
 * @file Dgram.hpp
 * @brief Tuic UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（Unreliable，
 * 或任意包边界的传输）包装为 Tuic packet 帧编解码层。
 * 帧格式：[Ver 1B][Cmd 1B=0x07][AssocID 4B LE][PktID 4B LE]
 *          [ATYP 1B][ADDR][PORT 2B BE][payload]。
 * 目标地址内嵌于帧内，assoc/pkt Id 由本对象自增维护。
 * @note 继承 Prism::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Tuic/Detail/DatagramPackets.hpp>
#include <Prism/Protocols/Tuic/DgramPacketReceiver.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/Types.hpp>
#include <tuple>

namespace Prism::Tuic
{

    /**
     * @class Dgram
     * @brief Tuic UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom），内部完成 packet 帧
     * 编解码（Codec.hpp 纯函数）。由工厂（ConnectPacket /
     * AcceptPacket）创建。
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Dgram : public Prism::Transmission
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param Upstream 底层数据报或已认证 QUIC 数据流（所有权移交）
         */
        explicit Dgram(SharedTransmission Upstream)
            : Prism::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Prism::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 传输类型（数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param Destination 目标地址（帧内携带）
         * @param Payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(
            const Address &Destination,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (CloseDelivered_.load(std::memory_order_acquire))
            {
                co_return Error::IoError;
            }
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            if (Payload.size() > Detail::MaxUdpPayloadSize)
            {
                co_return Error::BadLength;
            }
            const auto Plan = Detail::BuildDatagramPlan(Detail::DatagramBuildRequest{
                AssocId_, PacketId_, Destination, Payload.size(),
                NextLayer_->TransportType() == Prism::Transmission::Type::Udp},
                TxWire_);
            if (!Plan)
            {
                co_return Plan.error();
            }
            const auto PacketId = PacketId_;
            ++PacketId_;
            const bool DatagramTransport =
                NextLayer_->TransportType() == Prism::Transmission::Type::Udp;
            Message MessageValue;
            MessageValue.Cmd = CmdPacket;
            MessageValue.AssocId = AssocId_;
            MessageValue.PktId = PacketId;
            MessageValue.FragTotal = Plan->FragTotal;
            MessageValue.dst = Destination;
            std::size_t Offset = 0;
            for (std::size_t Index = 0; Index < Plan->FragTotal; ++Index)
            {
                const auto Capacity = Index == 0U
                    ? Plan->FirstPayloadSize
                    : Plan->LaterPayloadSize;
                const auto Count = (std::min)(Capacity, Payload.size() - Offset);
                MessageValue.FragId = static_cast<std::uint8_t>(Index);
                MessageValue.Size = static_cast<std::uint16_t>(Count);
                MessageValue.payload.clear();
                if (Count != 0U)
                {
                    MessageValue.payload.assign(
                        reinterpret_cast<const char *>(Payload.data() + Offset), Count);
                }
                Build(MessageValue, TxWire_);
                if (TxWire_.empty() ||
                    (DatagramTransport && TxWire_.size() > Detail::MaxDatagramFrameSize))
                {
                    co_return Error::BadLength;
                }

                std::size_t Done = 0;
                while (Done < TxWire_.size())
                {
                    const auto Remaining = TxWire_.size() - Done;
                    const auto Part = co_await NextLayer_->WriteSome(
                        AsBytes(std::span<const std::uint8_t>(TxWire_).subspan(Done)));
                    if (Part.Bytes > Remaining)
                    {
                        co_return Error::BadLength;
                    }
                    if (Part.Failure.Failed() || Part.Bytes == 0U ||
                        (DatagramTransport && Part.Bytes != Remaining))
                    {
                        co_return Error::IoError;
                    }
                    Done += Part.Bytes;
                }
                Offset += Count;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param Source 输出源地址（帧内目标）
         * @param Payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            Address &Source,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            co_await DispatchToExecutor();
            if (CloseDelivered_.load(std::memory_order_acquire))
            {
                co_return Error::IoError;
            }
            if (PendingReceiveTerminal_)
            {
                const auto Failure = *PendingReceiveTerminal_;
                if (NextLayer_ &&
                    NextLayer_->TransportType() == Prism::Transmission::Type::Udp)
                {
                    PendingReceiveTerminal_.reset();
                }
                co_return ReadFailureToError(Failure);
            }
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Detail::DgramPacketReceiver Receiver(NextLayer_);
            while (true)
            {
                auto Received = co_await Receiver.Receive();
                if (Received.TerminalAfter)
                {
                    PendingReceiveTerminal_ = Received.TerminalAfter;
                }
                if (!Received.Value)
                {
                    if (Received.Value.error() == Error::BadLength &&
                        !Received.TerminalAfter)
                    {
                        PendingReceiveTerminal_ =
                            Prism::Fault::Failure{Prism::Fault::Code::IoError};
                    }
                    co_return Received.Value.error();
                }

                const auto Complete = Reassembler_.Accept(
                    std::move(*Received.Value));
                if (!Complete)
                {
                    co_return Complete.error();
                }
                if (!Complete->has_value())
                {
                    if (PendingReceiveTerminal_)
                    {
                        const auto Failure = *PendingReceiveTerminal_;
                        if (NextLayer_->TransportType() ==
                            Prism::Transmission::Type::Udp)
                        {
                            PendingReceiveTerminal_.reset();
                        }
                        co_return ReadFailureToError(Failure);
                    }
                    continue;
                }
                auto Packet = std::move(**Complete);
                AssocId_ = Packet.AssocId;
                Source = std::move(Packet.dst);
                Payload.assign(
                    reinterpret_cast<const std::uint8_t *>(Packet.payload.data()),
                    reinterpret_cast<const std::uint8_t *>(Packet.payload.data()) +
                        Packet.payload.size());
                co_return Error::None;
            }
        }

        /**
         * @brief 透传读取（底层数据报原样）
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<DgramReadWork>(DgramRead{std::static_pointer_cast<Dgram>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /**
         * @brief 透传写入（底层数据报原样）
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<DgramWriteWork>(DgramWrite{std::static_pointer_cast<Dgram>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层数据报载体；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 关闭底层传输
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (NextLayer_)
            {
                const auto Closed = NextLayer_->Close();
                if (Closed)
                {
                    CloseDelivered_.store(true, std::memory_order_release);
                }
                return Closed;
            }
            CloseDelivered_.store(true, std::memory_order_release);
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
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
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
         * @brief 获取底层传输共享引用
         * @return 底层传输共享指针
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        [[nodiscard]] static auto ReadFailureToError(
            const Prism::Fault::Failure &Failure) noexcept -> Error
        {
            switch (Failure.Code)
            {
            case Prism::Fault::Code::Eof: return Error::UnexpectedEof;
            case Prism::Fault::Code::Canceled: return Error::Canceled;
            case Prism::Fault::Code::Timeout: return Error::Timeout;
            default: return Error::IoError;
            }
        }

        struct DgramRead final { std::shared_ptr<Dgram> Owner; std::span<std::byte> Buffer; };
        struct DgramWrite final { std::shared_ptr<Dgram> Owner; std::span<const std::byte> Buffer; };
        struct DgramReadWork final
        {
            template<class State>
            auto operator()(State Operation, DgramRead Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred)};
            }
        };
        struct DgramWriteWork final
        {
            template<class State>
            auto operator()(State Operation, DgramWrite Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred)};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        /** @brief 切到连接 executor 后透传真实部分读；上游已释放返回确定失败码。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await NextLayer_->ReadSome(Buffer);
        }

        /** @brief 切到连接 executor 后透传真实部分写；上游已释放返回确定失败码。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
        {
            co_await DispatchToExecutor();
            if (!NextLayer_)
            {
                co_return Prism::IoResult{0, {Prism::Fault::Code::IoError}};
            }
            co_return co_await NextLayer_->WriteSome(Buffer);
        }

        [[nodiscard]] auto DispatchToExecutor() -> Net::awaitable<void>
        {
            if (NextLayer_)
            {
                co_await Net::dispatch(NextLayer_->Executor(), Net::use_awaitable);
            }
        }

        SharedTransmission NextLayer_; ///< 底层数据报传输（独占所有权）
        std::uint16_t AssocId_{0};      ///< UDP 关联 ID
        std::uint16_t PacketId_{0};     ///< 下一个 UDP 包 ID（从 0 开始）
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
        Detail::DatagramReassembler Reassembler_; ///< TUIC packet 分片重组器
        std::optional<Prism::Fault::Failure> PendingReceiveTerminal_{}; ///< TCP 流终态持续保留；UDP 错误延迟交付一次。
        std::atomic<bool> CloseDelivered_{false}; ///< 本层最终关闭命令已交付，后续数据报操作按关闭错误返回。
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

    static_assert(Prism::TransmissionLike<Dgram<>>);

} // namespace Prism::Tuic
