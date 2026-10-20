/** @file Writer.hpp @brief XUDP 唯一完整回包 writer 与拥有值 completion。 */
#pragma once

#include <Prism/Contract/Io/PacketTransferResult.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Protocols/Vless/Xudp/VlessXudp.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <deque>
#include <memory>
#include <span>
#include <vector>

namespace Prism::Vless::Xudp
{
    struct RunFailureState final
    {
        Prism::Fault::Failure First{};
        auto Record(Prism::Fault::Failure Failure) noexcept -> void;
    };

    [[nodiscard]] auto MakeRunFailureHandler(
        const std::shared_ptr<RunFailureState> &State)
        -> Prism::Lifecycle::TaskRegistry::FailureHandler;

    struct WritePacket final
    {
        std::vector<std::byte> Wire;
        std::size_t PayloadSize{0};
    };
    using WriteResult = Prism::Contract::Io::PacketTransferResult;

    /** @brief 串行写入拥有型 XUDP wire，并等待真实完成后交付 packet 结果。 */
    class Writer final : public std::enable_shared_from_this<Writer>
    {
        struct Entry;

    public:
        Writer(
            Prism::SharedTransmission Inbound,
            std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks,
            std::shared_ptr<RunFailureState> Failure);

        auto BindIdentity(Prism::Lifecycle::TaskIdentity Identity) -> void;

        /** @brief writer 拥有完整 wire；producer 取消仍等待真实完成，根关闭会唤醒 queued/active producers。 */
        [[nodiscard]] auto Send(WritePacket Packet) -> Net::awaitable<WriteResult>;

        auto Close() noexcept -> void;

    private:
        static auto Complete(const std::shared_ptr<Entry> &Item, WriteResult Result) noexcept
            -> void;
        static auto Pump(std::shared_ptr<Writer> Owner) -> Net::awaitable<void>;

        Prism::SharedTransmission Inbound_;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks_;
        std::shared_ptr<RunFailureState> Failure_;
        Prism::Lifecycle::TaskIdentity Identity_;
        std::deque<std::shared_ptr<Entry>> Queue_;
        std::shared_ptr<Entry> Active_;
        bool Closed_{false};
        bool Running_{false};
    };
} // namespace Prism::Vless::Xudp
