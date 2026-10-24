/**
 * @file StreamSession.hpp
 * @brief 一个 Hysteria2 原始 stream 的子 owner。
 */

#pragma once

#include <Prism/Account/Lease.hpp>
#include <Prism/Protocols/Hysteria2/Admission.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <exception>

namespace Prism::Hysteria2
{

    class StreamSession final : public std::enable_shared_from_this<StreamSession>
    {
    public:
        struct Options final
        {
            boost::asio::any_io_executor Executor{};
            std::uint64_t Id{0};
            Prism::Quic::SharedStreamProvider Provider{};
            Prism::AccountId AccountId{};
            std::string Identity;
            Prism::Account::StreamLease Lease;
            AdmissionServices Services;
            std::function<void(std::uint64_t, Prism::Fault::Code)> Completed;
            Prism::Contract::RequestMetadata Metadata{};
        };

        [[nodiscard]] static auto Create(Options OptionsValue) -> std::shared_ptr<StreamSession>;

        ~StreamSession() noexcept;

        StreamSession(const StreamSession&) = delete;
        auto operator=(const StreamSession&) -> StreamSession& = delete;

        auto Start() -> void;
        auto Close() noexcept -> void;

        [[nodiscard]] auto Id() const noexcept -> std::uint64_t
        {
            return Options_.Id;
        }

    private:
        explicit StreamSession(Options OptionsValue);

        [[nodiscard]] auto Run() -> boost::asio::awaitable<void>;
        auto Complete(Prism::Fault::Code Status) noexcept -> void;

        Options Options_;
        std::shared_ptr<boost::asio::cancellation_signal> Cancellation_;
        Prism::SharedTransmission Outbound_{};
        bool Completed_{false};
        bool Started_{false};
        Prism::Fault::Code Result_{Prism::Fault::Code::Success};
    };

    namespace StreamDetail
    {

        enum class ParseResult : std::uint8_t
        {
            NeedMore,
            Invalid,
            Ready,
        };

        struct RawRequest final
        {
            Prism::Network::Target Target;
            std::size_t Consumed{0};
        };

        [[nodiscard]] auto ReadVarint(
            std::span<const std::byte> Data,
            std::size_t &Offset,
            std::uint64_t &Value) -> ParseResult;

        [[nodiscard]] auto ParseRawRequest(
            std::span<const std::byte> Data,
            RawRequest &Output) -> ParseResult;

        [[nodiscard]] auto WriteTcpResponseHeader(
            const Prism::Quic::SharedStreamProvider &Provider) -> Net::awaitable<bool>;

    } // namespace StreamDetail

    using StreamDetail::ParseRawRequest;
    using StreamDetail::ParseResult;
    using StreamDetail::RawRequest;
    using StreamDetail::WriteTcpResponseHeader;

} // namespace Prism::Hysteria2
