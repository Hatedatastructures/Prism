/**
 * @file Session.hpp
 * @brief 一个 Hysteria2 UDP 关联的子 owner。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>

#include <functional>
#include <exception>
#include <memory>

#include <Prism/Account/Lease.hpp>
#include <Prism/Protocols/Hysteria2/Admission.hpp>
#include <Prism/Protocols/Quic/Datagram/Adapter.hpp>
#include <cstdint>

namespace Prism::Hysteria2
{

    class DatagramSession final : public std::enable_shared_from_this<DatagramSession>
    {
    public:
        struct Options final
        {
            boost::asio::any_io_executor Executor{};
            Prism::Quic::SharedDatagramProvider Provider{};
            Prism::Account::StreamLease Lease;
            Prism::AccountId AccountId{};
            AdmissionServices Services;
            std::function<void(std::exception_ptr)> Completed;
            Prism::Contract::RequestMetadata Metadata{};
        };

        [[nodiscard]] static auto Create(Options OptionsValue)
            -> std::shared_ptr<DatagramSession>;

        ~DatagramSession() noexcept;

        DatagramSession(const DatagramSession &) = delete;
        auto operator=(const DatagramSession &) -> DatagramSession & = delete;

        auto Start() -> void;
        auto Close() noexcept -> void;

    private:
        explicit DatagramSession(Options OptionsValue);

        [[nodiscard]] auto Run() -> boost::asio::awaitable<void>;
        auto ReportBytes(std::uint64_t Uploaded, std::uint64_t Downloaded) noexcept -> void;
        auto Complete(std::exception_ptr Error) noexcept -> void;

        Options Options_;
        DatagramSessionReport Report_;
        std::shared_ptr<boost::asio::cancellation_signal> Cancellation_;
        bool Completed_{false};
        bool Started_{false};
    };


} // namespace Prism::Hysteria2
