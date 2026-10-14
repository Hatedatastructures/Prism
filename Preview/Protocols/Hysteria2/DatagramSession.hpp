/**
 * @file DatagramSession.hpp
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
#include <utility>
#include <vector>

#include <Preview/Account/Lease.hpp>
#include <Preview/Protocols/Hysteria2/Admission.hpp>
#include <Preview/Protocols/Hysteria2/Dgram.hpp>

namespace Preview::Hysteria2
{

    class DatagramSession final : public std::enable_shared_from_this<DatagramSession>
    {
    public:
        struct Options final
        {
            boost::asio::any_io_executor Executor{};
            Preview::Quic::SharedDatagramProvider Provider{};
            Preview::Account::StreamLease Lease;
            Preview::AccountId AccountId{};
            AdmissionServices Services;
            std::function<void(std::exception_ptr)> Completed;
            Preview::Contract::RequestMetadata Metadata{};
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


    inline auto DatagramSession::Create(Options OptionsValue)
        -> std::shared_ptr<DatagramSession>
    {
        if (!OptionsValue.Executor || !OptionsValue.Provider || !OptionsValue.Lease)
        {
            return {};
        }
        return std::shared_ptr<DatagramSession>(
            new DatagramSession(std::move(OptionsValue)));
    }

    inline DatagramSession::DatagramSession(Options OptionsValue)
        : Options_(std::move(OptionsValue)),
          Report_{Options_.AccountId},
          Cancellation_(std::make_shared<Net::cancellation_signal>())
    {
        Report_.Metadata = Options_.Metadata;
    }

    inline DatagramSession::~DatagramSession() noexcept
    {
        Close();
    }

    inline auto DatagramSession::Start() -> void
    {
        if (Started_)
        {
            return;
        }
        Started_ = true;
        auto Self = shared_from_this();
        Net::co_spawn(
            Options_.Executor,
            Self->Run(),
            Net::bind_cancellation_slot(
                Cancellation_->slot(),
                [Self](std::exception_ptr Error)
                {
                    Self->Complete(Error);
                }));
    }

    inline auto DatagramSession::Close() noexcept -> void
    {
        if (Cancellation_)
        {
            Cancellation_->emit(Net::cancellation_type::all);
        }
        if (Options_.Provider)
        {
            try
            {
                Options_.Provider->Cancel();
                Options_.Provider->Close();
            }
            catch (...)
            {
            }
        }
    }

    inline auto DatagramSession::Run() -> Net::awaitable<void>
    {
        if (!Options_.Provider)
        {
            co_return;
        }
        auto Transport = std::make_shared<Preview::Quic::DatagramAdapter>(Options_.Provider);
        auto Datagram = std::make_shared<Dgram<>>(std::move(Transport), true);
        try
        {
            while (Options_.Provider && !Options_.Provider->IsClosed())
            {
                Address Target;
                std::vector<std::uint8_t> Payload;
                const auto Status = co_await Datagram->AsyncReceiveFrom(Target, Payload);
                if (Status == Error::BadMessage || Status == Error::NeedMore)
                {
                    ++Report_.MalformedDatagrams;
                    continue;
                }
                if (Status != Error::None)
                {
                    break;
                }
                ++Report_.ValidDatagrams;
                if (!Options_.Services.Resolve || !Options_.Services.ExchangeDatagram)
                {
                    ++Report_.DroppedDatagrams;
                    continue;
                }
                auto Resolved = co_await Options_.Services.Resolve(ResolveRequest{Target});
                if (Resolved.Status != Preview::Fault::Code::Success ||
                    Resolved.Endpoints.empty())
                {
                    ++Report_.DroppedDatagrams;
                    continue;
                }
                auto Exchange = co_await Options_.Services.ExchangeDatagram(DatagramRequest{
                    Resolved.Endpoints.front(), std::move(Payload), Options_.AccountId});
                Report_.UploadedBytes += Exchange.UploadedBytes;
                ReportBytes(Exchange.UploadedBytes, 0);
                if (Exchange.Status != Preview::Fault::Code::Success)
                {
                    ++Report_.DroppedDatagrams;
                    continue;
                }
                const auto SendStatus = co_await Datagram->AsyncSendTo(
                    Exchange.Source,
                    std::span<const std::uint8_t>(Exchange.Payload));
                if (SendStatus != Error::None)
                {
                    ++Report_.DroppedDatagrams;
                    break;
                }
                Report_.DownloadedBytes += Exchange.DownloadedBytes;
                ReportBytes(0, Exchange.DownloadedBytes);
            }
        }
        catch (...)
        {
            ++Report_.DroppedDatagrams;
            throw;
        }
    }

    inline auto DatagramSession::ReportBytes(
        const std::uint64_t Uploaded,
        const std::uint64_t Downloaded) noexcept -> void
    {
        if ((!Uploaded && !Downloaded) || !Options_.Services.ReportDatagram)
        {
            return;
        }
        auto Report = Report_;
        Report.UploadedBytes = Uploaded;
        Report.DownloadedBytes = Downloaded;
        Report.Kind = Preview::Foundation::TrafficEventKind::Bytes;
        try
        {
            Options_.Services.ReportDatagram(std::move(Report));
        }
        catch (...)
        {
        }
    }

    inline auto DatagramSession::Complete(std::exception_ptr Error) noexcept -> void
    {
        if (Completed_)
        {
            return;
        }
        Completed_ = true;
        Close();
        Options_.Lease.Release();
        if (Options_.Services.ReportDatagram)
        {
            try
            {
                Options_.Services.ReportDatagram(Report_);
            }
            catch (...)
            {
            }
        }
        if (Options_.Completed)
        {
            Options_.Completed(Error);
        }
    }

} // namespace Preview::Hysteria2
