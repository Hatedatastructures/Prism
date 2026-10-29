/**
 * @file Session.cpp
 * @brief Hysteria2 数据报会话实现。
 */
#include <Prism/Protocols/Hysteria2/Datagram/Session.hpp>

#include <Prism/Protocols/Hysteria2/Dgram.hpp>
#include <Prism/Protocols/Quic/Datagram/Adapter.hpp>

#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Hysteria2
{
    auto DatagramSession::Create(Options OptionsValue)
        -> std::shared_ptr<DatagramSession>
    {
        if (!OptionsValue.Executor || !OptionsValue.Provider || !OptionsValue.Lease)
        {
            return {};
        }
        return std::shared_ptr<DatagramSession>(
            new DatagramSession(std::move(OptionsValue)));
    }

    DatagramSession::DatagramSession(Options OptionsValue)
        : Options_(std::move(OptionsValue)),
          Report_{Options_.AccountId},
          Cancellation_(std::make_shared<Net::cancellation_signal>())
    {
        Report_.Metadata = Options_.Metadata;
    }

    DatagramSession::~DatagramSession() noexcept
    {
        Close();
    }

    auto DatagramSession::Start() -> void
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

    auto DatagramSession::Close() noexcept -> void
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

    auto DatagramSession::Run() -> Net::awaitable<void>
    {
        if (!Options_.Provider)
        {
            co_return;
        }
        auto Transport = std::make_shared<Prism::Quic::DatagramAdapter>(Options_.Provider);
        auto Datagram = std::make_shared<Dgram<>>(std::move(Transport), true);
        try
        {
            while (Options_.Provider)
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
                if (Resolved.Status != Prism::Fault::Code::Success ||
                    Resolved.Endpoints.empty())
                {
                    ++Report_.DroppedDatagrams;
                    continue;
                }
                auto Exchange = co_await Options_.Services.ExchangeDatagram(DatagramRequest{
                    Resolved.Endpoints.front(), std::move(Payload), Options_.AccountId});
                Report_.UploadedBytes += Exchange.UploadedBytes;
                ReportBytes(Exchange.UploadedBytes, 0);
                if (Exchange.Status != Prism::Fault::Code::Success)
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

    auto DatagramSession::ReportBytes(
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
        Report.Kind = Prism::Foundation::TrafficEventKind::Bytes;
        try
        {
            Options_.Services.ReportDatagram(std::move(Report));
        }
        catch (...)
        {
        }
    }

    auto DatagramSession::Complete(std::exception_ptr Error) noexcept -> void
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
}
