/** @file Writer.hpp @brief XUDP 唯一完整回包 writer 与拥有值 completion。 */
#pragma once
#include <Preview/Contract/Io/PacketTransferResult.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Protocols/Vless/Xudp/Codec.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <deque>
#include <system_error>

namespace Preview::Vless::Xudp
{
    struct RunFailureState final
    {
        Preview::Fault::Failure First{};
        auto Record(Preview::Fault::Failure Failure) noexcept -> void
        {
            if (First.Succeeded())
                First = std::move(Failure);
        }
    };

    inline auto MakeRunFailureHandler(const std::shared_ptr<RunFailureState>& State)
        -> Preview::Lifecycle::TaskRegistry::FailureHandler
    {
        return [State](const Preview::Lifecycle::TaskIdentity&, Preview::Fault::Failure Failure)
        { State->Record(std::move(Failure)); };
    }

    struct WritePacket final
    {
        std::vector<std::byte> Wire;
        std::size_t PayloadSize{0};
    };
    using WriteResult = Preview::Contract::Io::PacketTransferResult;
    class Writer final : public std::enable_shared_from_this<Writer>
    {
        struct Entry final
        {
            Entry(Net::any_io_executor Ex, WritePacket Packet) : Value(std::move(Packet)), Completion(Ex, 1)
            {
            }
            WritePacket Value;
            Net::experimental::channel<void(boost::system::error_code, WriteResult)> Completion;
            std::size_t WireBytes{0};
            bool Completed{false};
        };

    public:
        Writer(Preview::SharedTransmission Inbound, std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks,
            std::shared_ptr<RunFailureState> Failure)
            : Inbound_(std::move(Inbound)), Tasks_(std::move(Tasks)), Failure_(std::move(Failure))
        {
        }
        auto BindIdentity(Preview::Lifecycle::TaskIdentity Identity) -> void
        {
            Identity_ = Identity;
        }
        /** @brief writer 拥有完整 wire；producer 取消仍等待真实完成，根关闭会唤醒 queued/active producers。 */
        [[nodiscard]] auto Send(WritePacket Packet) -> Net::awaitable<WriteResult>
        {
            co_await Net::dispatch(Tasks_->Executor(), Net::use_awaitable);
            if (Closed_)
                co_return WriteResult{0, 0, {Preview::Fault::Code::Canceled}};
            if (Packet.Wire.empty() || Packet.PayloadSize > Packet.Wire.size())
                co_return WriteResult{0, 0, {Preview::Fault::Code::InvalidArgument}};
            const auto EntryValue = std::make_shared<Entry>(Tasks_->Executor(), std::move(Packet));
            Queue_.push_back(EntryValue);
            if (!Running_)
            {
                Running_ = true;
                Preview::Lifecycle::TaskRequest Request{.Context = Preview::Lifecycle::FromParent(Identity_),
                    .StartOnSubmit = true};
                const auto Weak = weak_from_this();
                Request.Cancel = [Weak]
                {
                    if (const auto Owner = Weak.lock())
                        Owner->Close();
                };
                if (!Tasks_->SpawnTracked(std::move(Request), Pump(shared_from_this())))
                    Close();
            }
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            co_return co_await EntryValue->Completion.async_receive(Net::use_awaitable);
        }
        auto Close() noexcept -> void
        {
            Closed_ = true;
            while (!Queue_.empty())
            {
                Complete(Queue_.front(), WriteResult{0, 0, {Preview::Fault::Code::Canceled}});
                Queue_.pop_front();
            }
            try
            {
                Inbound_->Cancel();
                Inbound_->Close();
            }
            catch (...)
            {
            }
        }

    private:
        static auto Complete(const std::shared_ptr<Entry>& Item, WriteResult Result) noexcept -> void
        {
            if (Item->Completed)
                return;
            Item->Completed = true;
            (void)Item->Completion.try_send(boost::system::error_code{}, Result);
        }
        static auto Pump(std::shared_ptr<Writer> Owner) -> Net::awaitable<void>
        {
            try
            {
                while (!Owner->Closed_ && !Owner->Queue_.empty())
                {
                    auto Item = Owner->Queue_.front();
                    Owner->Queue_.pop_front();
                    Owner->Active_ = Item;
                    Preview::Fault::Failure Failure;
                    const auto Prefix = Item->Value.Wire.size() - Item->Value.PayloadSize;
                    while (Item->WireBytes < Item->Value.Wire.size() && !Owner->Closed_)
                    {
                        const auto Part = co_await Owner->Inbound_->WriteSome(
                            std::span(Item->Value.Wire).subspan(Item->WireBytes));
                        const auto Count = Part.Bytes;
                        if (Count > Item->Value.Wire.size() - Item->WireBytes)
                        {
                            Failure = {Preview::Fault::Code::InvalidArgument, Part.Failure.Native};
                            break;
                        }
                        Item->WireBytes += Count;
                        if (Part.Failure.Failed())
                        {
                            Failure = Part.Failure;
                            break;
                        }
                        if (Count == 0U)
                        {
                            Failure = {Preview::Fault::Code::WouldBlock};
                            break;
                        }
                    }
                    if (Owner->Closed_ && !Failure.Failed())
                    {
                        Failure = {Preview::Fault::Code::Canceled};
                    }
                    const bool Success = !Failure.Failed() && Item->WireBytes == Item->Value.Wire.size();
                    if (!Success && !Failure.Failed())
                    {
                        Failure = {Preview::Fault::Code::IoError};
                    }
                    const auto PayloadBytes = Success ? Item->Value.PayloadSize : 0U;
                    Complete(Item, {PayloadBytes, Item->WireBytes, Failure});
                    Owner->Active_.reset();
                    if (!Success)
                    {
                        Owner->Failure_->Record(Failure);
                        Owner->Close();
                    }
                }
            }
            catch (const boost::system::system_error& Error)
            {
                const auto Failure = Preview::Fault::FromNative(static_cast<std::error_code>(Error.code()));
                Owner->Failure_->Record(Failure);
                if (Owner->Active_)
                {
                    const auto Item = Owner->Active_;
                    Complete(Item, {0, Item->WireBytes, Failure});
                }
                Owner->Active_.reset();
                Owner->Close();
            }
            catch (const std::system_error& Error)
            {
                const auto Failure = Preview::Fault::FromNative(Error.code());
                Owner->Failure_->Record(Failure);
                if (Owner->Active_)
                    Complete(Owner->Active_, {0, Owner->Active_->WireBytes, Failure});
                Owner->Active_.reset();
                Owner->Close();
            }
            catch (...)
            {
                const Preview::Fault::Failure Failure{Preview::Fault::Code::IoError};
                Owner->Failure_->Record(Failure);
                if (Owner->Active_)
                    Complete(Owner->Active_, {0, Owner->Active_->WireBytes, Failure});
                Owner->Active_.reset();
                Owner->Close();
            }
            Owner->Running_ = false;
        }
        Preview::SharedTransmission Inbound_;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Tasks_;
        std::shared_ptr<RunFailureState> Failure_;
        Preview::Lifecycle::TaskIdentity Identity_;
        std::deque<std::shared_ptr<Entry>> Queue_;
        std::shared_ptr<Entry> Active_;
        bool Closed_{false}, Running_{false};
    };
} // namespace Preview::Vless::Xudp
