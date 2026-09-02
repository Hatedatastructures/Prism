/**
 * @file TransportContractTest.cpp
 * @brief psm 与 Preview 传输测试桩契约对拍
 * @details 用同一行为表驱动两套传输类型，比较数据、EOF、取消、
 *          写入错误和半关闭后的写方向语义。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <algorithm>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <prism/foundation/fault/code.hpp>
#include <prism/net/dns/upstream.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Net/Dns/Upstream.hpp>
#include <preview/Protocols/Mux/Session.hpp>
#include <preview/Protocols/Mux/Smux/Codec.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <TestSupport/Production/ProductionMockTransport.hpp>

namespace
{

    namespace net = boost::asio;

    enum class ReadAction
    {
        Close,
        Shutdown,
        Cancel,
        ReadError,
    };

    enum class ReadStatus
    {
        Data,
        Eof,
        Canceled,
        Error,
    };

    struct ReadObservation
    {
        std::array<std::byte, 8> Data{};
        std::size_t Bytes{0};
        std::error_code Error;
        std::exception_ptr Failure;
    };

    enum class WriteScenario
    {
        OneByte,
        Varying,
        PartialThenError,
        ZeroProgress,
        Closed,
    };

    struct WriteObservation
    {
        std::size_t Bytes{0};
        std::error_code Error;
        std::vector<std::uint8_t> Wire;
        bool Closed{false};
        std::exception_ptr Failure;
    };

    enum class WriteErrorClass
    {
        None,
        Io,
        Other,
    };

    [[nodiscard]] auto NormalizeWriteError(const std::error_code &Error) -> WriteErrorClass
    {
        if (!Error)
        {
            return WriteErrorClass::None;
        }
        if (Error == psm::fault::make_error_code(psm::fault::code::io_error) ||
            Error == Preview::make_error_code(Preview::Error::IoError) ||
            Error == Preview::make_error_code(Preview::Error::BrokenPipe))
        {
            return WriteErrorClass::Io;
        }
        return WriteErrorClass::Other;
    }

    constexpr std::array<std::byte, 9> WritePayload{
        std::byte{0x01}, std::byte{0x12}, std::byte{0x23}, std::byte{0x34}, std::byte{0x45},
        std::byte{0x56}, std::byte{0x67}, std::byte{0x78}, std::byte{0x89}};

    void ConfigureWrite(Psm::Testing::ProductionMockTransport &Transport, const WriteScenario Scenario)
    {
        switch (Scenario)
        {
        case WriteScenario::OneByte:
            Transport.MaxWrite = 1;
            break;
        case WriteScenario::Varying:
            Transport.WriteLimitSequence = {1, 3, 2, 4};
            break;
        case WriteScenario::PartialThenError:
            Transport.MaxWrite = 2;
            Transport.WriteFailAt = 2;
            break;
        case WriteScenario::ZeroProgress:
            Transport.ZeroWrite = true;
            break;
        case WriteScenario::Closed:
            Transport.close();
            break;
        }
    }

    void ConfigureWrite(Preview::PreviewMockTransport &Transport, const WriteScenario Scenario)
    {
        switch (Scenario)
        {
        case WriteScenario::OneByte:
            Transport.MaxWrite = 1;
            break;
        case WriteScenario::Varying:
            Transport.WriteLimitSequence = {1, 3, 2, 4};
            break;
        case WriteScenario::PartialThenError:
            Transport.MaxWrite = 2;
            Transport.WriteFailAt = 2;
            break;
        case WriteScenario::ZeroProgress:
            Transport.ZeroWrite = true;
            break;
        case WriteScenario::Closed:
            Transport.Close();
            break;
        }
    }

    [[nodiscard]] auto ToBytes(const psm::memory::vector<std::byte> &Data)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        Result.reserve(Data.size());
        for (const auto Byte : Data)
        {
            Result.push_back(std::to_integer<std::uint8_t>(Byte));
        }
        return Result;
    }

    auto RunProductionWrite(std::shared_ptr<Psm::Testing::ProductionMockTransport> Transport,
                            WriteObservation *Observation) -> net::awaitable<void>
    {
        Observation->Bytes = co_await psm::transport::async_write(
            *Transport, WritePayload, Observation->Error);
    }

    auto RunPreviewWrite(std::shared_ptr<Preview::PreviewMockTransport> Transport,
                         WriteObservation *Observation) -> net::awaitable<void>
    {
        Observation->Bytes = co_await Transport->AsyncWrite(WritePayload, Observation->Error);
    }

    auto ObserveProductionWrite(const WriteScenario Scenario) -> WriteObservation
    {
        auto Transport = std::make_shared<Psm::Testing::ProductionMockTransport>();
        ConfigureWrite(*Transport, Scenario);
        auto &Ioc = Transport->GetIoContext();
        WriteObservation Observation;
        net::co_spawn(Ioc, RunProductionWrite(Transport, &Observation),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        Observation.Wire = ToBytes(Transport->WrittenData());
        Observation.Closed = Transport->IsClosed();
        return Observation;
    }

    auto ObservePreviewWrite(const WriteScenario Scenario) -> WriteObservation
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        ConfigureWrite(*Transport, Scenario);
        WriteObservation Observation;
        net::co_spawn(Ioc, RunPreviewWrite(Transport, &Observation),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        Observation.Wire = Transport->Written;
        Observation.Closed = Transport->IsClosed();
        return Observation;
    }

    TEST(TransportContract, CompleteWriteScenariosMatch)
    {
        for (const auto Scenario : {WriteScenario::OneByte, WriteScenario::Varying,
                                    WriteScenario::PartialThenError, WriteScenario::ZeroProgress,
                                    WriteScenario::Closed})
        {
            const auto Production = ObserveProductionWrite(Scenario);
            const auto Preview = ObservePreviewWrite(Scenario);
            ASSERT_FALSE(Production.Failure);
            ASSERT_FALSE(Preview.Failure);
            EXPECT_EQ(Production.Bytes, Preview.Bytes);
            EXPECT_EQ(static_cast<bool>(Production.Error), static_cast<bool>(Preview.Error));
            EXPECT_EQ(NormalizeWriteError(Production.Error), NormalizeWriteError(Preview.Error));
            EXPECT_EQ(Production.Wire, Preview.Wire);
            EXPECT_EQ(Production.Closed, Preview.Closed);
        }
    }

    class ProductionMuxContract final : public psm::multiplex::multiplexer
    {
    public:
        ProductionMuxContract(std::shared_ptr<Psm::Testing::ProductionMockTransport> Transport,
                              const psm::multiplex::config &Config)
            : multiplexer({Transport, nullptr, Config}), Transport_(std::move(Transport)),
              Completed_(Transport_->GetIoContext().get_executor(), 3)
        {
        }

        [[nodiscard]] auto WaitFrame() -> net::awaitable<bool>
        {
            const auto Event = co_await Completed_.async_receive(net::use_awaitable);
            co_return Event != 0;
        }

        void ActivateWriterOnly()
        {
            active_.store(true, std::memory_order_release);
            auto Self = std::static_pointer_cast<ProductionMuxContract>(this->shared_from_this());
            net::co_spawn(Transport_->executor(), RunWriterOwned(std::move(Self)), net::detached);
        }

        auto SendRst(const std::uint32_t StreamId) -> net::awaitable<void>
        {
            outbound_frame Frame;
            Frame.stream_id = StreamId;
            Frame.kind = outbound_kind::control;
            const auto Rst = psm::multiplex::smux::make_fin(StreamId);
            Frame.payload.insert(Frame.payload.end(), Rst.begin(), Rst.end());
            co_await push_frame(std::move(Frame));
        }

    protected:
        auto RunWriter() -> net::awaitable<void>
        {
            co_await send_loop();
        }

        auto run() -> net::awaitable<void> override
        {
            co_return;
        }

        auto write_frame(outbound_frame Frame) -> net::awaitable<void> override
        {
            psm::memory::vector<std::byte> Wire(psm::memory::current_resource());
            switch (Frame.kind)
            {
            case outbound_kind::data:
                Wire = psm::multiplex::smux::make_data_frame(
                    Frame.stream_id,
                    std::span<const std::byte>(Frame.payload.data(), Frame.payload.size()));
                break;
            case outbound_kind::fin:
                {
                    const auto Fin = psm::multiplex::smux::make_fin(Frame.stream_id);
                    Wire.insert(Wire.end(), Fin.begin(), Fin.end());
                }
                break;
            case outbound_kind::control:
                Wire = std::move(Frame.payload);
                break;
            }

            std::error_code Ec;
            (void)co_await psm::transport::async_write(
                *Transport_, std::span<const std::byte>(Wire.data(), Wire.size()), Ec);
            (void)Completed_.try_send(boost::system::error_code{},
                                      static_cast<std::uint8_t>(Ec ? 1 : 0));
        }

    private:
        std::shared_ptr<Psm::Testing::ProductionMockTransport> Transport_;
        net::experimental::channel<void(boost::system::error_code, std::uint8_t)> Completed_;

        static auto RunWriterOwned(std::shared_ptr<ProductionMuxContract> Self) -> net::awaitable<void>
        {
            co_await Self->RunWriter();
        }
    };

    TEST(TransportContract, ProductionMultiplexerStartOwnsChannel)
    {
        auto Transport = std::make_shared<Psm::Testing::ProductionMockTransport>();
        auto &Ioc = Transport->GetIoContext();
        psm::multiplex::config Config;
        auto Session = std::make_shared<ProductionMuxContract>(Transport, Config);
        Session->start();
        Ioc.run();

        EXPECT_FALSE(Session->is_active());
        EXPECT_TRUE(Transport->IsClosed());
    }

    struct MuxObservation
    {
        std::vector<std::uint8_t> Wire;
        bool Closed{false};
        bool Active{false};
        bool WriteFailed{false};
        std::exception_ptr Failure;
    };

    auto RunProductionMuxData(std::shared_ptr<ProductionMuxContract> Session) -> net::awaitable<void>
    {
        psm::memory::vector<std::byte> Data(psm::memory::current_resource());
        Data.insert(Data.end(), {std::byte{0x11}, std::byte{0x12}, std::byte{0x13}});
        co_await Session->send(1, std::move(Data));
    }

    auto RunProductionMuxRst(std::shared_ptr<ProductionMuxContract> Session) -> net::awaitable<void>
    {
        co_await Session->SendRst(3);
    }

    auto RunProductionMuxWaitAndClose(std::shared_ptr<ProductionMuxContract> Session) -> net::awaitable<void>
    {
        (void)co_await Session->WaitFrame();
        (void)co_await Session->WaitFrame();
        (void)co_await Session->WaitFrame();
        Session->close();
    }

    auto RunPreviewMuxData(std::shared_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> Session,
                           std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done)
        -> net::awaitable<void>
    {
        const std::array<std::uint8_t, 3> Data{0x11, 0x12, 0x13};
        (void)Done->try_send(co_await Session->PushData(1, Data));
    }

    auto RunPreviewMuxFin(std::shared_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> Session,
                          std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done)
        -> net::awaitable<void>
    {
        co_await Session->SendFin(1);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunPreviewMuxRst(std::shared_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> Session,
                          std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done)
        -> net::awaitable<void>
    {
        co_await Session->SendRst(3);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunPreviewMuxWaitAndClose(
        std::shared_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> Session,
        std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done) -> net::awaitable<void>
    {
        (void)co_await Done->async_receive(net::use_awaitable);
        (void)co_await Done->async_receive(net::use_awaitable);
        (void)co_await Done->async_receive(net::use_awaitable);
        co_await Session->Close();
    }

    [[nodiscard]] auto DecodeSmuxFrames(const std::vector<std::uint8_t> &Wire)
        -> std::vector<std::vector<std::uint8_t>>
    {
        std::vector<std::vector<std::uint8_t>> Frames;
        std::size_t Offset = 0;
        while (Offset < Wire.size())
        {
            if (Wire.size() - Offset < 8)
            {
                return {};
            }
            const auto Length = static_cast<std::size_t>(Wire[Offset + 2]) |
                                static_cast<std::size_t>(Wire[Offset + 3]) << 8;
            const auto FrameLength = 8 + Length;
            if (FrameLength > Wire.size() - Offset)
            {
                return {};
            }
            Frames.emplace_back(Wire.begin() + static_cast<std::ptrdiff_t>(Offset),
                                Wire.begin() + static_cast<std::ptrdiff_t>(Offset + FrameLength));
            Offset += FrameLength;
        }
        return Frames;
    }

    [[nodiscard]] auto CanonicalFrames(std::vector<std::vector<std::uint8_t>> Frames)
        -> std::vector<std::vector<std::uint8_t>>
    {
        std::sort(Frames.begin(), Frames.end());
        return Frames;
    }

    auto RunProductionMuxContract(const WriteScenario Scenario) -> MuxObservation
    {
        auto Transport = std::make_shared<Psm::Testing::ProductionMockTransport>();
        ConfigureWrite(*Transport, Scenario);
        auto &Ioc = Transport->GetIoContext();
        psm::multiplex::config Config;
        auto Session = std::make_shared<ProductionMuxContract>(Transport, Config);
        MuxObservation Observation;
        Session->ActivateWriterOnly();

        net::co_spawn(Ioc, RunProductionMuxData(Session), net::detached);
        net::post(Ioc, [Session] { Session->fin(1); });
        net::co_spawn(Ioc, RunProductionMuxRst(Session), net::detached);
        net::co_spawn(Ioc, RunProductionMuxWaitAndClose(Session),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        Observation.Wire = ToBytes(Transport->WrittenData());
        Observation.Closed = Transport->IsClosed();
        Observation.Active = Session->is_active();
        return Observation;
    }

    auto RunPreviewMuxContract(const WriteScenario Scenario) -> MuxObservation
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        ConfigureWrite(*Transport, Scenario);
        auto Session = Preview::Mux::Session<Preview::Mux::Smux::Codec>::Create(Transport, {});
        auto Done = std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(Ioc.get_executor(), 3);
        MuxObservation Observation;

        net::co_spawn(Ioc, RunPreviewMuxData(Session, Done), net::detached);
        net::co_spawn(Ioc, RunPreviewMuxFin(Session, Done), net::detached);
        net::co_spawn(Ioc, RunPreviewMuxRst(Session, Done), net::detached);
        net::co_spawn(Ioc, RunPreviewMuxWaitAndClose(Session, Done),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        Observation.Wire = Transport->Written;
        Observation.Closed = Transport->IsClosed();
        Observation.Active = Session->IsOpen();
        return Observation;
    }

    TEST(TransportContract, MuxSessionFramesRemainCompleteAndEquivalent)
    {
        for (const auto Scenario : {WriteScenario::OneByte, WriteScenario::Varying})
        {
            const auto Production = RunProductionMuxContract(Scenario);
            const auto Preview = RunPreviewMuxContract(Scenario);
            ASSERT_FALSE(Production.Failure);
            ASSERT_FALSE(Preview.Failure);
            EXPECT_TRUE(Production.Closed);
            EXPECT_TRUE(Preview.Closed);
            EXPECT_FALSE(Production.Active);
            EXPECT_FALSE(Preview.Active);

            const auto ProductionFrames = DecodeSmuxFrames(Production.Wire);
            const auto PreviewFrames = DecodeSmuxFrames(Preview.Wire);
            ASSERT_EQ(ProductionFrames.size(), 3u);
            ASSERT_EQ(PreviewFrames.size(), 3u);
            EXPECT_EQ(CanonicalFrames(ProductionFrames), CanonicalFrames(PreviewFrames));
        }
    }

    auto RunProductionMuxDataError(std::shared_ptr<ProductionMuxContract> Session) -> net::awaitable<void>
    {
        psm::memory::vector<std::byte> Data(psm::memory::current_resource());
        Data.insert(Data.end(), {std::byte{0x31}, std::byte{0x32}, std::byte{0x33}});
        co_await Session->send(1, std::move(Data));
    }

    auto RunProductionMuxWaitError(std::shared_ptr<ProductionMuxContract> Session, MuxObservation *Observation)
        -> net::awaitable<void>
    {
        Observation->WriteFailed = co_await Session->WaitFrame();
        Session->close();
    }

    auto RunPreviewMuxDataError(std::shared_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> Session,
                                Preview::ProtocolEc *Result,
                                std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done)
        -> net::awaitable<void>
    {
        const std::array<std::uint8_t, 3> Data{0x31, 0x32, 0x33};
        *Result = co_await Session->PushData(1, Data);
        (void)Done->try_send(boost::system::error_code{});
    }

    auto RunPreviewMuxWaitError(std::shared_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> Session,
                                MuxObservation *Observation, Preview::ProtocolEc *Result,
                                std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> Done)
        -> net::awaitable<void>
    {
        co_await Done->async_receive(net::use_awaitable);
        Observation->WriteFailed = static_cast<bool>(*Result);
        co_await Session->Close();
    }

    auto RunProductionMuxWriteError(const WriteScenario Scenario) -> MuxObservation
    {
        auto Transport = std::make_shared<Psm::Testing::ProductionMockTransport>();
        ConfigureWrite(*Transport, Scenario);
        auto &Ioc = Transport->GetIoContext();
        psm::multiplex::config Config;
        auto Session = std::make_shared<ProductionMuxContract>(Transport, Config);
        MuxObservation Observation;
        Session->ActivateWriterOnly();

        net::co_spawn(Ioc, RunProductionMuxDataError(Session), net::detached);
        net::co_spawn(Ioc, RunProductionMuxWaitError(Session, &Observation),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        Observation.Wire = ToBytes(Transport->WrittenData());
        Observation.Closed = Transport->IsClosed();
        Observation.Active = Session->is_active();
        return Observation;
    }

    auto RunPreviewMuxWriteError(const WriteScenario Scenario) -> MuxObservation
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        ConfigureWrite(*Transport, Scenario);
        auto Session = Preview::Mux::Session<Preview::Mux::Smux::Codec>::Create(Transport, {});
        auto Done = std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(Ioc.get_executor(), 1);
        MuxObservation Observation;
        Preview::ProtocolEc Result;

        net::co_spawn(Ioc, RunPreviewMuxDataError(Session, &Result, Done), net::detached);
        net::co_spawn(Ioc, RunPreviewMuxWaitError(Session, &Observation, &Result, Done),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        Observation.Wire = Transport->Written;
        Observation.Closed = Transport->IsClosed();
        Observation.Active = Session->IsOpen();
        return Observation;
    }

    TEST(TransportContract, MuxSessionErrorScenariosMatch)
    {
        for (const auto Scenario : {WriteScenario::PartialThenError, WriteScenario::ZeroProgress})
        {
            const auto Production = RunProductionMuxWriteError(Scenario);
            const auto Preview = RunPreviewMuxWriteError(Scenario);
            ASSERT_FALSE(Production.Failure);
            ASSERT_FALSE(Preview.Failure);
            EXPECT_TRUE(Production.WriteFailed);
            EXPECT_TRUE(Preview.WriteFailed);
            EXPECT_EQ(Production.Wire, Preview.Wire);
            EXPECT_TRUE(Production.Closed);
            EXPECT_TRUE(Preview.Closed);
            EXPECT_FALSE(Production.Active);
            EXPECT_FALSE(Preview.Active);
            EXPECT_TRUE(DecodeSmuxFrames(Production.Wire).empty());
            EXPECT_TRUE(DecodeSmuxFrames(Preview.Wire).empty());
        }
    }

    [[nodiscard]] auto StatusOf(const ReadObservation &Observation) -> ReadStatus
    {
        if (Observation.Failure || Observation.Error)
        {
            if (Observation.Error == Preview::make_error_code(Preview::Error::Canceled) ||
                Observation.Error == psm::fault::make_error_code(psm::fault::code::canceled))
            {
                return ReadStatus::Canceled;
            }
            if (Observation.Bytes == 0 &&
                Observation.Error == psm::fault::make_error_code(psm::fault::code::eof))
            {
                return ReadStatus::Eof;
            }
            return ReadStatus::Error;
        }
        if (Observation.Bytes == 0)
        {
            return ReadStatus::Eof;
        }
        return ReadStatus::Data;
    }

    auto RunProductionRead(std::shared_ptr<Psm::Testing::ProductionMockTransport> Transport,
                           ReadObservation *Observation) -> net::awaitable<void>
    {
        Observation->Bytes = co_await Transport->async_read_some(Observation->Data, Observation->Error);
    }

    auto RunPreviewRead(std::shared_ptr<Preview::PreviewMockTransport> Transport,
                        ReadObservation *Observation) -> net::awaitable<void>
    {
        Observation->Bytes = co_await Transport->async_read_some(Observation->Data, Observation->Error);
    }

    auto ObserveProduction(ReadAction Action) -> ReadObservation
    {
        auto Transport = std::make_shared<Psm::Testing::ProductionMockTransport>();
        auto &Ioc = Transport->GetIoContext();
        ReadObservation Observation;
        net::co_spawn(Ioc, RunProductionRead(Transport, &Observation),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });

        net::post(Ioc, [Transport, Action]
                  {
                      switch (Action)
                      {
                      case ReadAction::Close:
                          Transport->close();
                          break;
                      case ReadAction::Shutdown:
                          Transport->Shutdown();
                          break;
                      case ReadAction::Cancel:
                          Transport->cancel();
                          break;
                      case ReadAction::ReadError:
                          Transport->SetReadError(
                              psm::fault::make_error_code(psm::fault::code::io_error));
                          break;
                      }
                  });
        Ioc.run();
        return Observation;
    }

    auto ObservePreview(ReadAction Action) -> ReadObservation
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        ReadObservation Observation;
        net::co_spawn(Ioc, RunPreviewRead(Transport, &Observation),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });

        net::post(Ioc, [Transport, Action]
                  {
                      switch (Action)
                      {
                      case ReadAction::Close:
                          Transport->Close();
                          break;
                      case ReadAction::Shutdown:
                          Transport->Shutdown();
                          break;
                      case ReadAction::Cancel:
                          Transport->Cancel();
                          break;
                      case ReadAction::ReadError:
                          Transport->SetReadError(Preview::make_error_code(Preview::Error::IoError));
                          break;
                      }
                  });
        Ioc.run();
        return Observation;
    }

    auto ObserveProductionData() -> ReadObservation
    {
        auto Transport = std::make_shared<Psm::Testing::ProductionMockTransport>();
        auto &Ioc = Transport->GetIoContext();
        const std::vector<std::byte> Input{std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
        Transport->InjectRead(Input);
        ReadObservation Observation;
        net::co_spawn(Ioc, RunProductionRead(Transport, &Observation),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        return Observation;
    }

    auto ObservePreviewData() -> ReadObservation
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->InjectRead({0x10U, 0x20U, 0x30U});
        ReadObservation Observation;
        net::co_spawn(Ioc, RunPreviewRead(Transport, &Observation),
            [&Observation](std::exception_ptr Failure) { Observation.Failure = std::move(Failure); });
        Ioc.run();
        return Observation;
    }

    TEST(TransportContract, DataReadMatches)
    {
        const auto Production = ObserveProductionData();
        const auto Preview = ObservePreviewData();

        ASSERT_FALSE(Production.Failure);
        ASSERT_FALSE(Preview.Failure);
        EXPECT_EQ(StatusOf(Production), ReadStatus::Data);
        EXPECT_EQ(StatusOf(Preview), ReadStatus::Data);
        EXPECT_EQ(Production.Bytes, Preview.Bytes);
        EXPECT_EQ(Production.Data, Preview.Data);
    }

    constexpr std::array<std::byte, 3> ShutdownWritePayload{
        std::byte{0xA0}, std::byte{0xB0}, std::byte{0xC0}};

    auto RunProductionWriteSome(std::shared_ptr<Psm::Testing::ProductionMockTransport> Transport,
                                std::error_code *Error, std::size_t *Bytes) -> net::awaitable<void>
    {
        *Bytes = co_await Transport->async_write_some(ShutdownWritePayload, *Error);
    }

    auto RunPreviewWriteSome(std::shared_ptr<Preview::PreviewMockTransport> Transport,
                             std::error_code *Error, std::size_t *Bytes) -> net::awaitable<void>
    {
        *Bytes = co_await Transport->async_write_some(ShutdownWritePayload, *Error);
    }

    TEST(TransportContract, CloseReadIsEof)
    {
        const auto Production = ObserveProduction(ReadAction::Close);
        const auto Preview = ObservePreview(ReadAction::Close);

        EXPECT_FALSE(Production.Failure);
        EXPECT_FALSE(Preview.Failure);
        EXPECT_EQ(StatusOf(Production), ReadStatus::Eof);
        EXPECT_EQ(StatusOf(Preview), ReadStatus::Eof);
        EXPECT_EQ(Production.Bytes, Preview.Bytes);
    }

    TEST(TransportContract, ShutdownReadIsEof)
    {
        const auto Production = ObserveProduction(ReadAction::Shutdown);
        const auto Preview = ObservePreview(ReadAction::Shutdown);

        EXPECT_FALSE(Production.Failure);
        EXPECT_FALSE(Preview.Failure);
        EXPECT_EQ(StatusOf(Production), ReadStatus::Eof);
        EXPECT_EQ(StatusOf(Preview), ReadStatus::Eof);
        EXPECT_EQ(Production.Bytes, Preview.Bytes);
    }

    TEST(TransportContract, CancelReadIsCanceled)
    {
        const auto Production = ObserveProduction(ReadAction::Cancel);
        const auto Preview = ObservePreview(ReadAction::Cancel);

        EXPECT_FALSE(Production.Failure);
        EXPECT_FALSE(Preview.Failure);
        EXPECT_EQ(StatusOf(Production), ReadStatus::Canceled);
        EXPECT_EQ(StatusOf(Preview), ReadStatus::Canceled);
        EXPECT_EQ(Production.Bytes, Preview.Bytes);
    }

    TEST(TransportContract, ReadErrorIsError)
    {
        const auto Production = ObserveProduction(ReadAction::ReadError);
        const auto Preview = ObservePreview(ReadAction::ReadError);

        EXPECT_FALSE(Production.Failure);
        EXPECT_FALSE(Preview.Failure);
        EXPECT_EQ(StatusOf(Production), ReadStatus::Error);
        EXPECT_EQ(StatusOf(Preview), ReadStatus::Error);
        EXPECT_EQ(Production.Bytes, Preview.Bytes);
    }

    TEST(TransportContract, ShutdownKeepsWriteDirection)
    {
        auto Production = std::make_shared<Psm::Testing::ProductionMockTransport>();
        auto Preview = std::make_shared<Preview::PreviewMockTransport>(
            Production->GetIoContext().get_executor());
        Production->Shutdown();
        Preview->Shutdown();

        std::error_code ProductionError;
        std::error_code PreviewError;
        std::size_t ProductionBytes = 0;
        std::size_t PreviewBytes = 0;
        net::co_spawn(Production->GetIoContext(),
                      RunProductionWriteSome(Production, &ProductionError, &ProductionBytes), net::detached);
        net::co_spawn(Production->GetIoContext(),
                      RunPreviewWriteSome(Preview, &PreviewError, &PreviewBytes), net::detached);

        Production->GetIoContext().run();

        EXPECT_EQ(ProductionBytes, PreviewBytes);
        EXPECT_EQ(ProductionError, std::error_code{});
        EXPECT_EQ(PreviewError, std::error_code{});
        EXPECT_EQ(Production->WrittenData().size(), Preview->Written.size());
    }

    enum class DnsBehavior
    {
        Answer,
        Silent,
        CloseAfterQuery,
    };

    class ContractDnsServer final : public std::enable_shared_from_this<ContractDnsServer>
    {
    public:
        ContractDnsServer(net::io_context &Ioc, const DnsBehavior Behavior)
            : Ex_(Ioc.get_executor()), Behavior_(Behavior),
              Socket_(Ioc, net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0)),
              QueryEvents_(Ex_, 4)
        {
        }

        void Start()
        {
            auto Self = shared_from_this();
            net::co_spawn(Ex_, RunOwned(std::move(Self)), net::detached);
        }

        [[nodiscard]] auto WaitForQuery() -> net::awaitable<void>
        {
            co_await QueryEvents_.async_receive(net::use_awaitable);
        }

        [[nodiscard]] auto Address() const -> std::string
        {
            return Socket_.local_endpoint().address().to_string();
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Socket_.local_endpoint().port();
        }

        void Close()
        {
            Stopped_ = true;
            boost::system::error_code Ec;
            Socket_.close(Ec);
        }

    private:
        static auto RunOwned(std::shared_ptr<ContractDnsServer> Self) -> net::awaitable<void>
        {
            co_await Self->Loop();
        }

        static void Put16(std::vector<std::uint8_t> &Out, const std::uint16_t Value)
        {
            Out.push_back(static_cast<std::uint8_t>(Value >> 8));
            Out.push_back(static_cast<std::uint8_t>(Value & 0xFF));
        }

        static void Put32(std::vector<std::uint8_t> &Out, const std::uint32_t Value)
        {
            Out.push_back(static_cast<std::uint8_t>(Value >> 24));
            Out.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFF));
            Out.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFF));
            Out.push_back(static_cast<std::uint8_t>(Value & 0xFF));
        }

        auto Loop() -> net::awaitable<void>
        {
            std::array<std::uint8_t, 2048> Buffer{};
            net::ip::udp::endpoint Sender;
            while (!Stopped_)
            {
                boost::system::error_code Ec;
                const auto Size = co_await Socket_.async_receive_from(
                    net::buffer(Buffer), Sender, net::redirect_error(net::use_awaitable, Ec));
                if (Ec || Stopped_)
                {
                    co_return;
                }
                (void)QueryEvents_.try_send(boost::system::error_code{});
                if (Size < 12)
                {
                    continue;
                }
                if (Behavior_ == DnsBehavior::Silent)
                {
                    continue;
                }
                if (Behavior_ == DnsBehavior::CloseAfterQuery)
                {
                    Close();
                    co_return;
                }

                std::size_t NameEnd = 12;
                while (NameEnd < Size && Buffer[NameEnd] != 0)
                {
                    const auto LabelSize = static_cast<std::size_t>(Buffer[NameEnd]);
                    if (LabelSize > 63 || NameEnd + 1 + LabelSize >= Size)
                    {
                        break;
                    }
                    NameEnd += 1 + LabelSize;
                }
                const auto QuestionEnd = NameEnd + 5;
                if (QuestionEnd > Size)
                {
                    continue;
                }
                const auto QueryType = static_cast<std::uint16_t>(Buffer[NameEnd + 1]) << 8 |
                                         Buffer[NameEnd + 2];
                const bool IsAaaa = QueryType == 28;
                std::vector<std::uint8_t> Response;
                Response.reserve(64);
                Put16(Response, static_cast<std::uint16_t>(Buffer[0]) << 8 | Buffer[1]);
                Put16(Response, 0x8180);
                Put16(Response, 1);
                Put16(Response, 1);
                Put16(Response, 0);
                Put16(Response, 0);
                Response.insert(Response.end(), Buffer.begin() + 12,
                                Buffer.begin() + static_cast<std::ptrdiff_t>(QuestionEnd));
                Put16(Response, 0xC00C);
                Put16(Response, IsAaaa ? 28 : 1);
                Put16(Response, 1);
                Put32(Response, 60);
                if (IsAaaa)
                {
                    Put16(Response, 16);
                    Response.insert(Response.end(), {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 1});
                }
                else
                {
                    Put16(Response, 4);
                    Response.insert(Response.end(), {1, 2, 3, 4});
                }
                (void)co_await Socket_.async_send_to(
                    net::buffer(Response), Sender, net::redirect_error(net::use_awaitable, Ec));
            }
        }

        net::any_io_executor Ex_;
        DnsBehavior Behavior_;
        net::ip::udp::socket Socket_;
        net::experimental::channel<void(boost::system::error_code)> QueryEvents_;
        bool Stopped_{false};
    };

    enum class DnsStatus
    {
        Success,
        Timeout,
        Canceled,
        NotSupported,
        Failure,
    };

    struct DnsObservation
    {
        DnsStatus Status{DnsStatus::Failure};
        std::vector<net::ip::address> Addresses;
        bool Completed{false};
        bool OwnerReleased{false};
        std::exception_ptr Failure;
    };

    [[nodiscard]] auto ProductionDnsStatus(const psm::dns::query_result &Result) -> DnsStatus;
    [[nodiscard]] auto PreviewDnsStatus(const Preview::Network::Dns::QueryResult &Result) -> DnsStatus;

    auto RunProductionDnsQuery(std::unique_ptr<psm::dns::upstream> *Owner, DnsObservation *Observation,
                               bool ReleaseOwner) -> net::awaitable<void>
    {
        const auto Result = co_await (*Owner)->resolve("contract.local", psm::dns::qtype::a);
        Observation->Status = ProductionDnsStatus(Result);
        Observation->Addresses.assign(Result.ips.begin(), Result.ips.end());
        Observation->Completed = true;
        if (ReleaseOwner)
        {
            Owner->reset();
        }
    }

    auto RunPreviewDnsQuery(std::unique_ptr<Preview::Network::Dns::Upstream> *Owner,
                            DnsObservation *Observation, bool ReleaseOwner) -> net::awaitable<void>
    {
        const auto Result = co_await (*Owner)->Resolve("contract.local", Preview::Network::Dns::QType::A);
        Observation->Status = PreviewDnsStatus(Result);
        Observation->Addresses = Result.Ips;
        Observation->Completed = true;
        if (ReleaseOwner)
        {
            Owner->reset();
        }
    }

    struct ProductionConcurrentDnsTask
    {
        std::shared_ptr<psm::dns::upstream> *Owner;
        DnsObservation *Observation;
        std::shared_ptr<ContractDnsServer> Fast;
        std::shared_ptr<ContractDnsServer> Slow;
    };

    auto RunProductionConcurrentDnsQuery(ProductionConcurrentDnsTask Task) -> net::awaitable<void>
    {
        const auto Result = co_await (*Task.Owner)->resolve("contract-concurrent.local", psm::dns::qtype::a);
        Task.Observation->Status = ProductionDnsStatus(Result);
        Task.Observation->Addresses.assign(Result.ips.begin(), Result.ips.end());
        Task.Observation->Completed = true;
        co_await Task.Slow->WaitForQuery();
        Task.Owner->reset();
        Task.Observation->OwnerReleased = true;
        Task.Fast->Close();
        Task.Slow->Close();
    }

    struct PreviewConcurrentDnsTask
    {
        std::shared_ptr<Preview::Network::Dns::Upstream> *Owner;
        DnsObservation *Observation;
        std::shared_ptr<ContractDnsServer> Fast;
        std::shared_ptr<ContractDnsServer> Slow;
    };

    auto RunPreviewConcurrentDnsQuery(PreviewConcurrentDnsTask Task) -> net::awaitable<void>
    {
        const auto Result = co_await (*Task.Owner)->Resolve(
            "contract-concurrent.local", Preview::Network::Dns::QType::A);
        Task.Observation->Status = PreviewDnsStatus(Result);
        Task.Observation->Addresses = Result.Ips;
        Task.Observation->Completed = true;
        co_await Task.Slow->WaitForQuery();
        Task.Owner->reset();
        Task.Observation->OwnerReleased = true;
        Task.Fast->Close();
        Task.Slow->Close();
    }

    auto RunProductionStackDnsQuery(psm::dns::upstream *Owner, DnsObservation *Observation) -> net::awaitable<void>
    {
        const auto Result = co_await Owner->resolve("contract-stack.local", psm::dns::qtype::a);
        Observation->Status = ProductionDnsStatus(Result);
        Observation->Completed = true;
    }

    auto RunPreviewStackDnsQuery(Preview::Network::Dns::Upstream *Owner, DnsObservation *Observation)
        -> net::awaitable<void>
    {
        const auto Result = co_await Owner->Resolve(
            "contract-stack.local", Preview::Network::Dns::QType::A);
        Observation->Status = PreviewDnsStatus(Result);
        Observation->Completed = true;
    }

    auto RunProductionEmptyDnsQuery(psm::dns::upstream *Owner, psm::dns::query_result *Result)
        -> net::awaitable<void>
    {
        *Result = co_await Owner->resolve("contract-empty.example", psm::dns::qtype::a);
    }

    auto RunPreviewEmptyDnsQuery(Preview::Network::Dns::Upstream *Owner,
                                 Preview::Network::Dns::QueryResult *Result) -> net::awaitable<void>
    {
        *Result = co_await Owner->Resolve("contract-empty.example", Preview::Network::Dns::QType::A);
    }

    [[nodiscard]] auto ProductionDnsStatus(const psm::dns::query_result &Result) -> DnsStatus
    {
        if (Result.error == psm::fault::code::timeout)
        {
            return DnsStatus::Timeout;
        }
        if (Result.error == psm::fault::code::canceled)
        {
            return DnsStatus::Canceled;
        }
        if (Result.error == psm::fault::code::not_supported)
        {
            return DnsStatus::NotSupported;
        }
        if (Result.error == psm::fault::code::success && !Result.ips.empty())
        {
            return DnsStatus::Success;
        }
        return DnsStatus::Failure;
    }

    [[nodiscard]] auto PreviewDnsStatus(const Preview::Network::Dns::QueryResult &Result) -> DnsStatus
    {
        if (Result.Error == Preview::make_error_code(Preview::Error::Timeout))
        {
            return DnsStatus::Timeout;
        }
        if (Result.Error == Preview::make_error_code(Preview::Error::Canceled))
        {
            return DnsStatus::Canceled;
        }
        if (Result.Error == Preview::make_error_code(Preview::Error::NotSupported))
        {
            return DnsStatus::NotSupported;
        }
        if (!Result.Error && !Result.Ips.empty())
        {
            return DnsStatus::Success;
        }
        return DnsStatus::Failure;
    }

    auto RunProductionDns(const DnsBehavior Behavior, const bool ReleaseOwner) -> DnsObservation
    {
        net::io_context Ioc;
        auto Fake = std::make_shared<ContractDnsServer>(Ioc, Behavior);
        Fake->Start();
        auto Owner = std::make_unique<psm::dns::upstream>(Ioc);
        psm::dns::server Server(psm::memory::current_resource());
        Server.address = Fake->Address();
        Server.port = Fake->Port();
        Server.protocol = psm::dns::protocol::udp;
        Server.timeout_ms = 40;
        psm::memory::vector<psm::dns::server> Servers(psm::memory::current_resource());
        Servers.push_back(Server);
        Owner->set_servers(Servers);
        Owner->set_mode(psm::dns::mode::fallback);
        Owner->set_timeout(40);

        DnsObservation Observation;
        net::co_spawn(Ioc, RunProductionDnsQuery(&Owner, &Observation, ReleaseOwner),
            [&](std::exception_ptr Failure)
            {
                Observation.Failure = std::move(Failure);
                Ioc.stop();
            });
        Ioc.run();
        Observation.OwnerReleased = Owner == nullptr;
        Fake->Close();
        Ioc.restart();
        Ioc.run();
        return Observation;
    }

    auto RunPreviewDns(const DnsBehavior Behavior, const bool ReleaseOwner) -> DnsObservation
    {
        net::io_context Ioc;
        auto Fake = std::make_shared<ContractDnsServer>(Ioc, Behavior);
        Fake->Start();
        Preview::Network::Dns::Server Server;
        Server.Address = Fake->Address();
        Server.Port = Fake->Port();
        Server.Proto = Preview::Network::Dns::Protocol::Udp;
        Server.TimeoutMs = 40;
        std::vector<Preview::Network::Dns::Server> Servers{Server};
        auto Owner = std::make_unique<Preview::Network::Dns::Upstream>(
            Ioc.get_executor(), std::move(Servers), Preview::Network::Dns::Mode::Fallback);
        Owner->SetTimeout(std::chrono::milliseconds(40));

        DnsObservation Observation;
        net::co_spawn(Ioc, RunPreviewDnsQuery(&Owner, &Observation, ReleaseOwner),
            [&](std::exception_ptr Failure)
            {
                Observation.Failure = std::move(Failure);
                Ioc.stop();
            });
        Ioc.run();
        Observation.OwnerReleased = Owner == nullptr;
        Fake->Close();
        Ioc.restart();
        Ioc.run();
        return Observation;
    }

    auto RunProductionConcurrentDnsOwnerRelease() -> DnsObservation
    {
        net::io_context Ioc;
        auto Fast = std::make_shared<ContractDnsServer>(Ioc, DnsBehavior::Answer);
        auto Slow = std::make_shared<ContractDnsServer>(Ioc, DnsBehavior::Silent);
        Fast->Start();
        Slow->Start();

        auto Owner = std::make_shared<psm::dns::upstream>(Ioc);
        psm::dns::server FastConfig(psm::memory::current_resource());
        FastConfig.address = Fast->Address();
        FastConfig.port = Fast->Port();
        FastConfig.protocol = psm::dns::protocol::udp;
        FastConfig.timeout_ms = 40;
        psm::dns::server SlowConfig(psm::memory::current_resource());
        SlowConfig.address = Slow->Address();
        SlowConfig.port = Slow->Port();
        SlowConfig.protocol = psm::dns::protocol::udp;
        SlowConfig.timeout_ms = 40;
        psm::memory::vector<psm::dns::server> Servers(psm::memory::current_resource());
        Servers.push_back(FastConfig);
        Servers.push_back(SlowConfig);
        Owner->set_servers(Servers);
        Owner->set_mode(psm::dns::mode::first);
        Owner->set_timeout(40);

        DnsObservation Observation;
        std::exception_ptr Failure;
        net::co_spawn(Ioc, RunProductionConcurrentDnsQuery(
                              ProductionConcurrentDnsTask{&Owner, &Observation, Fast, Slow}),
            [&](std::exception_ptr Error) { Failure = std::move(Error); });
        Ioc.run();
        if (Failure)
        {
            Observation.Failure = std::move(Failure);
        }
        return Observation;
    }

    auto RunPreviewConcurrentDnsOwnerRelease() -> DnsObservation
    {
        net::io_context Ioc;
        auto Fast = std::make_shared<ContractDnsServer>(Ioc, DnsBehavior::Answer);
        auto Slow = std::make_shared<ContractDnsServer>(Ioc, DnsBehavior::Silent);
        Fast->Start();
        Slow->Start();

        Preview::Network::Dns::Server FastConfig;
        FastConfig.Address = Fast->Address();
        FastConfig.Port = Fast->Port();
        FastConfig.Proto = Preview::Network::Dns::Protocol::Udp;
        FastConfig.TimeoutMs = 40;
        Preview::Network::Dns::Server SlowConfig;
        SlowConfig.Address = Slow->Address();
        SlowConfig.Port = Slow->Port();
        SlowConfig.Proto = Preview::Network::Dns::Protocol::Udp;
        SlowConfig.TimeoutMs = 40;
        std::vector<Preview::Network::Dns::Server> Servers{FastConfig, SlowConfig};
        auto Owner = std::make_shared<Preview::Network::Dns::Upstream>(
            Ioc.get_executor(), std::move(Servers), Preview::Network::Dns::Mode::First);
        Owner->SetTimeout(std::chrono::milliseconds(40));

        DnsObservation Observation;
        std::exception_ptr Failure;
        net::co_spawn(Ioc, RunPreviewConcurrentDnsQuery(
                              PreviewConcurrentDnsTask{&Owner, &Observation, Fast, Slow}),
            [&](std::exception_ptr Error) { Failure = std::move(Error); });
        Ioc.run();
        if (Failure)
        {
            Observation.Failure = std::move(Failure);
        }
        return Observation;
    }

    auto RunProductionStackConcurrentDns() -> DnsObservation
    {
        net::io_context Ioc;
        psm::dns::upstream Owner(Ioc);
        psm::dns::server First(psm::memory::current_resource());
        First.address = "127.0.0.1";
        First.port = 1;
        psm::dns::server Second(psm::memory::current_resource());
        Second.address = "127.0.0.1";
        Second.port = 2;
        psm::memory::vector<psm::dns::server> Servers(psm::memory::current_resource());
        Servers.push_back(First);
        Servers.push_back(Second);
        Owner.set_servers(Servers);
        Owner.set_mode(psm::dns::mode::first);

        DnsObservation Observation;
        net::co_spawn(Ioc, RunProductionStackDnsQuery(&Owner, &Observation),
            [&](std::exception_ptr Failure)
            {
                Observation.Failure = std::move(Failure);
                Ioc.stop();
            });
        Ioc.run();
        return Observation;
    }

    auto RunPreviewStackConcurrentDns() -> DnsObservation
    {
        net::io_context Ioc;
        Preview::Network::Dns::Server First;
        First.Address = "127.0.0.1";
        First.Port = 1;
        Preview::Network::Dns::Server Second;
        Second.Address = "127.0.0.1";
        Second.Port = 2;
        std::vector<Preview::Network::Dns::Server> Servers{First, Second};
        Preview::Network::Dns::Upstream Owner(
            Ioc.get_executor(), std::move(Servers), Preview::Network::Dns::Mode::First);

        DnsObservation Observation;
        net::co_spawn(Ioc, RunPreviewStackDnsQuery(&Owner, &Observation),
            [&](std::exception_ptr Failure)
            {
                Observation.Failure = std::move(Failure);
                Ioc.stop();
            });
        Ioc.run();
        return Observation;
    }

    TEST(TransportContract, DnsSuccessMatches)
    {
        const auto Production = RunProductionDns(DnsBehavior::Answer, false);
        const auto Preview = RunPreviewDns(DnsBehavior::Answer, false);
        ASSERT_FALSE(Production.Failure);
        ASSERT_FALSE(Preview.Failure);
        ASSERT_TRUE(Production.Completed);
        ASSERT_TRUE(Preview.Completed);
        EXPECT_EQ(Production.Status, DnsStatus::Success);
        EXPECT_EQ(Preview.Status, DnsStatus::Success);
        EXPECT_EQ(Production.Addresses, Preview.Addresses);
    }

    TEST(TransportContract, DnsTimeoutMatches)
    {
        const auto Production = RunProductionDns(DnsBehavior::Silent, false);
        const auto Preview = RunPreviewDns(DnsBehavior::Silent, false);
        ASSERT_FALSE(Production.Failure);
        ASSERT_FALSE(Preview.Failure);
        EXPECT_EQ(Production.Status, DnsStatus::Timeout);
        EXPECT_EQ(Preview.Status, DnsStatus::Timeout);
        EXPECT_TRUE(Production.Addresses.empty());
        EXPECT_TRUE(Preview.Addresses.empty());
    }

    TEST(TransportContract, DnsCloseAfterQueryMatches)
    {
        const auto Production = RunProductionDns(DnsBehavior::CloseAfterQuery, false);
        const auto Preview = RunPreviewDns(DnsBehavior::CloseAfterQuery, false);
        ASSERT_FALSE(Production.Failure);
        ASSERT_FALSE(Preview.Failure);
        EXPECT_EQ(Production.Status, DnsStatus::Timeout);
        EXPECT_EQ(Preview.Status, DnsStatus::Timeout);
        EXPECT_EQ(Production.Addresses, Preview.Addresses);
    }

    TEST(TransportContract, DnsOwnerReleaseAfterCompletionMatches)
    {
        const auto Production = RunProductionDns(DnsBehavior::Answer, true);
        const auto Preview = RunPreviewDns(DnsBehavior::Answer, true);
        ASSERT_FALSE(Production.Failure);
        ASSERT_FALSE(Preview.Failure);
        EXPECT_TRUE(Production.OwnerReleased);
        EXPECT_TRUE(Preview.OwnerReleased);
        EXPECT_EQ(Production.Status, DnsStatus::Success);
        EXPECT_EQ(Preview.Status, DnsStatus::Success);
        EXPECT_EQ(Production.Addresses, Preview.Addresses);
    }

    TEST(TransportContract, DnsConcurrentOwnerReleaseMatches)
    {
        const auto Production = RunProductionConcurrentDnsOwnerRelease();
        const auto Preview = RunPreviewConcurrentDnsOwnerRelease();
        ASSERT_FALSE(Production.Failure);
        ASSERT_FALSE(Preview.Failure);
        EXPECT_TRUE(Production.OwnerReleased);
        EXPECT_TRUE(Preview.OwnerReleased);
        EXPECT_EQ(Production.Status, DnsStatus::Success);
        EXPECT_EQ(Preview.Status, DnsStatus::Success);
        EXPECT_EQ(Production.Addresses, Preview.Addresses);
    }

    TEST(TransportContract, DnsConcurrentStackOwnerRejectedMatches)
    {
        const auto Production = RunProductionStackConcurrentDns();
        const auto Preview = RunPreviewStackConcurrentDns();
        ASSERT_FALSE(Production.Failure);
        ASSERT_FALSE(Preview.Failure);
        ASSERT_TRUE(Production.Completed);
        ASSERT_TRUE(Preview.Completed);
        EXPECT_EQ(Production.Status, DnsStatus::NotSupported);
        EXPECT_EQ(Preview.Status, DnsStatus::NotSupported);
    }

    TEST(TransportContract, DnsEmptyUpstreamFailureMatches)
    {
        net::io_context ProductionIoc;
        psm::dns::upstream Production(ProductionIoc);
        psm::dns::query_result ProductionResult;
        std::exception_ptr ProductionFailure;
        net::co_spawn(ProductionIoc, RunProductionEmptyDnsQuery(&Production, &ProductionResult),
            [&](std::exception_ptr Failure) { ProductionFailure = std::move(Failure); });
        ProductionIoc.run();

        net::io_context PreviewIoc;
        Preview::Network::Dns::Upstream PreviewUpstream(
            PreviewIoc.get_executor(), std::vector<Preview::Network::Dns::Server>{});
        Preview::Network::Dns::QueryResult PreviewResult;
        std::exception_ptr PreviewFailure;
        net::co_spawn(PreviewIoc, RunPreviewEmptyDnsQuery(&PreviewUpstream, &PreviewResult),
            [&](std::exception_ptr Failure) { PreviewFailure = std::move(Failure); });
        PreviewIoc.run();

        ASSERT_FALSE(ProductionFailure);
        ASSERT_FALSE(PreviewFailure);
        EXPECT_EQ(ProductionResult.error, psm::fault::code::dns_failed);
        EXPECT_EQ(PreviewResult.Error, Preview::make_error_code(Preview::Error::BadAddress));
        EXPECT_TRUE(ProductionResult.ips.empty());
        EXPECT_TRUE(PreviewResult.Ips.empty());
    }

} // namespace
