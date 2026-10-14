/**
 * @file TransmissionHandlerTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "CoreTransmissionTestSupport.hpp"

TEST(CoreTransmission, HandlerReadSuccess)
    {
        // completion-handler 桥接：成功路径（ToEc 空错误分支）
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        TransportObject->SetReadData({std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}});
        std::byte IoBuffer[8]{};
        std::error_code ObservedError{static_cast<int>(std::errc::invalid_argument), std::generic_category()};
        std::size_t ObservedBytes = 0;

        TransportObject->ReadSome(IoBuffer, [&](Preview::IoResult Result)
                           { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                               ObservedError = OperationFailure;
                               ObservedBytes = ByteCount;
                           });
        Loop.run();

        EXPECT_FALSE(ObservedError);
        EXPECT_EQ(ObservedBytes, 5);
    }

TEST(CoreTransmission, HandlerWriteSuccess)
    {
        // completion-handler 桥接：写入成功路径
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        const std::byte IoBuffer[3]{};
        std::error_code ObservedError{static_cast<int>(std::errc::invalid_argument), std::generic_category()};
        std::size_t ObservedBytes = 0;

        TransportObject->WriteSome(IoBuffer, [&](Preview::IoResult Result)
                            { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                                ObservedError = OperationFailure;
                                ObservedBytes = ByteCount;
                            });
        Loop.run();

        EXPECT_FALSE(ObservedError);
        EXPECT_EQ(ObservedBytes, 3);
        EXPECT_EQ(TransportObject->Written_, 3);
    }

TEST(CoreTransmission, HandlerReadErrorProtocol)
    {
        // completion-handler 桥接：Preview 协议错误 → boost 侧保留协议分类
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        TransportObject->SetReadError(
            static_cast<std::error_code>(Preview::make_error_code(Preview::Error::NeedMore)));
        std::byte IoBuffer[8]{};
        std::error_code ObservedError;
        std::size_t ObservedBytes = 999;

        TransportObject->ReadSome(IoBuffer, [&](Preview::IoResult Result)
                           { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                               ObservedError = OperationFailure;
                               ObservedBytes = ByteCount;
                           });
        Loop.run();

        EXPECT_EQ(ObservedBytes, 0);
        EXPECT_TRUE(ObservedError);
        EXPECT_EQ(std::string_view(ObservedError.category().name()), "prism.protocol");
        EXPECT_EQ(ObservedError.value(), static_cast<int>(Preview::Error::NeedMore));
    }

TEST(CoreTransmission, HandlerWriteErrorGeneric)
    {
        // completion-handler 桥接：非协议错误 → boost 侧归入 generic 分类
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        TransportObject->SetWriteError(std::make_error_code(std::errc::io_error));
        const std::byte IoBuffer[8]{};
        std::error_code ObservedError;
        std::size_t ObservedBytes = 999;

        TransportObject->WriteSome(IoBuffer, [&](Preview::IoResult Result)
                            { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                                ObservedError = OperationFailure;
                                ObservedBytes = ByteCount;
                            });
        Loop.run();

        EXPECT_EQ(ObservedBytes, 0);
        EXPECT_TRUE(ObservedError);
        EXPECT_EQ(std::string_view(ObservedError.category().name()), "generic");
        EXPECT_EQ(ObservedError.value(), static_cast<int>(std::errc::io_error));
    }

TEST(CoreTransmission, HandlerReadPreservesFaultCanceledCategoryExactlyOnce)
    {
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        TransportObject->SetReadError(Preview::Fault::make_error_code(Preview::Fault::Code::Canceled));
        std::byte IoBuffer[8]{};
        std::error_code ObservedError;
        std::size_t ObservedBytes = 999;
        std::size_t Calls = 0;

        TransportObject->ReadSome(IoBuffer, [&](Preview::IoResult Result)
                           { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                               ++Calls;
                               ObservedError = OperationFailure;
                               ObservedBytes = ByteCount;
                           });
        Loop.run();

        EXPECT_EQ(Calls, 1U);
        EXPECT_EQ(ObservedBytes, 0U);
        EXPECT_EQ(std::string_view(ObservedError.category().name()), "Preview::fault");
        EXPECT_EQ(ObservedError.value(), static_cast<int>(Preview::Fault::Code::Canceled));
        EXPECT_EQ(Preview::Fault::ToCode(ObservedError), Preview::Fault::Code::Canceled);
    }

TEST(CoreTransmission, HandlerReadPreservesFaultEofCategoryExactlyOnce)
    {
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        TransportObject->SetReadError(Preview::Fault::make_error_code(Preview::Fault::Code::Eof));
        std::byte IoBuffer[8]{};
        std::error_code ObservedError;
        std::size_t ObservedBytes = 999;
        std::size_t Calls = 0;

        TransportObject->ReadSome(IoBuffer, [&](Preview::IoResult Result)
                           { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                               ++Calls;
                               ObservedError = OperationFailure;
                               ObservedBytes = ByteCount;
                           });
        Loop.run();

        EXPECT_EQ(Calls, 1U);
        EXPECT_EQ(ObservedBytes, 0U);
        EXPECT_EQ(std::string_view(ObservedError.category().name()), "Preview::fault");
        EXPECT_EQ(ObservedError.value(), static_cast<int>(Preview::Fault::Code::Eof));
        EXPECT_EQ(Preview::Fault::ToCode(ObservedError), Preview::Fault::Code::Eof);
    }

TEST(CoreTransmission, HandlerWritePreservesFaultCanceledCategoryExactlyOnce)
    {
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        TransportObject->SetWriteError(Preview::Fault::make_error_code(Preview::Fault::Code::Canceled));
        const std::byte IoBuffer[8]{};
        std::error_code ObservedError;
        std::size_t ObservedBytes = 999;
        std::size_t Calls = 0;

        TransportObject->WriteSome(IoBuffer, [&](Preview::IoResult Result)
                            { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                                ++Calls;
                                ObservedError = OperationFailure;
                                ObservedBytes = ByteCount;
                            });
        Loop.run();

        EXPECT_EQ(Calls, 1U);
        EXPECT_EQ(ObservedBytes, 0U);
        EXPECT_EQ(std::string_view(ObservedError.category().name()), "Preview::fault");
        EXPECT_EQ(ObservedError.value(), static_cast<int>(Preview::Fault::Code::Canceled));
        EXPECT_EQ(Preview::Fault::ToCode(ObservedError), Preview::Fault::Code::Canceled);
    }

TEST(CoreTransmission, HandlerWritePreservesFaultEofCategoryExactlyOnce)
    {
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        TransportObject->SetWriteError(Preview::Fault::make_error_code(Preview::Fault::Code::Eof));
        const std::byte IoBuffer[8]{};
        std::error_code ObservedError;
        std::size_t ObservedBytes = 999;
        std::size_t Calls = 0;

        TransportObject->WriteSome(IoBuffer, [&](Preview::IoResult Result)
                            { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                                ++Calls;
                                ObservedError = OperationFailure;
                                ObservedBytes = ByteCount;
                            });
        Loop.run();

        EXPECT_EQ(Calls, 1U);
        EXPECT_EQ(ObservedBytes, 0U);
        EXPECT_EQ(std::string_view(ObservedError.category().name()), "Preview::fault");
        EXPECT_EQ(ObservedError.value(), static_cast<int>(Preview::Fault::Code::Eof));
        EXPECT_EQ(Preview::Fault::ToCode(ObservedError), Preview::Fault::Code::Eof);
    }

TEST(CoreTransmission, HandlerReadPreservesStdSystemCategory)
    {
        Net::io_context Loop;
        auto TransportObject = std::make_shared<MockTransmission>(Loop.get_executor());
        const std::error_code Source{
            static_cast<int>(std::errc::operation_canceled), std::system_category()};
        ASSERT_EQ(std::string_view(Source.category().name()), "system");
        TransportObject->SetReadError(Source);
        std::byte IoBuffer[8]{};
        std::error_code ObservedError;
        std::size_t ObservedBytes = 999;

        TransportObject->ReadSome(IoBuffer, [&](Preview::IoResult Result)
                           { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                               ObservedError = OperationFailure;
                               ObservedBytes = ByteCount;
                           });
        Loop.run();

        EXPECT_EQ(ObservedBytes, 0U);
        EXPECT_EQ(std::string_view(ObservedError.category().name()), "system");
        EXPECT_EQ(ObservedError.value(), Source.value());
    }

TEST(CoreTransmission, CompletionHandlerReportsReadException)
    {
        auto ContextOwner = Preview::Executor::ContextOwner::Create(std::make_shared<Preview::Executor::ClosingStorage>());
        auto& Loop = ContextOwner->Io;
        auto Transport = std::make_shared<ThrowingTransmission>(Loop.get_executor());
        std::array<std::byte, 4> Buffer{};
        bool Called = false;
        std::error_code Error;
        std::size_t Bytes = 1;

        Transport->ReadSome(
            Buffer,
            [&](Preview::IoResult Result)
            { const auto Ec = Result.Failure.Native; const auto N = Result.Bytes;
                Called = true;
                Error = Ec;
                Bytes = N;
            });
        std::string FatalMessage;
        try { Loop.run(); } catch (const std::runtime_error& Fatal) { FatalMessage = Fatal.what(); }
        Preview::Fault::Failure DrainFailure;
        Net::co_spawn(Loop, Transport->Activity()->Drain(),
            [&Loop, &DrainFailure](std::exception_ptr, Preview::Transmission::ControlResult Result)
            { if (!Result) DrainFailure = Result.error(); Loop.stop(); });
        Loop.run();

        EXPECT_FALSE(Called);
        EXPECT_EQ(FatalMessage, "read failure");
        EXPECT_EQ(DrainFailure.Code, Preview::Fault::Code::Blocked);
    }

TEST(CoreTransmission, CompletionHandlerReportsWriteException)
    {
        auto ContextOwner = Preview::Executor::ContextOwner::Create(std::make_shared<Preview::Executor::ClosingStorage>());
        auto& Loop = ContextOwner->Io;
        auto Transport = std::make_shared<ThrowingTransmission>(Loop.get_executor());
        const std::array<std::byte, 4> Buffer{};
        bool Called = false;
        std::error_code Error;
        std::size_t Bytes = 1;

        Transport->WriteSome(
            Buffer,
            [&](Preview::IoResult Result)
            { const auto Ec = Result.Failure.Native; const auto N = Result.Bytes;
                Called = true;
                Error = Ec;
                Bytes = N;
            });
        std::string FatalMessage;
        try { Loop.run(); } catch (const std::runtime_error& Fatal) { FatalMessage = Fatal.what(); }
        Preview::Fault::Failure DrainFailure;
        Net::co_spawn(Loop, Transport->Activity()->Drain(),
            [&Loop, &DrainFailure](std::exception_ptr, Preview::Transmission::ControlResult Result)
            { if (!Result) DrainFailure = Result.error(); Loop.stop(); });
        Loop.run();

        EXPECT_FALSE(Called);
        EXPECT_EQ(FatalMessage, "write failure");
        EXPECT_EQ(DrainFailure.Code, Preview::Fault::Code::Blocked);
    }

TEST(CoreTransmission, CompletionHandlerRejectsStackOwnedTransport)
    {
        Net::io_context Loop;
        MockTransmission TransportObject(Loop.get_executor());
        bool Called = false;
        TransportObject.ReadSome(std::span<std::byte>{},
                          [&](Preview::IoResult Result)
                          { const auto OperationFailure = Result.Failure.Native; const auto ByteCount = Result.Bytes;
                              Called = true;
                              EXPECT_EQ(ByteCount, 0u);
                              EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::InvalidArgument);
                          });
        Loop.run();
        EXPECT_TRUE(Called);
    }

