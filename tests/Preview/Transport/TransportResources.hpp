/**
 * @file TransportResources.hpp
 * @brief 提供 Transport 测试共用的有主资源构造与关闭回执。
 */
#pragma once

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Pad.hpp>
#include <Preview/Transport/Replay.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <exception>
#include <memory>
#include <stdexcept>
#include <utility>

namespace Preview::Testing
{
    /**
     * @brief 分别保留 Close 与 Drain 的原始结果，不折叠主错误。
     */
    struct FixtureCloseReceipt final
    {
        Preview::Transmission::ControlResult Close;
        Preview::Transmission::ControlResult Drain;

        /** @brief 仅当控制关闭与活动退栈都成功时返回真。 */
        [[nodiscard]] auto Succeeded() const noexcept -> bool
        {
            return Close.has_value() && Drain.has_value();
        }
    };

    /**
     * @brief 在测试报告中分别验证 Close 与 Drain，并显示原始错误原因。
     * @param Receipt 同一 owner 上真实取得的 Close 与 Drain 回执。
     */
    inline auto ExpectFixtureCloseReceipt(const FixtureCloseReceipt& Receipt) -> void
    {
        if (!Receipt.Close)
        {
            ADD_FAILURE() << "Close failed: code="
                          << static_cast<unsigned>(Receipt.Close.error().Code)
                          << ", native="
                          << Receipt.Close.error().Native.category().name()
                          << ":" << Receipt.Close.error().Native.value();
        }
        if (!Receipt.Drain)
        {
            ADD_FAILURE() << "Drain failed: code="
                          << static_cast<unsigned>(Receipt.Drain.error().Code)
                          << ", native="
                          << Receipt.Drain.error().Native.category().name()
                          << ":" << Receipt.Drain.error().Native.value();
        }
    }

    /**
     * @brief 在载体原 executor 上关闭并等待其全部活动退出。
     * @param Carrier 调用方持有的实际关闭 owner；本协程在 Drain 完成前保留它。
     * @return 独立返回 Close 与 Drain 结果；关闭失败时仍等待 Drain，保留两种原因。
     * @note 取消和半关闭由调用方按场景发起；本函数仅执行最终 Close。
     */
    inline auto CloseFixture(std::shared_ptr<Preview::Transmission> Carrier)
        -> boost::asio::awaitable<FixtureCloseReceipt>
    {
        const auto Close = Carrier->Close();
        const auto Drain = co_await Carrier->Activity()->Drain();
        co_return FixtureCloseReceipt{Close, Drain};
    }

    /**
     * @brief 等待已经发起关闭的实际 owner 完成活动退栈。
     * @param Carrier 调用方持有的关闭 owner。
     * @return Drain 的原始 ControlResult。
     */
    inline auto DrainFixture(std::shared_ptr<Preview::Transmission> Carrier)
        -> boost::asio::awaitable<Preview::Transmission::ControlResult>
    {
        co_return co_await Carrier->Activity()->Drain();
    }

    /**
     * @brief 重启已自然跑空的测试 executor，等待已关闭 owner 的活动退栈。
     * @param Context 承载 Carrier 固定 executor 的测试 io_context。
     * @param Carrier 调用方持有的关闭 owner。
     * @return Drain 的原始 ControlResult；异常仍传播。
     */
    inline auto DriveDrain(
        boost::asio::io_context& Context,
        std::shared_ptr<Preview::Transmission> Carrier)
        -> Preview::Transmission::ControlResult
    {
        Context.restart();
        std::exception_ptr Fatal;
        bool Completed = false;
        Preview::Transmission::ControlResult Result;
        boost::asio::co_spawn(
            Context, DrainFixture(std::move(Carrier)),
            [&Fatal, &Completed, &Result](std::exception_ptr Error, Preview::Transmission::ControlResult Value)
            {
                Fatal = std::move(Error);
                Result = std::move(Value);
                Completed = true;
            });
        Context.run();
        if (Fatal) std::rethrow_exception(Fatal);
        if (!Completed) throw std::logic_error("Transport fixture drain did not complete");
        return Result;
    }

    /**
     * @brief 重启已自然跑空的测试 executor，执行有主 owner 的关闭与完整 Drain。
     * @param Context 承载 Carrier 固定 executor 的测试 io_context。
     * @param Carrier 调用方持有的实际关闭 owner。
     * @return 独立返回 Close 与 Drain 的真实结果。
     * @note 只用于测试协程外；异常仍传播，未交付完成回执视为测试 harness 错误。
     */
    inline auto DriveClose(
        boost::asio::io_context& Context,
        std::shared_ptr<Preview::Transmission> Carrier) -> FixtureCloseReceipt
    {
        Context.restart();
        std::exception_ptr Fatal;
        bool Completed = false;
        FixtureCloseReceipt Result;
        boost::asio::co_spawn(
            Context, CloseFixture(std::move(Carrier)),
            [&Fatal, &Completed, &Result](std::exception_ptr Error, FixtureCloseReceipt Value)
            {
                Fatal = std::move(Error);
                Result = std::move(Value);
                Completed = true;
            });
        Context.run();
        if (Fatal) std::rethrow_exception(Fatal);
        if (!Completed) throw std::logic_error("Transport fixture close did not complete");
        return Result;
    }

    /**
     * @brief 一对仅含 shared owner 的 MemoryStream 端点。
     * @details 消费者需要借用对象时，应在 owner 仍存活的词法作用域内显式解引用。
     */
    struct OwnedTransportPair final
    {
        std::shared_ptr<Preview::MemoryStream> FirstOwner;
        std::shared_ptr<Preview::MemoryStream> SecondOwner;
    };

    /**
     * @brief 在给定 executor 上建立具备明确 shared owner 的双端 MemoryStream。
     * @param Executor 两端共用的 Asio executor。
     * @return 两端唯一的 shared owner；不返回可脱离 owner 的引用句柄。
     */
    [[nodiscard]] inline auto MakeOwnedTransportPair(
        boost::asio::any_io_executor Executor) -> OwnedTransportPair
    {
        auto [First, Second] = Preview::MakeMemoryPair(std::move(Executor));
        auto FirstOwner = std::make_shared<Preview::MemoryStream>(std::move(First));
        auto SecondOwner = std::make_shared<Preview::MemoryStream>(std::move(Second));
        return {std::move(FirstOwner), std::move(SecondOwner)};
    }

    /**
     * @brief 为单个测试操作创建独立的有界字节池。
     * @return 上限为 64 KiB 且最多 64 个块的 shared owner。
     */
    [[nodiscard]] inline auto MakeTransportBytes() -> std::shared_ptr<Memory::BytePool>
    {
        return std::make_shared<Memory::BytePool>(Memory::BytePoolOptions{64U * 1024U, 64});
    }

    /**
     * @brief 冻结 padding policy 并装入该 fixture 专属字节池。
     * @param Policy 原始 padding 配置。
     * @param Random 此 fixture 的随机源；空值保留 PadDriver 的既有行为。
     * @return 仅共享不可变 policy 的 PadOptions。
     */
    [[nodiscard]] inline auto MakePadOptions(
        Transport::PadConfig Policy,
        Transport::Detail::PadDriver::RandomSource Random = {})
        -> Transport::PadOptions
    {
        return {
            std::make_shared<const Transport::PadConfig>(std::move(Policy)),
            MakeTransportBytes(),
            std::move(Random)};
    }
}