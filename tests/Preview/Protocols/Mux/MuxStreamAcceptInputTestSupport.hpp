/** @file MuxStreamAcceptInputTestSupport.hpp @brief Mux root 测试输入和真实父任务 owner。 */
#pragma once

#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>

#include <expected>
#include <memory>
#include <utility>

namespace Preview::Testing::MuxStreamAcceptInputTestSupport
{
    namespace Net = boost::asio;
    using Signal = Net::experimental::channel<void(boost::system::error_code)>;

    struct RootParentTask final
    {
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Registry;
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Children;
        Preview::Lifecycle::TaskIdentity Identity;
    };

    inline auto WaitForRootParentTask(std::shared_ptr<Signal> Release)
        -> Net::awaitable<void>
    {
        co_await Release->async_receive(Net::use_awaitable);
    }

    /** @brief 用真实活动任务构造 Mux root 的父 task scope 与不可变身份。 */
    [[nodiscard]] inline auto CreateRootParentTask(
        Net::any_io_executor Executor,
        Preview::Lifecycle::TaskContext Context,
        Preview::Lifecycle::TaskRegistry::FailureHandler Failure)
        -> Net::awaitable<std::expected<RootParentTask, Preview::Fault::Failure>>
    {
        auto Registry = std::make_shared<Preview::Lifecycle::TaskRegistry>(Executor);
        auto Children = Registry->CreateChild(std::move(Failure));
        auto Release = std::make_shared<Signal>(Executor, 1U);
        Preview::Lifecycle::TaskRequest Request;
        Request.Context = Context;
        Request.StartOnSubmit = true;
        Request.Cancel = [Release]
        { (void)Release->try_send(boost::system::error_code{}); };
        const auto Task = Registry->SpawnTracked(
            std::move(Request), WaitForRootParentTask(Release));
        if (!Task) co_return std::unexpected(Task.error());
        co_return RootParentTask{
            std::move(Registry), std::move(Children), Task->Identity()};
    }

    /** @brief 请求 parent task 取消并等待其 completion handler 真实退栈。 */
    [[nodiscard]] inline auto DrainRootParentTask(
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Registry)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        (void)Registry->Cancel();
        co_return co_await Registry->Drain();
    }

    /**
     * @brief 为 Mux root owner 用例构造带真实有界字节池的输入。
     * @param Inbound 测试 fixture 移交的入站传输 owner。
     * @param Bytes 测试 fixture 与 root relay 共用的有界字节池 owner。
     * @return 包含空元数据并与 root relay 共用字节池的 StreamFactory 输入。
     */
    [[nodiscard]] inline auto MakeMuxRootAcceptInput(Preview::SharedTransmission Inbound,
        std::shared_ptr<Preview::Memory::BytePool> Bytes)
        -> Preview::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), {}, std::move(Bytes)};
    }

    /**
     * @brief 为真实 Mux root 负载用例构造带真实有界字节池的输入。
     * @param Inbound 测试 fixture 移交的入站传输 owner。
     * @param Metadata 测试 fixture 收集的请求元数据快照。
     * @return 包含元数据和六十四个池块的 StreamFactory 输入。
     */
    [[nodiscard]] inline auto MakeRealRootAcceptInput(Preview::SharedTransmission Inbound,
        Preview::Contract::RequestMetadata Metadata) -> Preview::Contract::StreamAcceptInput
    {
        return {std::move(Inbound), std::move(Metadata),
            std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount = 64})};
    }
}
