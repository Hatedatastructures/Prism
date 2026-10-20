/**
 * @file IoBridge.hpp
 * @brief 协议 owner 的部分读写协程到唯一 typed I/O 前门的通用桥。
 * @details owner 提供 `ReadPartial(span) -> awaitable<IoResult>` 与
 *          `WritePartial(span) -> awaitable<IoResult>`；桥在 owner executor 上以 co_composed
 *          保活 owner，并将同一次 IoResult 原样交付一次。Bytes 与 Failure 同时保留，不能先转
 *          std::error_code 再映射，否则纯领域 Code 或原生 category/value 会丢失。普通取消与错误
 *          由实际操作值返回，不从帧抛出。
 *          借用期限到 completion 返回；本桥不执行关闭、取消或半关闭，也不复制 buffer。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/post.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>

namespace Prism::Protocols
{
    namespace Net = boost::asio;

    /** @brief 部分读的正式输入；队列执行域由冷构造 owner 显式带入。 */
    template<class Owner>
    struct PartialReadInput final
    {
        std::shared_ptr<Owner> Carrier;
        std::span<std::byte> Buffer;
        Net::any_io_executor QueueExecutor;
    };

    /** @brief 部分写的正式输入；队列执行域由冷构造 owner 显式带入。 */
    template<class Owner>
    struct PartialWriteInput final
    {
        std::shared_ptr<Owner> Carrier;
        std::span<const std::byte> Buffer;
        Net::any_io_executor QueueExecutor;
    };

    /** @brief 把 owner 的 awaitable 接到 co_composed 可识别的异步操作契约。 */
    template<class Awaitable>
    struct SpawnAwaitable final
    {
        Net::any_io_executor Executor;
        Awaitable Operation;

        template<class CompletionToken>
        auto operator()(CompletionToken&& Token) -> decltype(Net::co_spawn(
            std::declval<Net::any_io_executor>(), std::declval<Awaitable>(),
            std::declval<CompletionToken>()))
        {
            return Net::co_spawn(Executor, std::move(Operation),
                                 std::forward<CompletionToken>(Token));
        }
    };

    /** @brief 一次部分读的 owner 保活协程体；同次 IoResult 原样交付。 */
    template<class Owner>
    struct PartialRead final
    {
        PartialReadInput<Owner> Input;
        template<class State>
        auto operator()(State OperationState) const -> void
        {
            Prism::Transmission::ConfigureIo(OperationState);
            if (!Input.Carrier)
            {
                co_await Net::post(Input.QueueExecutor, Net::deferred);
                co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
            }
            auto Awaitable = Input.Carrier->ReadPartial(Input.Buffer);
            const auto Result = co_await SpawnAwaitable<decltype(Awaitable)>{
                Input.QueueExecutor, std::move(Awaitable)};
            co_return std::tuple{Result};
        }
    };

    /** @brief 一次部分写的 owner 保活协程体；同次 IoResult 原样交付。 */
    template<class Owner>
    struct PartialWrite final
    {
        PartialWriteInput<Owner> Input;
        template<class State>
        auto operator()(State OperationState) const -> void
        {
            Prism::Transmission::ConfigureIo(OperationState);
            if (!Input.Carrier)
            {
                co_await Net::post(Input.QueueExecutor, Net::deferred);
                co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
            }
            auto Awaitable = Input.Carrier->WritePartial(Input.Buffer);
            const auto Result = co_await SpawnAwaitable<decltype(Awaitable)>{
                Input.QueueExecutor, std::move(Awaitable)};
            co_return std::tuple{Result};
        }
    };

    /** @brief 在 owner executor 上启动一次部分读；结果沿正式前门恰好交付一次。 */
    template<class Owner>
    auto StartPartialRead(PartialReadInput<Owner> Input,
                          Prism::Transmission::Completion Handler) -> void
    {
        const auto Executor = Input.QueueExecutor;
        if (!Input.Carrier)
        {
            Prism::Transmission::PostResult(
                Executor, std::move(Handler),
                Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}});
            return;
        }
        Net::async_initiate<Prism::Transmission::Completion, void(Prism::IoResult)>(
            Net::co_composed<void(Prism::IoResult)>(
                PartialRead<Owner>{std::move(Input)}, Executor),
            Handler);
    }

    /** @brief 在 owner executor 上启动一次部分写；结果沿正式前门恰好交付一次。 */
    template<class Owner>
    auto StartPartialWrite(PartialWriteInput<Owner> Input,
                           Prism::Transmission::Completion Handler) -> void
    {
        const auto Executor = Input.QueueExecutor;
        if (!Input.Carrier)
        {
            Prism::Transmission::PostResult(
                Executor, std::move(Handler),
                Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}});
            return;
        }
        Net::async_initiate<Prism::Transmission::Completion, void(Prism::IoResult)>(
            Net::co_composed<void(Prism::IoResult)>(
                PartialWrite<Owner>{std::move(Input)}, Executor),
            Handler);
    }
}
