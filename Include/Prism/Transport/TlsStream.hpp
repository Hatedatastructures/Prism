/**
 * @file TlsStream.hpp
 * @brief 公开 TLS 流 facade；engine、取消预约与 Asio SSL 实现留在 Transport owner 内。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/system/error_code.hpp>

#include <openssl/base.h>

#include <cstddef>
#include <memory>
#include <span>
#include <type_traits>
#include <utility>

namespace boost::asio::ssl
{
    class context;
}

namespace Prism::Transport::Detail
{
    class TlsEngine;
}

namespace Prism::Transport
{
    /**
     * @brief TLS engine 的公开 owning facade；不暴露 Boost.Asio SSL detail 类型。
     * @details 输入所有权：构造按值接管 Connector；ssl::context 只借用到本类销毁，调用方负责保活。
     *          各读写操作只借用 buffer 到 completion；异步 buffer sequence 按既有语义只消费首 buffer。
     *          输出与错误：typed 操作交付 IoResult，Asio stream 操作保留 error_code/bytes ABI 和 Native；
     *          TLS error 的领域码转换由调用方既有边界决定。
     *          取消：handler 的 associated executor、allocator、cancellation slot 经 completion 适配器保留；
     *          engine 在 strand 上预约完成，排队前取消交付 Canceled，真实 I/O 取消仍由 Asio 操作完成。
     *          半关闭：WriteShutdown/AsyncWriteShutdown 只发本端 close_notify，读方向继续可用；
     *          async_shutdown 执行完整双向 TLS shutdown。
     *          最终关闭者：本类只拥有 TLS engine，不关闭底层 socket；描述符最终由 lowest_layer 的
     *          Transmission 关闭。executor：engine 使用 Connector 的 executor 建立 strand，结果按 handler
     *          的关联 executor 交付。
     */
    class TlsStream final : public std::enable_shared_from_this<TlsStream>
    {
    public:
        using executor_type = Net::any_io_executor;
        using lowest_layer_type = Prism::Transmission;

        TlsStream(Connector Next, Net::ssl::context& Context);
        ~TlsStream();
        TlsStream(const TlsStream&) = delete;
        auto operator=(const TlsStream&) -> TlsStream& = delete;
        TlsStream(TlsStream&&) = delete;
        auto operator=(TlsStream&&) -> TlsStream& = delete;

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity>;
        [[nodiscard]] auto IsIdle() const noexcept -> bool;
        [[nodiscard]] auto get_executor() const noexcept -> executor_type;
        [[nodiscard]] auto next_layer() noexcept -> Connector&;
        [[nodiscard]] auto next_layer() const noexcept -> const Connector&;
        [[nodiscard]] auto lowest_layer() noexcept -> Prism::Transmission&;
        [[nodiscard]] auto native_handle() noexcept -> SSL*;

        /** @brief typed 读保留领域失败和原生原因；buffer 借用到 completion 返回。 */
        auto ReadSome(std::span<std::byte> Input, Prism::Transmission::Completion Handler) -> void;
        auto WriteSome(std::span<const std::byte> Input, Prism::Transmission::Completion Handler) -> void;
        auto WriteShutdown(Prism::Transmission::Completion Handler) -> void;

        template<class Buffers, class Token>
        auto async_read_some(const Buffers& Input, Token&& Handler)
        {
            const auto Buffer = FirstMutableBuffer(Input);
            return InitiateAsio<true>(std::forward<Token>(Handler),
                [Buffer](std::shared_ptr<TlsStream> Owner, Prism::Transmission::Completion Completion)
                {
                    Owner->StartReadSome(std::move(Owner), Buffer, std::move(Completion));
                });
        }

        template<class Buffers, class Token>
        auto async_write_some(const Buffers& Input, Token&& Handler)
        {
            const auto Buffer = FirstConstBuffer(Input);
            return InitiateAsio<true>(std::forward<Token>(Handler),
                [Buffer](std::shared_ptr<TlsStream> Owner, Prism::Transmission::Completion Completion)
                {
                    Owner->StartWriteSome(std::move(Owner), Buffer, std::move(Completion));
                });
        }

        template<class Token>
        auto async_handshake(Net::ssl::stream_base::handshake_type Side, Token&& Handler)
        {
            return InitiateAsio<false>(std::forward<Token>(Handler),
                [Side](std::shared_ptr<TlsStream> Owner, Prism::Transmission::Completion Completion)
                {
                    Owner->StartHandshake(std::move(Owner), Side, std::move(Completion));
                });
        }

        /** @brief 完整 TLS 双向关闭，仅显式要求 async_shutdown 的调用方使用。 */
        template<class Token>
        auto async_shutdown(Token&& Handler)
        {
            return InitiateAsio<false>(std::forward<Token>(Handler),
                [](std::shared_ptr<TlsStream> Owner, Prism::Transmission::Completion Completion)
                {
                    Owner->StartShutdown(std::move(Owner), std::move(Completion));
                });
        }

        /**
         * @brief 只发送本端 close_notify；成功后反向读仍可继续。
         * @details Asio signature 仍声明单个 error_code；为保留既有 adapter 行为，
         *          同时可接收单参和双参的泛型 handler 仍优先收到 (error_code, 0)。
         */
        template<class Token>
        auto AsyncWriteShutdown(Token&& Handler)
        {
            return InitiateAsio<false, true>(std::forward<Token>(Handler),
                [](std::shared_ptr<TlsStream> Owner, Prism::Transmission::Completion Completion)
                {
                    Owner->StartWriteShutdown(std::move(Owner), std::move(Completion));
                });
        }

    private:
        [[nodiscard]] static auto ToAsioError(const Prism::Fault::Failure& Failure)
            -> boost::system::error_code;
        static auto PostAsioResult(
            executor_type QueueExecutor,
            Prism::Transmission::Completion Handler,
            Prism::IoResult Result) -> void;

        template<class Handler, bool IncludeBytes>
        class AbiCompletion final
        {
        public:
            using executor_type = Net::associated_executor_t<Handler>;
            using allocator_type = Net::associated_allocator_t<Handler>;
            using cancellation_slot_type = Net::associated_cancellation_slot_t<Handler>;
            explicit AbiCompletion(Handler Callback)
                : Handler_(std::move(Callback))
            {
            }

            [[nodiscard]] auto get_executor() const noexcept -> executor_type
            {
                return Net::get_associated_executor(Handler_);
            }

            [[nodiscard]] auto get_allocator() const noexcept -> allocator_type
            {
                return Net::get_associated_allocator(Handler_);
            }

            [[nodiscard]] auto get_cancellation_slot() const noexcept -> cancellation_slot_type
            {
                return Net::get_associated_cancellation_slot(Handler_);
            }

            auto operator()(Prism::IoResult Result) -> void
            {
                const auto Error = TlsStream::ToAsioError(Result.Failure);
                if constexpr (IncludeBytes)
                {
                    if constexpr (std::is_invocable_v<
                                      Handler, boost::system::error_code, std::size_t>)
                    {
                        std::move(Handler_)(Error, Result.Bytes);
                    }
                    else
                    {
                        std::move(Handler_)(Error);
                    }
                }
                else
                {
                    std::move(Handler_)(Error);
                }
            }
        private:
            Handler Handler_;
        };

        template<bool SignatureIncludesBytes, bool AdapterIncludesBytes, class Start>
        struct Initiation
        {
            std::shared_ptr<TlsStream> Owner;
            Net::any_io_executor Fallback;
            Start Operation;
            using executor_type = Net::any_io_executor;

            [[nodiscard]] auto get_executor() const noexcept -> executor_type
            {
                return Fallback;
            }

            template<class Handler>
            auto operator()(Handler&& Callback) -> void
            {
                const auto UserExecutor = Net::get_associated_executor(Callback, Fallback);
                auto Bound = Net::bind_executor(UserExecutor, std::forward<Handler>(Callback));
                Prism::Transmission::Completion Completion(
                    AbiCompletion<decltype(Bound), AdapterIncludesBytes>(std::move(Bound)));
                if (!Owner)
                {
                    TlsStream::PostAsioResult(
                        Fallback, std::move(Completion),
                        {0, {Prism::Fault::Code::InvalidArgument}});
                    return;
                }
                Operation(std::move(Owner), std::move(Completion));
            }
        };

        template<bool SignatureIncludesBytes,
                 bool AdapterIncludesBytes = SignatureIncludesBytes,
                 class Token, class Start>
        auto InitiateAsio(Token&& Handler, Start Operation)
        {
            auto InitiationValue = Initiation<
                SignatureIncludesBytes, AdapterIncludesBytes, Start>{
                weak_from_this().lock(), get_executor(), std::move(Operation)};
            if constexpr (SignatureIncludesBytes)
            {
                return Net::async_initiate<Token,
                    void(boost::system::error_code, std::size_t)>(
                        std::move(InitiationValue), Handler);
            }
            else
            {
                return Net::async_initiate<Token, void(boost::system::error_code)>(
                    std::move(InitiationValue), Handler);
            }
        }

        template<class Buffers>
        [[nodiscard]] static auto FirstMutableBuffer(const Buffers& Input) noexcept
            -> std::span<std::byte>
        {
            const auto Begin = Net::buffer_sequence_begin(Input);
            if (Begin == Net::buffer_sequence_end(Input)) return {};
            const auto Buffer = *Begin;
            return {static_cast<std::byte*>(Buffer.data()), Buffer.size()};
        }

        template<class Buffers>
        [[nodiscard]] static auto FirstConstBuffer(const Buffers& Input) noexcept
            -> std::span<const std::byte>
        {
            const auto Begin = Net::buffer_sequence_begin(Input);
            if (Begin == Net::buffer_sequence_end(Input)) return {};
            const auto Buffer = *Begin;
            return {static_cast<const std::byte*>(Buffer.data()), Buffer.size()};
        }

        auto StartReadSome(std::shared_ptr<TlsStream> Owner,
                           std::span<std::byte> Input,
                           Prism::Transmission::Completion Handler) -> void;
        auto StartWriteSome(std::shared_ptr<TlsStream> Owner,
                            std::span<const std::byte> Input,
                            Prism::Transmission::Completion Handler) -> void;
        auto StartWriteShutdown(std::shared_ptr<TlsStream> Owner,
                                Prism::Transmission::Completion Handler) -> void;
        auto StartHandshake(std::shared_ptr<TlsStream> Owner,
                            Net::ssl::stream_base::handshake_type Side,
                            Prism::Transmission::Completion Handler) -> void;
        auto StartShutdown(std::shared_ptr<TlsStream> Owner,
                           Prism::Transmission::Completion Handler) -> void;

        std::unique_ptr<Detail::TlsEngine> Engine_;
    };
} // namespace Prism::Transport
