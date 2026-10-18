/**
 * @file StreamOwner.hpp
 * @brief WebSocket 会话连接公共聚合入口。
 * @details 握手、底层 partial I/O、帧/分片、流适配和关闭分别由专用 owner 实现；
 *          ConnSession 持有底层传输与 BytePool，直至活动排空并销毁。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Ws/Detail/ConnClose.hpp>
#include <Prism/Protocols/Ws/Detail/ConnFrame.hpp>
#include <Prism/Protocols/Ws/Detail/ConnHandshake.hpp>
#include <Prism/Protocols/Ws/Detail/ConnSession.hpp>
#include <Prism/Protocols/Ws/Detail/ConnStream.hpp>
#include <Prism/Protocols/Ws/Detail/ConnTransport.hpp>
#include <Prism/Transport/Detail/ActivityGroup.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <vector>

namespace Prism::Ws::Detail
{

    namespace Net = boost::asio;

    /**
     * @class StreamOwner
     * @brief WebSocket 会话连接（Transmission 装饰器）。
     * @tparam Memory 会话内存策略。
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class StreamOwner : public Prism::Transmission
    {
    private:
        /**
         * @brief 从已拥有的上游传输取得连接 executor。
         * @param Upstream 同步借用的上游共享 owner。
         * @return 上游 executor；空传输返回空 executor。
         */
        static auto SelectExecutor(const SharedTransmission &Upstream)
            -> Net::any_io_executor
        {
            if (!Upstream)
            {
                return {};
            }
            return Upstream->Executor();
        }

    public:
        static constexpr std::size_t MaxFramePayload =
            ConnFrame<Memory>::MaxFramePayload;

        /// 内存策略类型（供嵌套层和测试使用）。
        using MemoryType = Memory;

        /**
         * @param Upstream 底层传输共享 owner，移交给连接。
         * @param Bytes 与传输同生命周期的 BytePool 共享 owner，移交给会话。
         * @param Client 客户端视角；客户端发送的帧需要掩码。
         * @details executor 从 Upstream 继承；取消、半关闭和最终关闭由活动、
         *          ConnClose 与底层 Transport owner 管理。Bytes 保留至 StreamOwner 销毁。
         */
        explicit StreamOwner(
            SharedTransmission Upstream,
            std::shared_ptr<Prism::Memory::BytePool> Bytes,
            bool Client)
            : Prism::Transmission(SelectExecutor(Upstream)),
              Session_(std::move(Upstream), std::move(Bytes), Client),
              Activity_(CreateActivity(Prism::Transmission::Activity(), Session_)),
              Transport_(Session_),
              Close_(Session_),
              Frame_(Session_, Transport_, Close_),
              Stream_(Session_, Frame_, Close_),
              Handshake_(Session_, Transport_)
        {
        }

        StreamOwner(const StreamOwner &) = delete;
        auto operator=(const StreamOwner &) -> StreamOwner & = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Session_.Executor();
        }

        /** @brief 返回本层操作与实际接收下层 owner 的组合回执。 */
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        /**
         * @brief 客户端发送 Upgrade 请求并校验 101 响应。
         * @return 空值表示成功；失败完整保留 Fault::Failure 的 Code 与 Native。
         * @details Key/Host 借用至协程完成，在底层 executor 执行；失败不关闭 StreamOwner，
         *          调用者仍持有所有权并负责 Close 与 Activity()->Drain()。
         */
        [[nodiscard]] auto WriteHandshake(
            std::string_view Key,
            std::string_view Host)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            PrepareHandshake();
            return Handshake_.WriteHandshake(Key, Host);
        }

        /**
         * @brief 服务端读取 Upgrade 请求并发送 101 响应。
         * @return 空值表示成功；失败完整保留 Fault::Failure 的 Code 与 Native。
         * @details Key 仅在成功时有效；失败不关闭 StreamOwner，调用者仍持有所有权并负责
         *          Close 与 Activity()->Drain()。
         */
        [[nodiscard]] auto ReadHandshake(
            std::string &Key,
            std::string_view ExpectedPath = {},
            std::string_view ExpectedHost = {})
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            PrepareHandshake();
            return Handshake_.ReadHandshake(Key, ExpectedPath, ExpectedHost);
        }

        /** @brief 读取一部分已解帧的应用数据；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WsReadWork>(WsRead{std::static_pointer_cast<StreamOwner>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 写入一部分应用数据并编码为 binary 帧；结果沿正式前门交付一次。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WsWriteWork>(WsWrite{std::static_pointer_cast<StreamOwner>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Close_.WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 交付底层关闭命令；在途帧与流状态留在 StreamOwner 生命周期内，实际退栈由 Activity()->Drain() 等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Close_.Close();
        }

        /**
         * @brief 只取消底层挂起操作，保留连接状态。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Close_.Cancel();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Close_.NextLayer();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override
        {
            return Close_.NextLayer();
        }

        /**
         * @brief 停止发起者后，在本层及已接收下层 owner 均真实退休时移交底层。
         * @details 调用方先等待 Activity()->Drain()，再独立核对 IsRetired；Drain 中的历史错误
         *          不替代物理回执。任一 owner 仍未退休时返回空并保留底层 owner。
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            if (!Activity_->IsRetired()) return {};
            return Close_.Release();
        }

        /**
         * @brief 获取握手生成的 Sec-WebSocket-Accept。
         */
        [[nodiscard]] auto Accept() const noexcept -> const std::string &
        {
            return Handshake_.Accept();
        }

    private:
        /**
         * @brief 把基类操作预约与本连接实际接收的下层 owner 组合为单一物理回执。
         * @param Parent 本层 Transmission 操作与控制预约的 owner。
         * @param Session 保存本连接已接管下层 owner 的状态。
         * @return 聚合本层前门及下层真实 owner 的活动回执。
         */
        [[nodiscard]] static auto CreateActivity(
            std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
            const ConnSession<Memory> &Session)
            -> std::shared_ptr<Prism::Transport::Detail::ActivityGroup>
        {
            std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> Children;
            if (auto Upstream = Session.Underlying())
            {
                Children.push_back(Upstream->Activity());
            }
            return std::make_shared<Prism::Transport::Detail::ActivityGroup>(
                std::move(Parent), std::move(Children));
        }

        struct WsRead final { std::shared_ptr<StreamOwner> Owner; std::span<std::byte> Buffer; };
        struct WsWrite final { std::shared_ptr<StreamOwner> Owner; std::span<const std::byte> Buffer; };
        struct WsReadWork final
        {
            template<class State>
            auto operator()(State Operation, WsRead Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->Stream_.ReadPartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WsWriteWork final
        {
            template<class State>
            auto operator()(State Operation, WsWrite Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->Stream_.WritePartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        auto PrepareHandshake() -> void
        {
            Close_.Reset();
            Frame_.Reset();
            Stream_.Reset();
        }

        using Session = ConnSession<Memory>;
        using Transport = ConnTransport<Memory>;
        using CloseOwner = ConnClose<Memory>;
        using Frame = ConnFrame<Memory>;
        using Stream = ConnStream<Memory>;
        using Handshake = ConnHandshake<Memory>;

        Session Session_;
        std::shared_ptr<Prism::Transport::Detail::ActivityGroup> Activity_;
        Transport Transport_;
        CloseOwner Close_;
        Frame Frame_;
        Stream Stream_;
        Handshake Handshake_;
    };

    static_assert(Prism::TransmissionLike<StreamOwner<>>);

} // namespace Prism::Ws::Detail
