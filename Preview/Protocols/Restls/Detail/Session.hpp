/**
 * @file Conn.hpp
 * @brief Restls 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 Restls 连接：
 * 1. WriteHandshake / ReadHandshake：认证握手（测试库简化：
 *    交换 ServerRandom，客户端派生 Secret 校验服务端 mask）
 * 2. 数据面：每条应用数据记录都带 auth_mac、掩码长度/命令和数据载荷
 * @note 与 restls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Restls/Detail/Record.hpp>
#include <Preview/Protocols/Restls/Types.hpp>
#include <Preview/Protocols/Restls/Detail/Io.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Restls::Detail
{

    /**
     * @class Conn
     * @brief Restls 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面
     * 经 auth_mac + mask 编解码透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;
        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         * @param Password 认证密码
         */
        explicit Conn(SharedTransmission Upstream, std::string Password)
            : Preview::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream)), Password_(std::move(Password))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Preview::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：派生 Secret 并交换 ServerRandom
         * @param ServerRandom 服务端随机数（32 字节）
         * @return 成功无值；失败保留 Restls 分类与原生 cause。
         * @details 客户端由密码派生 RestlsSecret，后续认证均以其为密钥。
         */
        [[nodiscard]] auto WriteHandshake(
            std::span<const std::uint8_t> ServerRandom) -> Net::awaitable<Result<void>>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToServer, {});
        }

        /**
         * @brief 客户端握手并接管首个 ClientFinished
         * @param ServerRandom 服务端随机数
         * @param ClientFinished 首个客户端加密记录
         * @return 成功无值；失败保留 Restls 分类与原生 cause。
         */
        [[nodiscard]] auto WriteHandshake(
            std::span<const std::uint8_t> ServerRandom,
            std::span<const std::uint8_t> ClientFinished) -> Net::awaitable<Result<void>>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToServer, ClientFinished);
        }

        /**
         * @brief 服务端握手：派生 Secret 并校验客户端身份
         * @param ServerRandom 服务端随机数（32 字节）
         * @return 成功无值；失败保留 Restls 分类与原生 cause。
         * @details 服务端同样派生 Secret，并以 ServerMask 加密
         * 首个 TLS 记录实现服务端身份验证（测试库简化直接派生）。
         */
        [[nodiscard]] auto ReadHandshake(
            std::span<const std::uint8_t> ServerRandom) -> Net::awaitable<Result<void>>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToClient, {});
        }

        /**
         * @brief 服务端握手并接管首个 ClientFinished
         * @param ServerRandom 服务端随机数
         * @param ClientFinished 首个客户端加密记录
         * @return 成功无值；失败保留 Restls 分类与原生 cause。
         */
        [[nodiscard]] auto ReadHandshake(
            std::span<const std::uint8_t> ServerRandom,
            std::span<const std::uint8_t> ClientFinished) -> Net::awaitable<Result<void>>
        {
            co_return Initialize(ServerRandom, FlowDirection::ToClient, ClientFinished);
        }

        /**
         * @brief 允许 TLS 1.3 加密 close_notify 作为 clean EOF
         * @details Restls-V1 的应用数据有独立认证头；TLS 1.3 连接关闭时，
         *          客户端仍可能发送外层 ApplicationData 形式的 19 字节
         *          加密 alert，无法用 Restls 密钥解码。该兼容路径只由
         *          VersionHint=tls13 的真实 carrier 显式开启。
         */
        auto AllowTls13EncryptedCloseNotify() noexcept -> void
        {
            Tls13EncryptedCloseNotify_ = true;
        }

    private:
        /** @brief 内部协程实现；只在正式前门包装一次，错误经 Fault 映射交付。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (!NextLayer_ || !Handshaken_)
            {
                co_return Preview::IoResult{0,
                    ToFaultFailure(ProtocolFailure(Error::NotOpen))};
            }
            if (Buffer.empty())
            {
                co_return Preview::IoResult{};
            }

            while (true)
            {
                if (const auto Count = DrainPendingRead(Buffer))
                {
                    co_return Preview::IoResult{*Count, {}};
                }

                auto Wire = co_await ReadFrame();
                if (!Wire)
                {
                    co_return Preview::IoResult{0, ToFaultFailure(Wire.error())};
                }

                auto [DecodeError, Decoded] = DecodeDataFrame(*Wire);
                if (DecodeError != Error::None)
                {
                    co_return Preview::IoResult{
                        0, ToFaultFailure(ProtocolFailure(DecodeError))};
                }

                const auto Consumed = co_await ConsumeDataFrame(std::move(Decoded));
                if (!Consumed)
                {
                    co_return Preview::IoResult{
                        0, ToFaultFailure(Consumed.error())};
                }
            }
        }

        /** @brief 内部协程实现；只在正式前门包装一次，错误经 Fault 映射交付。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (!NextLayer_ || !Handshaken_)
            {
                co_return Preview::IoResult{0,
                    ToFaultFailure(ProtocolFailure(Error::NotOpen))};
            }
            if (Buffer.empty())
            {
                co_return Preview::IoResult{};
            }

            const auto Count = (std::min)(Buffer.size(), MaxDataLength);
            std::vector<std::uint8_t> Data(Count);
            std::memcpy(Data.data(), Buffer.data(), Count);
            const auto ClientFinished =
                WriteDirection_ == FlowDirection::ToServer
                    ? std::span<const std::uint8_t>(ClientFinished_)
                    : std::span<const std::uint8_t>{};
            const auto [BuildError, Wire] = BuildFrame(FrameOptions{
                .Secret = Secret_,
                .ServerRandom = ServerRandom_,
                .Direction = WriteDirection_,
                .Counter = WriteCounter_,
                .ClientFinished = ClientFinished,
                .Data = Data,
                .PaddingLength = 0,
                .Command = CmdTypeNoop,
                .CommandArgument = 0});
            if (BuildError != Error::None)
            {
                co_return Preview::IoResult{
                    0, ToFaultFailure(ProtocolFailure(BuildError))};
            }

            const auto Sent = co_await SendAll(Wire);
            if (!Sent)
            {
                co_return Preview::IoResult{0, ToFaultFailure(Sent.error())};
            }
            ++WriteCounter_;
            if (WriteDirection_ == FlowDirection::ToServer && !ClientFinished_.empty())
            {
                ClientFinished_.clear();
            }
            co_return Preview::IoResult{Count, {}};
        }

    public:
        /** @brief 数据面真实部分读；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<RestlsReadWork>(RestlsRead{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 数据面真实部分写；mask/record 组装语义保持不变。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<RestlsWriteWork>(RestlsWrite{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 关闭底层传输
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Handshaken_ = false;
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /**
         * @brief 取消挂起操作
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
        }

        struct RestlsRead final { std::shared_ptr<Conn> Owner; std::span<std::byte> Buffer; };
        struct RestlsWrite final { std::shared_ptr<Conn> Owner; std::span<const std::byte> Buffer; };
        struct RestlsReadWork final
        {
            template<class State>
            auto operator()(State Operation, RestlsRead Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct RestlsWriteWork final
        {
            template<class State>
            auto operator()(State Operation, RestlsWrite Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            Handshaken_ = false;
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取派生密钥（握手后有效）
         */
        [[nodiscard]] auto Secret() const -> const std::array<std::uint8_t, 32> &
        {
            return Secret_;
        }

    private:
        [[nodiscard]] auto DrainPendingRead(std::span<std::byte> Buffer)
            -> std::optional<std::size_t>
        {
            if (PendingReadOffset_ >= PendingReadPayload_.size())
            {
                return std::nullopt;
            }
            const auto Count = (std::min)(Buffer.size(),
                                          PendingReadPayload_.size() - PendingReadOffset_);
            std::memcpy(Buffer.data(), PendingReadPayload_.data() + PendingReadOffset_, Count);
            PendingReadOffset_ += Count;
            if (PendingReadOffset_ == PendingReadPayload_.size())
            {
                PendingReadPayload_.clear();
                PendingReadOffset_ = 0;
            }
            return Count;
        }

        [[nodiscard]] auto ReadFrame()
            -> Net::awaitable<Result<std::vector<std::uint8_t>>>
        {
            co_return co_await ReadRecordWire(NextLayer_);
        }

        [[nodiscard]] auto DecodeDataFrame(const std::vector<std::uint8_t> &Wire)
            -> std::pair<Error, DecodedFrame>
        {
            const auto ClientFinished =
                ReadDirection_ == FlowDirection::ToServer
                    ? std::span<const std::uint8_t>(ClientFinished_)
                    : std::span<const std::uint8_t>{};
            DecodedFrame Decoded;
            auto DecodeError = DecodeFrame(
                Wire,
                DecodeOptions{.Secret = Secret_,
                              .ServerRandom = ServerRandom_,
                              .Direction = ReadDirection_,
                              .Counter = ReadCounter_,
                              .ClientFinished = ClientFinished},
                Decoded);
            if (DecodeError == Error::BadAuth)
            {
                // Restls clients may advance a direction counter for an empty/control write.
                for (int Delta = -5; Delta <= 5; ++Delta)
                {
                    if (Delta == 0 ||
                        (Delta < 0 && ReadCounter_ < static_cast<std::uint64_t>(-Delta)))
                    {
                        continue;
                    }
                    const auto CandidateCounter = Delta < 0
                                                      ? ReadCounter_ - static_cast<std::uint64_t>(-Delta)
                                                      : ReadCounter_ + static_cast<std::uint64_t>(Delta);
                    DecodedFrame Candidate;
                    const auto CandidateError = DecodeFrame(
                        Wire,
                        DecodeOptions{.Secret = Secret_,
                                      .ServerRandom = ServerRandom_,
                                      .Direction = ReadDirection_,
                                      .Counter = CandidateCounter,
                                      .ClientFinished = ClientFinished},
                        Candidate);
                    if (CandidateError == Error::None)
                    {
                        ReadCounter_ = CandidateCounter;
                        Decoded = std::move(Candidate);
                        DecodeError = Error::None;
                        break;
                    }
                }
            }
            if (DecodeError == Error::BadAuth && Tls13EncryptedCloseNotify_ &&
                ReadCounter_ > 0 && Wire.size() == TlsHdrlen + 19U &&
                Wire[0] == TlsApplicationData)
            {
                return {Error::UnexpectedEof, {}};
            }
            return {DecodeError, std::move(Decoded)};
        }

        [[nodiscard]] auto ConsumeDataFrame(DecodedFrame Frame)
            -> Net::awaitable<Result<void>>
        {
            if (Frame.Command == CmdTypeResponse && Frame.CommandArgument > 0U)
            {
                for (std::uint8_t Index = 0; Index < Frame.CommandArgument; ++Index)
                {
                    const auto Sent = co_await SendResponseControl();
                    if (!Sent) co_return std::unexpected(Sent.error());
                }
            }

            ++ReadCounter_;
            if (ReadDirection_ == FlowDirection::ToServer && !ClientFinished_.empty())
            {
                ClientFinished_.clear();
            }
            if (Frame.Data.size() == RandomResponseMagic.size() &&
                std::equal(Frame.Data.begin(), Frame.Data.end(),
                           reinterpret_cast<const std::uint8_t *>(RandomResponseMagic.data())))
            {
                co_return Result<void>{};
            }
            PendingReadPayload_ = std::move(Frame.Data);
            PendingReadOffset_ = 0;
            co_return Result<void>{};
        }

        [[nodiscard]] auto SendResponseControl() -> Net::awaitable<Result<void>>
        {
            const auto [BuildError, Wire] = BuildFrame(FrameOptions{
                .Secret = Secret_,
                .ServerRandom = ServerRandom_,
                .Direction = FlowDirection::ToClient,
                .Counter = WriteCounter_,
                .ClientFinished = {},
                .Data = {},
                .PaddingLength = 0,
                .Command = CmdTypeResponse,
                .CommandArgument = 1});
            if (BuildError != Error::None)
            {
                co_return std::unexpected(ProtocolFailure(BuildError));
            }
            const auto Sent = co_await SendAll(Wire);
            if (!Sent) co_return std::unexpected(Sent.error());
            ++WriteCounter_;
            co_return Result<void>{};
        }

        [[nodiscard]] auto Initialize(
            std::span<const std::uint8_t> ServerRandom,
            const FlowDirection WriteDirection,
            std::span<const std::uint8_t> ClientFinished) -> Result<void>
        {
            Handshaken_ = false;
            if (!NextLayer_)
            {
                return std::unexpected(ProtocolFailure(Error::NotOpen));
            }
            if (ServerRandom.size() != ServerRandom_.size())
            {
                return std::unexpected(ProtocolFailure(Error::BadLength));
            }
            Secret_ = DeriveSecret(Password_);
            std::copy(ServerRandom.begin(), ServerRandom.end(), ServerRandom_.begin());
            WriteDirection_ = WriteDirection;
            ReadDirection_ = WriteDirection == FlowDirection::ToServer
                                 ? FlowDirection::ToClient
                                 : FlowDirection::ToServer;
            ClientFinished_.assign(ClientFinished.begin(), ClientFinished.end());
            ReadCounter_ = 0;
            WriteCounter_ = 0;
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            Handshaken_ = true;
            return {};
        }

        [[nodiscard]] auto SendAll(std::span<const std::uint8_t> Buffer)
            -> Net::awaitable<Result<void>>
        {
            return SendAllWire(NextLayer_, Buffer);
        }

        SharedTransmission NextLayer_;                ///< 底层传输（独占所有权）
        std::string Password_;                          ///< 认证密码
        std::array<std::uint8_t, 32> Secret_{};         ///< RestlsSecret（派生）
        std::array<std::uint8_t, 32> ServerRandom_{};  ///< 服务端随机数
        std::vector<std::uint8_t> ClientFinished_;      ///< 首个客户端加密记录
        FlowDirection WriteDirection_{FlowDirection::ToServer}; ///< 写方向
        FlowDirection ReadDirection_{FlowDirection::ToClient};  ///< 读方向
        std::uint64_t ReadCounter_{0};                  ///< 读方向记录计数器
        std::uint64_t WriteCounter_{0};                 ///< 写方向记录计数器
        std::vector<std::uint8_t> PendingReadPayload_;  ///< 尚未交给调用方的明文
        std::size_t PendingReadOffset_{0};              ///< 明文消费游标
        bool Handshaken_{false};                        ///< 握手完成标志
        bool Tls13EncryptedCloseNotify_{false};         ///< TLS 1.3 加密 close_notify 兼容开关
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Restls::Detail
