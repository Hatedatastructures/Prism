/**
 * @file DataPlane.hpp
 * @brief 会话根数据面契约
 * @details 数据面以值语义 variant 区分可靠流与数据报服务。协议层只
 *          负责构造 ProtocolDataPlane，Session 只消费 RootDataPlane，
 *          不再通过布尔标志或 RTTI 猜测数据面形态。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include <Preview/Account/Lease.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Middleware
{

    class Context;

} // namespace Preview::Middleware

namespace Preview::Runtime
{

    namespace Net = boost::asio;

    /**
     * @struct StreamDataPlane
     * @brief 可靠、可半关闭的流数据面
     */
    struct StreamDataPlane final
    {
        Preview::SharedTransmission Transport{};
    };

    /**
     * @struct DatagramDataPlane
     * @brief 协议数据报数据面
     * @details Transport 保存协议握手后的根传输，Service 负责执行数据报
     *          帧循环。服务回调拥有 Context 的非拥有引用，Session 在
     *          回调返回前保证 Context 与根数据面存活。
     */
    struct DatagramDataPlane final
    {
        using ServiceFn = std::function<Net::awaitable<Preview::Fault::Code>(
            Preview::Middleware::Context &)>;

        Preview::SharedTransmission Transport{};
        ServiceFn Service{};
    };

    struct MuxRootDataPlane final
    {
        Preview::SharedTransmission Transport{};
        std::string Mode{"auto"};
    };

    /// Session 使用的根数据面；variant 类型本身表达数据面形态。
    using RootDataPlane = std::variant<StreamDataPlane, DatagramDataPlane, MuxRootDataPlane>;

    /**
     * @struct ProtocolDataPlane
     * @brief 协议握手结果及其根数据面
     * @details 账户租约随该对象移动到 Session 所有权边界；AccountId 是
     *          值语义身份，即使租约之后被释放也不会产生悬空引用。
     */
    struct ProtocolDataPlane final
    {
        RootDataPlane Root{};
        Preview::Network::Target Target{};
        std::string Identity{};
        Preview::AccountId AccountId{};
        std::optional<Preview::Account::AccountLease> AccountLease{};
        bool ProtocolAuthenticated{false};
        std::function<Net::awaitable<void>(Preview::Fault::Code)> PostDial{};

        [[nodiscard]] auto IsStream() const noexcept -> bool
        {
            return std::holds_alternative<StreamDataPlane>(Root);
        }

        [[nodiscard]] auto IsDatagram() const noexcept -> bool
        {
            return std::holds_alternative<DatagramDataPlane>(Root);
        }

        [[nodiscard]] auto IsMux() const noexcept -> bool
        {
            return std::holds_alternative<MuxRootDataPlane>(Root);
        }

        [[nodiscard]] auto Stream() noexcept -> StreamDataPlane *
        {
            return std::get_if<StreamDataPlane>(&Root);
        }

        [[nodiscard]] auto Stream() const noexcept -> const StreamDataPlane *
        {
            return std::get_if<StreamDataPlane>(&Root);
        }

        [[nodiscard]] auto Datagram() noexcept -> DatagramDataPlane *
        {
            return std::get_if<DatagramDataPlane>(&Root);
        }

        [[nodiscard]] auto Datagram() const noexcept -> const DatagramDataPlane *
        {
            return std::get_if<DatagramDataPlane>(&Root);
        }

        [[nodiscard]] auto Mux() noexcept -> MuxRootDataPlane *
        {
            return std::get_if<MuxRootDataPlane>(&Root);
        }

        [[nodiscard]] auto Mux() const noexcept -> const MuxRootDataPlane *
        {
            return std::get_if<MuxRootDataPlane>(&Root);
        }

        [[nodiscard]] auto HasTransport() const noexcept -> bool
        {
            const auto *StreamValue = Stream();
            if (StreamValue)
            {
                return static_cast<bool>(StreamValue->Transport);
            }
            const auto *DatagramValue = Datagram();
            if (DatagramValue)
            {
                return static_cast<bool>(DatagramValue->Transport);
            }
            const auto *MuxValue = Mux();
            return MuxValue && static_cast<bool>(MuxValue->Transport);
        }

        [[nodiscard]] auto Transport() const noexcept -> Preview::SharedTransmission
        {
            if (const auto *StreamValue = Stream())
            {
                return StreamValue->Transport;
            }
            if (const auto *DatagramValue = Datagram())
            {
                return DatagramValue->Transport;
            }
            if (const auto *MuxValue = Mux())
            {
                return MuxValue->Transport;
            }
            return {};
        }
    };

} // namespace Preview::Runtime

namespace Preview::Runtime::Contract
{

    using ::Preview::Runtime::DatagramDataPlane;
    using ::Preview::Runtime::MuxRootDataPlane;
    using ::Preview::Runtime::ProtocolDataPlane;
    using ::Preview::Runtime::RootDataPlane;
    using ::Preview::Runtime::StreamDataPlane;

} // namespace Preview::Runtime::Contract
