/**
 * @file Auth.hpp
 * @brief HTTP/3 帧引擎与协议适配器共享的传输值合同。
 * @details 本头只拥有 HTTP/3 数据值；认证策略、状态约定和应用头由消费协议拥有。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <expected>
#include <cstdint>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Http3/HeaderLimits.hpp>
#include <Preview/Protocols/Http3/Qpack.hpp>

namespace Preview::Quic
{
    class StreamProvider;
}

namespace Preview::Http3
{

    namespace Net = boost::asio;

    /**
     * @struct HeaderBlock
     * @brief 拥有解码字段和其会话竞技场的 HTTP/3 头块。
     * @details Owner 必须先于 Fields 声明，保证 PMR 容器析构时竞技场仍然存在。
     */
    struct HeaderBlock final
    {
        struct FieldRange final
        {
            std::size_t NameOffset{0};
            std::size_t NameLength{0};
            std::size_t ValueOffset{0};
            std::size_t ValueLength{0};
        };

        struct ReservedStorage final
        {
            std::array<std::byte, HeaderLimits::MaxHeaderSectionBytes> Bytes{};
            std::array<FieldRange, HeaderLimits::MaxHeaderFields> Fields{};
            std::size_t ByteCount{0};
            std::size_t FieldCount{0};
        };

        std::shared_ptr<Preview::Memory::SessionResource<>> Owner;
        Preview::Memory::Vector<Qpack::HeaderField> Fields;

        explicit HeaderBlock(std::shared_ptr<Preview::Memory::SessionResource<>> OwnerValue)
            : Owner(RequireOwner(std::move(OwnerValue))), Fields(Owner->Arena()),
              Storage_(std::make_unique<ReservedStorage>())
        {
            Fields.reserve(HeaderLimits::MaxHeaderFields);
        }

        HeaderBlock(const HeaderBlock &) = delete;
        auto operator=(const HeaderBlock &) -> HeaderBlock & = delete;
        HeaderBlock(HeaderBlock &&) noexcept = default;
        auto operator=(HeaderBlock &&) noexcept -> HeaderBlock & = delete;

        /** @brief 在固定字节区和预留字段索引内复制拥有字段，拒绝超预算输入。 */
        [[nodiscard]] auto TryAppend(
            const std::string_view Name,
            const std::string_view Value) noexcept
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!Storage_ || Fields.size() >= HeaderLimits::MaxHeaderFields ||
                Name.size() > HeaderLimits::MaxFieldBytes ||
                Value.size() > HeaderLimits::MaxFieldBytes)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::OversizedMsg});
            }
            if (Name.size() > HeaderLimits::MaxHeaderSectionBytes - Storage_->ByteCount ||
                Value.size() > HeaderLimits::MaxHeaderSectionBytes - Storage_->ByteCount - Name.size())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::OversizedMsg});
            }
            const auto Index = Storage_->FieldCount;
            const auto NameOffset = Storage_->ByteCount;
            if (!Name.empty())
            {
                std::memcpy(Storage_->Bytes.data() + NameOffset, Name.data(), Name.size());
            }
            const auto ValueOffset = NameOffset + Name.size();
            if (!Value.empty())
            {
                std::memcpy(Storage_->Bytes.data() + ValueOffset, Value.data(), Value.size());
            }
            try
            {
                Fields.push_back(Qpack::HeaderField{std::string(Name), std::string(Value)});
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
            }
            catch (...)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
            }
            Storage_->Fields[Index] = FieldRange{NameOffset, Name.size(), ValueOffset, Value.size()};
            Storage_->ByteCount += Name.size() + Value.size();
            ++Storage_->FieldCount;
            return {};
        }

        /** @brief 复用响应头块的预留区，不释放其固定容量。 */
        auto Clear() noexcept -> void
        {
            Fields.clear();
            if (Storage_)
            {
                Storage_->ByteCount = 0;
                Storage_->FieldCount = 0;
            }
        }

        /** @brief 返回实际拥有字段的解码字节总量；溢出或超限使用上限加一表示。 */
        [[nodiscard]] auto ByteSize() const noexcept -> std::size_t
        {
            std::size_t Total = 0;
            for (const auto &Field : Fields)
            {
                if (Field.Name.size() > HeaderLimits::MaxHeaderSectionBytes - Total)
                {
                    return HeaderLimits::MaxHeaderSectionBytes + 1;
                }
                Total += Field.Name.size();
                if (Field.value.size() > HeaderLimits::MaxHeaderSectionBytes - Total)
                {
                    return HeaderLimits::MaxHeaderSectionBytes + 1;
                }
                Total += Field.value.size();
            }
            return Total;
        }

        /** @brief 返回该块固定预留区的真实容量。 */
        [[nodiscard]] auto ReservedBytes() const noexcept -> std::size_t
        {
            if (!Storage_)
            {
                return 0;
            }
            return Storage_->Bytes.size();
        }

        /** @brief 检查直接构造的响应字段是否符合共享 section/count/field 额度。 */
        [[nodiscard]] auto WithinLimits() const noexcept -> bool
        {
            if (Fields.size() > HeaderLimits::MaxHeaderFields)
            {
                return false;
            }
            for (const auto &Field : Fields)
            {
                if (Field.Name.size() > HeaderLimits::MaxFieldBytes ||
                    Field.value.size() > HeaderLimits::MaxFieldBytes)
                {
                    return false;
                }
            }
            return ByteSize() <= HeaderLimits::MaxHeaderSectionBytes;
        }

    private:
        [[nodiscard]] static auto RequireOwner(
            std::shared_ptr<Preview::Memory::SessionResource<>> Value)
            -> std::shared_ptr<Preview::Memory::SessionResource<>>
        {
            if (!Value)
            {
                throw std::invalid_argument("HTTP/3 HeaderBlock requires an arena owner");
            }
            return Value;
        }

        std::unique_ptr<ReservedStorage> Storage_;
    };

    /** @brief HTTP/3 请求头和请求流 FIN。 */
    struct RequestHead final
    {
        HeaderBlock Headers;
        bool Fin{false};

        RequestHead(HeaderBlock HeadersValue, const bool FinValue)
            : Headers(std::move(HeadersValue)), Fin(FinValue)
        {
        }

        RequestHead(const RequestHead &) = delete;
        auto operator=(const RequestHead &) -> RequestHead & = delete;
        RequestHead(RequestHead &&) noexcept = default;
        auto operator=(RequestHead &&) noexcept -> RequestHead & = default;
    };

    /** @brief 带真实来源流 ID 的服务端请求事件。 */
    struct RequestEvent final
    {
        std::int64_t StreamId{0};
        RequestHead Head;

        RequestEvent(std::int64_t StreamIdValue, RequestHead HeadValue)
            : StreamId(StreamIdValue), Head(std::move(HeadValue))
        {
        }

        RequestEvent(const RequestEvent &) = delete;
        auto operator=(const RequestEvent &) -> RequestEvent & = delete;
        RequestEvent(RequestEvent &&) noexcept = default;
        auto operator=(RequestEvent &&) noexcept -> RequestEvent & = default;
    };

    /** @brief 按值拥有响应头和其竞技场；StreamId/Fin 对应真实请求流与结束标记。
     * @details HeaderBlock 使本聚合值自动为 move-only；提交前由 caller 拥有，
     *          提交后由 HTTP/3 session 保持到写出。同步构造不取消、不关闭流。
     */
    struct ResponseHead final
    {
        std::int64_t StreamId{0};
        std::uint16_t Status{0};
        HeaderBlock Headers;
        bool Fin{false};

    };

    /** @brief 拥有一次读取结果的 HTTP/3 数据事件。 */
    struct DataEvent final
    {
        std::int64_t StreamId{0};
        std::vector<std::byte> Data;
        bool Fin{false};

        DataEvent(
            std::int64_t StreamIdValue,
            std::vector<std::byte> DataValue,
            const bool FinValue)
            : StreamId(StreamIdValue), Data(std::move(DataValue)), Fin(FinValue)
        {
        }

        DataEvent(const DataEvent &) = delete;
        auto operator=(const DataEvent &) -> DataEvent & = delete;
        DataEvent(DataEvent &&) noexcept = default;
        auto operator=(DataEvent &&) noexcept -> DataEvent & = default;
    };

    /** @brief 通用 HTTP/3 流重置事件。 */
    struct ResetEvent final
    {
        std::int64_t StreamId{0};
        Preview::Fault::Code Error{Preview::Fault::Code::ProtocolError};
    };

    /** @brief 裸流方向。 */
    enum class StreamDirection : std::uint8_t
    {
        Inbound,
        Outbound,
    };

    /**
     * @brief 提供原生 QUIC 流所有权的通用事件。
     * @details 事件持有共享 provider，handler 返回 Opaque 后才由协议层消费字节。
     */
    struct RawStreamEvent final
    {
        std::int64_t StreamId{0};
        StreamDirection Direction{StreamDirection::Inbound};
        std::shared_ptr<Preview::Quic::StreamProvider> Provider{};
    };

    using ServerEvent = std::variant<RequestEvent, DataEvent, ResetEvent, RawStreamEvent>;

    /** @brief generic HTTP/3 会话输出承载模式。 */
    enum class StreamMode : std::uint8_t
    {
        Http3,
        Opaque,
    };

    /** @brief handler 对一个输入事件的 typed 结果。 */
    struct SessionAction final
    {
        std::optional<ResponseHead> Response;
        StreamMode Mode{StreamMode::Http3};

        SessionAction() = default;
        explicit SessionAction(StreamMode ModeValue) : Mode(ModeValue)
        {
        }
        SessionAction(ResponseHead ResponseValue, StreamMode ModeValue = StreamMode::Http3)
            : Response(std::move(ResponseValue)), Mode(ModeValue)
        {
        }

        SessionAction(const SessionAction &) = delete;
        auto operator=(const SessionAction &) -> SessionAction & = delete;
        SessionAction(SessionAction &&) noexcept = default;
        auto operator=(SessionAction &&) noexcept -> SessionAction & = default;
    };

    using EventHandler = std::function<Net::awaitable<SessionAction>(ServerEvent)>;

} // namespace Preview::Http3
