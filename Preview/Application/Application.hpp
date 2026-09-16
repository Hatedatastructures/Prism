/**
 * @file Application.hpp
 * @brief PrismPreview 应用启动与生命周期入口。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>

#include <cstdint>
#include <filesystem>
#include <expected>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Preview::Application
{

    /** @brief 应用启动阶段的 typed 错误分类。 */
    enum class StartupErrorCode : std::uint8_t
    {
        MissingConfiguration,
        InvalidConfiguration,
        UnsupportedService,
        Builtin,
        Generation,
        Bind,
        Signal,
        Runtime,
    };

    /** @brief 应用启动错误，不携带生产配置或运行时对象。 */
    struct StartupError final
    {
        StartupErrorCode Code{StartupErrorCode::Runtime};
        std::string Path;
        std::string Message;
    };

    /** @brief 成功绑定后的只读就绪状态。 */
    struct Readiness final
    {
        std::uint16_t Port{0};
        std::uint16_t OperationsPort{0};
        Preview::GenerationId Generation{};
        std::uint16_t UdpPort{0};
        bool UdpReady{false};
        bool QuicReady{false};
        bool UdpSocketReady{false};
        bool QuicSocketReady{false};
        bool QuicHandshakeReady{false};
        bool QuicProtocolReady{false};
    };

    /** @brief 应用启动选项。Output 由调用方持有；为空时使用 stdout。 */
    struct Options final
    {
        std::filesystem::path ConfigurationPath;
        std::ostream *Output{nullptr};
        std::function<std::optional<std::string>(std::string_view)> SecretResolver{};
    };

    /**
     * @class Application
     * @brief 持有 Preview 启动对象并收口监听、会话和进程生命周期。
     * @details 解析、generation、Process、SessionServices、TCP listener 和
     *          signal_set 均在 Preview 应用边界内创建；启动失败不会发布就绪状态。
     */
    class Application final
    {
    public:
        struct RuntimeState;

        explicit Application(Options OptionsValue);

        explicit Application(std::filesystem::path ConfigurationPath);

        ~Application() noexcept;

        Application(const Application &) = delete;
        auto operator=(const Application &) -> Application & = delete;
        Application(Application &&) = delete;
        auto operator=(Application &&) -> Application & = delete;

        [[nodiscard]] auto Start() -> std::expected<Readiness, StartupError>;

        [[nodiscard]] auto Run() -> int;

        /** @brief 请求一次幂等优雅停机；实际排空由 Run 驱动。 */
        auto Stop() noexcept -> void;

        [[nodiscard]] auto IsReady() const noexcept -> bool;

        [[nodiscard]] auto IsStopping() const noexcept -> bool;

        [[nodiscard]] auto IsStopped() const noexcept -> bool;

        [[nodiscard]] auto LastError() const noexcept -> const std::optional<StartupError> &;

    private:
        Options Options_;
        std::shared_ptr<RuntimeState> State_;
        std::optional<Readiness> Readiness_;
        std::optional<StartupError> LastError_;
    };

} // namespace Preview::Application
