/**
 * @file RuntimeTest.cpp
 * @brief 经真实管理 listener 验证同源 Web 资源与 Operations HTTP 控制面。
 */

#include "WebTestSupport.hpp"

#include <gtest/gtest.h>

#include <Prism/Operations/Controller.hpp>
#include <Prism/Operations/Web/Loader.hpp>

#include "../Http/AuthSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    namespace Web = Prism::Operations::Web;
    using Tcp = Net::ip::tcp;
    using Controller = Prism::Operations::Controller;
    using Query = Prism::Operations::Query;
    using QueryResult = Prism::Operations::QueryResult;
    using Command = Prism::Operations::Command;
    using CommandResult = Prism::Operations::CommandResult;
    using Observations = std::shared_ptr<struct HandlerObservations>;

    struct HandlerObservations final
    {
        std::atomic<std::size_t> QueryCalls{0};
        std::atomic<std::size_t> CommandCalls{0};
        std::string ReloadConfiguration;
    };

    [[nodiscard]] auto MakeHealthResult(Query Value, Observations Seen)
        -> Net::awaitable<QueryResult>
    {
        Seen->QueryCalls.fetch_add(1U, std::memory_order_relaxed);
        Prism::Operations::HealthSnapshot Health;
        Health.Status = Prism::Operations::HealthStatus::Healthy;
        Health.Ready = true;
        Health.TcpReady = true;
        Health.UdpReady = false;
        Health.QuicReady = true;
        co_return QueryResult::Health(Prism::Operations::CorrelationOf(Value), Health);
    }

    [[nodiscard]] auto AcceptReload(Command Value, Observations Seen)
        -> Net::awaitable<CommandResult>
    {
        const auto Correlation = Prism::Operations::CorrelationOf(Value);
        Seen->CommandCalls.fetch_add(1U, std::memory_order_relaxed);
        const auto *Reload = std::get_if<Prism::Operations::ReloadCommand>(&Value.Value);
        if (!Reload)
        {
            co_return CommandResult::Rejected(Correlation);
        }
        Seen->ReloadConfiguration = Reload->ConfigurationJson;
        co_return CommandResult::Accepted(Correlation);
    }

    [[nodiscard]] auto MakeHandlers(Observations Seen)
        -> Prism::Operations::RouterHandlers
    {
        Prism::Operations::RouterHandlers Handlers;
        Handlers.Query = [Seen](Query Value) -> Net::awaitable<QueryResult>
        {
            co_return co_await MakeHealthResult(std::move(Value), Seen);
        };
        Handlers.Command = [Seen](Command Value, Prism::Operations::OperationCompletion)
            -> Net::awaitable<CommandResult>
        {
            co_return co_await AcceptReload(std::move(Value), Seen);
        };
        return Handlers;
    }

    [[nodiscard]] auto MakeAuthority(const Controller::Endpoint &Endpoint) -> std::string
    {
        auto Address = Endpoint.address().to_string();
        if (Endpoint.address().is_v6())
        {
            Address = "[" + Address + "]";
        }
        Address.append(":").append(std::to_string(Endpoint.port()));
        return Address;
    }

    [[nodiscard]] auto MakeOrigin(const Controller::Endpoint &Endpoint) -> std::string
    {
        return "http://" + MakeAuthority(Endpoint);
    }

    struct HttpRequestSpec final
    {
        std::string Method;
        std::string Target;
        std::string Host;
        std::string Origin;
        std::string Authorization;
        std::string ContentType;
        std::string Body;
    };

    [[nodiscard]] auto MakeGetSpec(const Controller::Endpoint &Endpoint,
                                   std::string Target) -> HttpRequestSpec
    {
        return HttpRequestSpec{"GET", std::move(Target), MakeAuthority(Endpoint),
            MakeOrigin(Endpoint), {}, {}, {}};
    }

    [[nodiscard]] auto MakeReloadSpec(const Controller::Endpoint &Endpoint,
                                      std::string Token) -> HttpRequestSpec
    {
        constexpr std::string_view Body{
            R"json({"mode":"apply","base_generation":"4","configuration":{}})json"};
        return HttpRequestSpec{"POST", "/Operations/Reload", MakeAuthority(Endpoint),
            MakeOrigin(Endpoint), Token.empty() ? std::string{} : "Bearer " + Token,
            "application/json", std::string(Body)};
    }

    [[nodiscard]] auto BuildRequest(const HttpRequestSpec &Spec) -> std::string
    {
        std::string Request;
        Request.reserve(Spec.Body.size() + 512U);
        Request.append(Spec.Method).append(" ").append(Spec.Target).append(" HTTP/1.1\r\n");
        Request.append("Host: ").append(Spec.Host).append("\r\n");
        if (!Spec.Origin.empty()) Request.append("Origin: ").append(Spec.Origin).append("\r\n");
        if (!Spec.Authorization.empty())
            Request.append("Authorization: ").append(Spec.Authorization).append("\r\n");
        if (!Spec.ContentType.empty())
            Request.append("Content-Type: ").append(Spec.ContentType).append("\r\n");
        if (!Spec.Body.empty())
        {
            Request.append("Content-Length: ").append(std::to_string(Spec.Body.size())).append("\r\n");
        }
        Request.append("Connection: close\r\n\r\n").append(Spec.Body);
        return Request;
    }

    struct WireResponse final
    {
        int Status{0};
        std::string Wire;
        std::string Headers;
        std::string Body;
        boost::system::error_code Error;
        bool Closed{false};
        bool Complete{false};
    };

    [[nodiscard]] auto ReadContentLength(std::string_view Headers)
        -> std::optional<std::size_t>
    {
        constexpr std::string_view Key{"Content-Length: "};
        const auto Start = Headers.find(Key);
        if (Start == std::string_view::npos) return std::nullopt;
        const auto ValueStart = Start + Key.size();
        const auto End = Headers.find("\r\n", ValueStart);
        const auto ValueEnd = End == std::string_view::npos ? Headers.size() : End;
        std::size_t Length{};
        const auto [Position, Error] = std::from_chars(
            Headers.data() + ValueStart, Headers.data() + ValueEnd, Length);
        if (Error != std::errc{} || Position != Headers.data() + ValueEnd) return std::nullopt;
        return Length;
    }

    [[nodiscard]] auto ParseWireResponse(std::string Wire, const bool Closed,
                                         const boost::system::error_code Error)
        -> WireResponse
    {
        WireResponse Result;
        Result.Wire = Wire;
        Result.Closed = Closed;
        Result.Error = Error;
        const auto HeaderEnd = Wire.find("\r\n\r\n");
        if (HeaderEnd == std::string::npos) return Result;
        Result.Headers = Wire.substr(0, HeaderEnd);
        const auto LineEnd = Result.Headers.find("\r\n");
        if (LineEnd == std::string::npos || LineEnd < 12U) return Result;
        const auto [StatusEnd, StatusError] = std::from_chars(
            Result.Headers.data() + 9U, Result.Headers.data() + 12U, Result.Status);
        if (StatusError != std::errc{} || StatusEnd != Result.Headers.data() + 12U) return Result;
        const auto Length = ReadContentLength(Result.Headers);
        if (!Length || Wire.size() != HeaderEnd + 4U + *Length) return Result;
        Result.Body = Wire.substr(HeaderEnd + 4U, *Length);
        Result.Complete = true;
        return Result;
    }

    [[nodiscard]] auto ReadHttpResponse(Tcp::socket &Socket) -> Net::awaitable<WireResponse>
    {
        std::array<char, 4096> Buffer{};
        std::string Wire;
        boost::system::error_code TerminalError;
        bool Closed = false;
        constexpr std::size_t MaxResponseBytes = 8U * 1024U * 1024U;
        while (true)
        {
            boost::system::error_code Error;
            const auto Count = co_await Socket.async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            if (Count > MaxResponseBytes - std::min(Wire.size(), MaxResponseBytes))
            {
                TerminalError = Net::error::message_size;
                break;
            }
            Wire.append(Buffer.data(), Count);
            if (Count == 0U && !Error)
            {
                Closed = true;
                break;
            }
            if (Error)
            {
                if (Error == Net::error::eof || Error == Net::error::connection_reset)
                    Closed = true;
                else
                    TerminalError = Error;
                break;
            }
        }
        co_return ParseWireResponse(std::move(Wire), Closed, TerminalError);
    }

    /** @brief 按值接管可由临时值构造的请求，保证跨协程挂起后仍有效。 */
    [[nodiscard]] auto Exchange(Controller::Endpoint Endpoint,
                                HttpRequestSpec Spec) -> Net::awaitable<WireResponse>
    {
        Tcp::socket Socket(co_await Net::this_coro::executor);
        boost::system::error_code Error;
        co_await Socket.async_connect(Endpoint, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            WireResponse Result;
            Result.Error = Error;
            co_return Result;
        }
        const auto Request = BuildRequest(Spec);
        co_await Net::async_write(Socket, Net::buffer(Request),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            WireResponse Result;
            Result.Error = Error;
            co_return Result;
        }
        co_return co_await ReadHttpResponse(Socket);
    }

    [[nodiscard]] auto ExtractBootstrapToken(const WireResponse &Response)
        -> std::optional<std::string>
    {
        constexpr std::string_view Key{"\"command_token\":\""};
        const auto Begin = Response.Body.find(Key);
        if (Begin == std::string::npos) return std::nullopt;
        const auto Start = Begin + Key.size();
        const auto End = Response.Body.find('"', Start);
        if (End == std::string::npos || End - Start != 64U) return std::nullopt;
        return Response.Body.substr(Start, End - Start);
    }

    struct HttpScenarioResult final
    {
        std::array<WireResponse, 7> Pages;
        WireResponse Asset;
        WireResponse MissingAsset;
        WireResponse UnknownApi;
        WireResponse UnknownPath;
        WireResponse Traversal;
        WireResponse EncodedTraversal;
        WireResponse WrongHost;
        WireResponse WrongOrigin;
        WireResponse Bootstrap;
        WireResponse Health;
        WireResponse MissingTokenCommand;
        WireResponse ValidCommand;
        std::optional<Controller::DrainResult> Drain;
        std::string BootstrapToken;
    };

    struct HttpScenarioInput final
    {
        Controller &Server;
        Controller::Endpoint Endpoint;
    };

    [[nodiscard]] auto RunHttpScenario(HttpScenarioInput Input)
        -> Net::awaitable<HttpScenarioResult>
    {
        HttpScenarioResult Result;
        constexpr std::array<std::string_view, 7> Pages{
            "/", "/workers", "/accounts", "/sessions", "/events", "/configuration", "/operations"};
        for (std::size_t Index = 0; Index < Pages.size(); ++Index)
        {
            Result.Pages[Index] = co_await Exchange(Input.Endpoint,
                MakeGetSpec(Input.Endpoint, std::string(Pages[Index])));
        }
        Result.Asset = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/assets/app-0123456789abcdef.js"));
        Result.MissingAsset = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/assets/missing.js"));
        Result.UnknownApi = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/Operations/unknown"));
        Result.UnknownPath = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/unknown/path"));
        Result.Traversal = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/assets/../index.html"));
        Result.EncodedTraversal = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/assets/%2e%2e/index.html"));
        auto WrongHost = MakeGetSpec(Input.Endpoint, "/workers");
        WrongHost.Host = "untrusted.example";
        Result.WrongHost = co_await Exchange(Input.Endpoint, WrongHost);
        auto WrongOrigin = MakeGetSpec(Input.Endpoint, "/workers");
        WrongOrigin.Origin = "http://untrusted.example";
        Result.WrongOrigin = co_await Exchange(Input.Endpoint, WrongOrigin);
        Result.Bootstrap = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/Operations/Bootstrap"));
        const auto Token = ExtractBootstrapToken(Result.Bootstrap);
        if (Token) Result.BootstrapToken = *Token;
        Result.Health = co_await Exchange(Input.Endpoint,
            MakeGetSpec(Input.Endpoint, "/Operations/Health?correlation=771"));
        Result.MissingTokenCommand = co_await Exchange(Input.Endpoint,
            MakeReloadSpec(Input.Endpoint, {}));
        if (Token)
        {
            Result.ValidCommand = co_await Exchange(Input.Endpoint,
                MakeReloadSpec(Input.Endpoint, *Token));
        }
        Result.Drain = co_await Input.Server.Drain(
            std::chrono::steady_clock::now() + std::chrono::milliseconds{5000});
        co_return Result;
    }

    class WebHttpRuntimeFixture : public ::testing::Test
    {
    protected:
        static constexpr std::string_view IndexBody{
            "<!doctype html><html><body>catalog-index-v1</body></html>"};
        static constexpr std::string_view AssetBody{"export const build = 'asset-v1';"};

        auto SetUp() -> void override
        {
            std::error_code Error;
            TempRoot_ = std::filesystem::canonical(std::filesystem::temp_directory_path(), Error);
            ASSERT_FALSE(Error);
            const auto Tick = std::chrono::steady_clock::now().time_since_epoch().count();
            Root_ = TempRoot_ / ("Prism-WebHttpRuntime-" + std::to_string(Tick) + "-" +
                std::to_string(Next_.fetch_add(1U, std::memory_order_relaxed)));
            Created_ = std::filesystem::create_directory(Root_, Error);
            ASSERT_FALSE(Error);
            ASSERT_TRUE(Created_);
            OwnedRoot_ = std::filesystem::canonical(Root_, Error);
            ASSERT_FALSE(Error);
            OwnsRoot_ = OwnedRoot_.parent_path() == TempRoot_ &&
                OwnedRoot_.filename().string().starts_with("Prism-WebHttpRuntime-");
            ASSERT_TRUE(OwnsRoot_);
            ASSERT_TRUE(AddAsset("index.html", std::string(IndexBody)));
            ASSERT_TRUE(AddAsset("assets/app-0123456789abcdef.js", std::string(AssetBody)));
            ASSERT_TRUE(WriteManifest());
            auto Loaded = Web::LoadCatalog(OwnedRoot_);
            ASSERT_TRUE(Loaded);
            Catalog_ = std::move(*Loaded);
            const auto IndexDigest = Prism::Testing::OperationsWeb::Sha256Hex(IndexBody);
            ASSERT_TRUE(IndexDigest);
            IndexDigest_ = std::move(*IndexDigest);
            const auto AssetDigest = Prism::Testing::OperationsWeb::Sha256Hex(AssetBody);
            ASSERT_TRUE(AssetDigest);
            AssetDigest_ = std::move(*AssetDigest);
        }

        auto TearDown() -> void override
        {
            if (!Created_ || !OwnsRoot_) return;
            std::error_code Error;
            const auto Actual = std::filesystem::canonical(OwnedRoot_, Error);
            ASSERT_FALSE(Error);
            ASSERT_EQ(Actual, OwnedRoot_);
            ASSERT_EQ(Actual.parent_path(), TempRoot_);
            ASSERT_TRUE(Actual.filename().string().starts_with("Prism-WebHttpRuntime-"));
            std::filesystem::remove_all(Actual, Error);
            EXPECT_FALSE(Error);
            Created_ = false;
        }

        [[nodiscard]] auto AddAsset(std::string Path, std::string Body) -> bool
        {
            if (!Web::IsResourcePath(Path)) return false;
            std::error_code Error;
            std::filesystem::create_directories((OwnedRoot_ / Path).parent_path(), Error);
            if (Error) return false;
            std::ofstream Output(OwnedRoot_ / Path, std::ios::binary);
            if (!Output) return false;
            Output.write(Body.data(), static_cast<std::streamsize>(Body.size()));
            if (!Output) return false;
            auto Digest = Prism::Testing::OperationsWeb::Sha256Hex(Body);
            if (!Digest) return false;
            Manifest_.Assets.push_back(Web::ResourceDescriptor{Path,
                std::string(Web::ContentTypeFor(Path)), std::move(*Digest),
                static_cast<std::uint64_t>(Body.size()), Path.starts_with("assets/")});
            return true;
        }

        [[nodiscard]] auto WriteManifest() -> bool
        {
            Manifest_.Version = 1;
            const auto Json = glz::write_json(Manifest_);
            if (!Json) return false;
            std::ofstream Output(OwnedRoot_ / "catalog.json", std::ios::binary);
            if (!Output) return false;
            Output.write(Json->data(), static_cast<std::streamsize>(Json->size()));
            return static_cast<bool>(Output);
        }

        [[nodiscard]] auto ReplaceFile(const std::string_view Path,
                                       const std::string_view Body) const -> bool
        {
            if (!OwnsRoot_) return false;
            std::ofstream Output(OwnedRoot_ / std::string(Path), std::ios::binary | std::ios::trunc);
            if (!Output) return false;
            Output.write(Body.data(), static_cast<std::streamsize>(Body.size()));
            return static_cast<bool>(Output);
        }

        inline static std::atomic<std::uint64_t> Next_{0};
        std::filesystem::path TempRoot_;
        std::filesystem::path Root_;
        std::filesystem::path OwnedRoot_;
        Web::ResourceManifest Manifest_;
        std::shared_ptr<const Web::Catalog> Catalog_;
        std::string IndexDigest_;
        std::string AssetDigest_;
        bool Created_{false};
        bool OwnsRoot_{false};
    };

    [[nodiscard]] auto IsResponse(const WireResponse &Response, const int Status) -> bool
    {
        return Response.Complete && Response.Closed && !Response.Error && Response.Status == Status;
    }

    /** @brief 汇总一次失败响应可观测的全部字段，便于分阶段复现。 */
    [[nodiscard]] auto ResponseWire(const WireResponse &Response) -> std::string
    {
        std::string Text;
        Text.append("wire=").append(std::to_string(Response.Wire.size()))
            .append(" status=").append(std::to_string(Response.Status))
            .append(" complete=").append(Response.Complete ? "1" : "0")
            .append(" closed=").append(Response.Closed ? "1" : "0")
            .append(" error=").append(Response.Error.message())
            .append(" headers=[").append(Response.Headers).append("]");
        return Text;
    }

    /** @brief 报告单个响应在哪个阶段失败；诊断只描述已收到的 wire，不改变断言语义。 */
    [[nodiscard]] auto CheckResponse(
        const WireResponse &Response, const int Status, const std::string_view Label) -> bool
    {
        SCOPED_TRACE(std::string(Label));
        EXPECT_EQ(Response.Status, Status) << ResponseWire(Response);
        EXPECT_TRUE(Response.Complete) << ResponseWire(Response);
        EXPECT_TRUE(Response.Closed) << ResponseWire(Response);
        EXPECT_FALSE(Response.Error) << ResponseWire(Response);
        return IsResponse(Response, Status);
    }
}

TEST_F(WebHttpRuntimeFixture, ServesPublishedCatalogAndDrainsRealHttpConnections)
{
    auto Seen = std::make_shared<HandlerObservations>();
    Controller::Options Options;
    Options.BindEndpoint = Controller::Endpoint(Net::ip::address_v4::loopback(), 0);
    Options.Handlers = MakeHandlers(Seen);
    Options.ReadDeadline = std::chrono::milliseconds{5000};
    Options.DrainTimeout = std::chrono::milliseconds{5000};
    Options.Bootstrap = Prism::Testing::OperationsHttp::MakeTestBootstrap();
    Options.WebResources = Catalog_;
    Controller Server(std::move(Options));
    const auto Started = Server.Start();
    ASSERT_TRUE(Started);
    ASSERT_TRUE(ReplaceFile("index.html", "<!doctype html><html>disk-changed</html>"));
    ASSERT_TRUE(ReplaceFile("assets/app-0123456789abcdef.js", "export const build = 'disk-changed';"));

    Net::io_context ClientIo;
    std::optional<HttpScenarioResult> Scenario;
    std::exception_ptr Failure;
    Net::co_spawn(ClientIo, RunHttpScenario(HttpScenarioInput{Server, *Started}),
        [&Scenario, &Failure](std::exception_ptr Error, HttpScenarioResult Value)
        {
            Failure = std::move(Error);
            if (!Failure) Scenario.emplace(std::move(Value));
        });
    const auto HandlerCount = ClientIo.run();

    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Scenario);
    EXPECT_GT(HandlerCount, 0U);
    EXPECT_TRUE(ClientIo.stopped());
    const auto Joined = Server.Join();
    EXPECT_TRUE(Joined);
    EXPECT_TRUE(CheckResponse(Scenario->Bootstrap, 200, "bootstrap"));
    ASSERT_EQ(Scenario->BootstrapToken.size(), 64U);
    for (const auto &Page : Scenario->Pages)
    {
        ASSERT_TRUE(CheckResponse(Page, 200, "catalog page"));
        EXPECT_EQ(Page.Body, IndexBody);
        const auto Digest = Prism::Testing::OperationsWeb::Sha256Hex(Page.Body);
        ASSERT_TRUE(Digest);
        EXPECT_EQ(*Digest, IndexDigest_);
        EXPECT_NE(Page.Headers.find("Cache-Control: no-store"), std::string::npos);
        EXPECT_NE(Page.Headers.find("Content-Security-Policy:"), std::string::npos);
        EXPECT_NE(Page.Headers.find("X-Content-Type-Options: nosniff"), std::string::npos);
        EXPECT_NE(Page.Headers.find("Referrer-Policy: no-referrer"), std::string::npos);
    }
    ASSERT_TRUE(CheckResponse(Scenario->Asset, 200, "catalog asset"));
    EXPECT_EQ(Scenario->Asset.Body, AssetBody);
    const auto AssetDigest = Prism::Testing::OperationsWeb::Sha256Hex(Scenario->Asset.Body);
    ASSERT_TRUE(AssetDigest);
    EXPECT_EQ(*AssetDigest, AssetDigest_);
    EXPECT_NE(Scenario->Asset.Headers.find("Content-Type: text/javascript; charset=utf-8"),
        std::string::npos);
    EXPECT_NE(Scenario->Asset.Headers.find(
        "Cache-Control: public, max-age=31536000, immutable"), std::string::npos);

    for (const auto *Response : {&Scenario->MissingAsset, &Scenario->UnknownApi,
            &Scenario->UnknownPath, &Scenario->Traversal, &Scenario->EncodedTraversal})
    {
        EXPECT_TRUE(Response->Complete)
            << "status=" << Response->Status
            << " wire_size=" << Response->Wire.size()
            << " closed=" << Response->Closed
            << " error=" << Response->Error.message()
            << " headers=" << Response->Headers;
        EXPECT_NE(Response->Status, 200);
        EXPECT_EQ(Response->Body.find(IndexBody), std::string::npos);
    }
    EXPECT_TRUE(CheckResponse(Scenario->WrongHost, 403, "wrong host"));
    EXPECT_TRUE(CheckResponse(Scenario->WrongOrigin, 403, "wrong origin"));
    EXPECT_TRUE(CheckResponse(Scenario->Health, 200, "health"));
    EXPECT_NE(Scenario->Health.Body.find("\"ready\":true"), std::string::npos);
    EXPECT_EQ(Seen->QueryCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_TRUE(CheckResponse(Scenario->MissingTokenCommand, 403, "missing token"));
    EXPECT_TRUE(CheckResponse(Scenario->ValidCommand, 202, "valid command"));
    EXPECT_NE(Scenario->ValidCommand.Body.find("\"status\":\"accepted\""), std::string::npos);
    EXPECT_NE(Scenario->ValidCommand.Body.find("\"configuration_issues\":[]"), std::string::npos);
    EXPECT_NE(Scenario->ValidCommand.Body.find("\"restart_required_fields\":[]"), std::string::npos);
    EXPECT_EQ(Seen->CommandCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(Seen->ReloadConfiguration, "{}");
    ASSERT_TRUE(Scenario->Drain);
    EXPECT_TRUE(Scenario->Drain->Failure.Succeeded());
    EXPECT_EQ(Scenario->Drain->RemainingConnections, 0U);
    EXPECT_NE(Server.LocalEndpoint().port(), 0U);
}

TEST(OperationsWebHttpRuntime, ServesManagementApiWithoutPublishedCatalog)
{
    auto Seen = std::make_shared<HandlerObservations>();
    Controller::Options Options;
    Options.BindEndpoint = Controller::Endpoint(Net::ip::address_v4::loopback(), 0);
    Options.Handlers = MakeHandlers(Seen);
    Options.ReadDeadline = std::chrono::milliseconds{5000};
    Options.DrainTimeout = std::chrono::milliseconds{5000};
    Options.Bootstrap = Prism::Testing::OperationsHttp::MakeTestBootstrap();
    Controller Server(std::move(Options));
    const auto Started = Server.Start();
    ASSERT_TRUE(Started);

    Net::io_context ClientIo;
    std::optional<HttpScenarioResult> Scenario;
    std::exception_ptr Failure;
    Net::co_spawn(ClientIo, RunHttpScenario(HttpScenarioInput{Server, *Started}),
        [&Scenario, &Failure](std::exception_ptr Error, HttpScenarioResult Value)
        {
            Failure = std::move(Error);
            if (!Failure) Scenario.emplace(std::move(Value));
        });
    const auto HandlerCount = ClientIo.run();

    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Scenario);
    EXPECT_GT(HandlerCount, 0U);
    EXPECT_TRUE(ClientIo.stopped());
    const auto Joined = Server.Join();
    EXPECT_TRUE(Joined);
    EXPECT_TRUE(CheckResponse(Scenario->Asset, 404, "missing catalog asset"));
    EXPECT_TRUE(CheckResponse(Scenario->Bootstrap, 200, "bootstrap"));
    ASSERT_EQ(Scenario->BootstrapToken.size(), 64U);
    EXPECT_TRUE(CheckResponse(Scenario->Health, 200, "health"));
    EXPECT_NE(Scenario->Health.Body.find("\"ready\":true"), std::string::npos);
    EXPECT_EQ(Seen->QueryCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_TRUE(CheckResponse(Scenario->MissingTokenCommand, 403, "missing token"));
    EXPECT_TRUE(CheckResponse(Scenario->ValidCommand, 202, "valid command"));
    EXPECT_EQ(Seen->CommandCalls.load(std::memory_order_relaxed), 1U);
    ASSERT_TRUE(Scenario->Drain);
    EXPECT_TRUE(Scenario->Drain->Failure.Succeeded());
    EXPECT_EQ(Scenario->Drain->RemainingConnections, 0U);
}
