/**
 * @file ConfigurationValidationCompareScenario.cpp
 * @brief 配置校验对照工具的固定 JSON 场景和语义预检实现。
 */

#include "ConfigurationValidationCompareScenario.hpp"

#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>

#include <glaze/glaze.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Application::Configuration::Perf::Scenario
{

    namespace
    {

        constexpr std::uint64_t FnvPrime = 1099511628211ull;

        auto Require(const bool Condition, const std::string_view Message) -> void
        {
            if (!Condition)
            {
                throw std::invalid_argument(std::string{Message});
            }
        }

        auto Mix(std::uint64_t &Hash, const std::uint64_t Value) noexcept -> void
        {
            Hash ^= Value;
            Hash *= FnvPrime;
        }

        auto HashBytes(const std::string_view Value, const std::uint64_t Seed) noexcept
            -> std::uint64_t
        {
            auto Hash = FnvOffset;
            Mix(Hash, Seed);
            for (const auto Character : Value)
            {
                Mix(Hash, static_cast<std::uint64_t>(
                             static_cast<unsigned char>(Character)));
            }
            return Hash;
        }

        auto MakeNativeCarrier(const std::string_view Id)
            -> Preview::Application::Configuration::CarrierConfiguration
        {
            using Preview::Application::Configuration::CarrierConfiguration;
            using Preview::Application::Configuration::NativeTlsOptions;

            CarrierConfiguration Carrier;
            Carrier.Id = std::string{Id};
            Carrier.Name = "native-tls";
            Carrier.Builtin = "native";
            Carrier.Match.ServerNames = {"shared.example.com"};
            Carrier.Match.Alpn = {"h2"};
            Carrier.Match.Priority = 0;
            Carrier.Match.Fallback = false;
            Carrier.Options = NativeTlsOptions{"cert.pem", "key.pem"};
            return Carrier;
        }

        auto MakeConfiguration(const ScenarioSpec &Spec) -> PreviewConfiguration
        {
            using Preview::Application::Configuration::AccountConfiguration;
            using Preview::Application::Configuration::BuiltinConfiguration;
            using Preview::Application::Configuration::ListenerEndpoint;
            using Preview::Contract::ProtocolBindingConfiguration;
            using Preview::Contract::ProtocolConfiguration;
            using Preview::Application::Configuration::RouteConfiguration;

            PreviewConfiguration Configuration = PreviewConfiguration::Defaults();
            Configuration.Runtime.WorkerCount = 1;
            Configuration.Runtime.RequiredCapabilities = {"Stream", "Datagram", "Multiplex"};
            Configuration.Listeners.Tcp.push_back(
                ListenerEndpoint{"tcp-main", "127.0.0.1", 1080, 5000});
            Configuration.Builtins.push_back(
                BuiltinConfiguration{"builtin-socks5", "protocol", "socks5", {}, {}});
            Configuration.Carriers.push_back(MakeNativeCarrier("carrier-native"));
            if (Spec.Kind == ScenarioKind::CarrierRouteConflict)
            {
                Configuration.Carriers.push_back(MakeNativeCarrier("carrier-conflict"));
            }

            Configuration.Protocols.reserve(Spec.Nodes);
            Configuration.ProtocolBindings.reserve(Spec.Nodes);
            Configuration.Accounts.reserve(Spec.Nodes);
            Configuration.Routes.reserve(Spec.Nodes);
            for (std::size_t Index = 0; Index < Spec.Nodes; ++Index)
            {
                const auto NodeName = std::string{"node-"} + std::to_string(Index);
                const auto ProtocolId = std::string{"protocol-"} + std::to_string(Index);
                const auto BindingId = std::string{"binding-"} + std::to_string(Index);

                Preview::Contract::ProtocolConfiguration Protocol;
                Protocol.Id = ProtocolId;
                Protocol.Name = "socks5";
                Protocol.Builtin = "socks5";
                Configuration.Protocols.push_back(std::move(Protocol));

                Preview::Contract::ProtocolBindingConfiguration Binding;
                Binding.Id = BindingId;
                Binding.ProtocolId = ProtocolId;
                Binding.CarrierId =
                    Spec.Kind == ScenarioKind::CarrierRouteConflict && Index == 1
                        ? "carrier-conflict"
                        : "carrier-native";
                Binding.TcpEnabled = true;
                Binding.UdpEnabled = false;
                Binding.MuxModes = {"Smux"};
                Binding.Priority = Spec.Kind == ScenarioKind::CarrierRouteConflict && Index == 1
                                       ? 1
                                       : static_cast<std::int32_t>(Index + 1U);
                Binding.Recognition.Pattern = NodeName + ".example.com";
                Configuration.ProtocolBindings.push_back(std::move(Binding));

                AccountConfiguration Account;
                Account.Id = std::string{"account-"} + std::to_string(Index);
                Account.Credential = std::string{"credential-"} + std::to_string(Index);
                Configuration.Accounts.push_back(std::move(Account));

                RouteConfiguration Route;
                Route.Id = std::string{"route-"} + std::to_string(Index);
                Route.Match = NodeName;
                Route.Target = std::string{"target-"} + std::to_string(Index);
                Configuration.Routes.push_back(std::move(Route));
            }
            return Configuration;
        }

        auto SerializeConfiguration(const PreviewConfiguration &Configuration) -> std::string
        {
            std::string Json;
            if (const auto Error = glz::write_json(Configuration, Json); Error)
            {
                throw std::runtime_error("configuration serialization failed: " +
                                         std::string{glz::format_error(Error)});
            }
            return Json;
        }

        auto DecodeConfiguration(const std::string_view Json) -> PreviewConfiguration
        {
            PreviewConfiguration Configuration;
            if (const auto Error = glz::read_json(Configuration, Json); Error)
            {
                throw std::runtime_error("input configuration decode failed: " +
                                         std::string{glz::format_error(Error)});
            }
            return Configuration;
        }

        auto ReadFile(const std::filesystem::path &Path) -> std::string
        {
            std::ifstream File(Path, std::ios::binary);
            if (!File)
            {
                throw std::runtime_error("cannot open input JSON: " + Path.string());
            }
            return std::string(std::istreambuf_iterator<char>(File),
                               std::istreambuf_iterator<char>());
        }

    } // namespace

    auto ScenarioName(const ScenarioKind Kind) -> const char *
    {
        switch (Kind)
        {
        case ScenarioKind::Valid:
            return "valid";
        case ScenarioKind::CarrierRouteConflict:
            return "carrier-route-conflict";
        case ScenarioKind::All:
            return "all";
        }
        return "unknown";
    }

    auto MakeExpectedError(const ScenarioKind Kind) -> ExpectedError
    {
        if (Kind == ScenarioKind::CarrierRouteConflict)
        {
            return {true, ConfigurationErrorCode::InvalidValue, "Carriers[1].Match"};
        }
        return {};
    }

    auto MakeValidationOptions(const SnapshotPointer &Builtins) -> ValidationOptions
    {
        ValidationOptions Options;
        Options.Builtins = Builtins;
        Options.CheckSecrets = false;
        Options.CheckCapabilities = true;
        Options.RequireBuiltinSnapshot = true;
        return Options;
    }

    auto MakeStaticBuiltinSnapshot() -> SnapshotPointer
    {
        auto RegistryValue = Preview::Composition::Builtin::MakeStaticBuiltinRegistry();
        if (!Preview::Composition::Builtin::RegisterStaticBuiltins(RegistryValue, {}))
        {
            return nullptr;
        }
        const auto Frozen = RegistryValue.Freeze(
            Preview::Composition::Builtin::FreezeRequest{});
        return Frozen ? *Frozen : nullptr;
    }

    auto MakeScenario(const ScenarioSpec &Spec) -> Scenario
    {
        Scenario Result;
        Result.Configuration = MakeConfiguration(Spec);
        Result.Json = SerializeConfiguration(Result.Configuration);
        Result.Nodes = Spec.Nodes;
        Result.TraceHash = HashBytes(Result.Json, Spec.Seed);
        Result.Kind = Spec.Kind;
        Result.Expected = MakeExpectedError(Spec.Kind);
        return Result;
    }

    auto WriteFile(const std::filesystem::path &Path, const std::string_view Contents) -> void
    {
        std::ofstream File(Path, std::ios::binary | std::ios::trunc);
        if (!File)
        {
            throw std::runtime_error("cannot create input JSON: " + Path.string());
        }
        File.write(Contents.data(), static_cast<std::streamsize>(Contents.size()));
        if (!File)
        {
            throw std::runtime_error("cannot write input JSON: " + Path.string());
        }
    }

    auto LoadScenario(const Options &Settings, const SnapshotPointer &Builtins) -> Scenario
    {
        Require(!Settings.InputPath.empty(), "input path is required");
        Scenario Result;
        Result.Json = ReadFile(Settings.InputPath);
        Result.Configuration = DecodeConfiguration(Result.Json);
        Result.Nodes = Result.Configuration.Protocols.size();
        Require(Result.Nodes == 64U || Result.Nodes == 1024U,
                "input must contain 64 or 1024 protocol nodes");
        Result.TraceHash = HashBytes(Result.Json, Settings.Seed);
        Result.Kind = Settings.Scenario;
        Result.Expected = MakeExpectedError(Settings.Scenario);

        const auto Parsed = Parser::Parse(
            {.Json = Result.Json, .Options = MakeValidationOptions(Builtins)});
        const auto ParserError = CaptureError(Parsed);
        if (!MatchesExpected(ParserError, Result.Expected))
        {
            throw std::runtime_error("input JSON does not match the selected scenario");
        }
        return Result;
    }

    auto ValidateScenario(const Scenario &ScenarioValue,
                          const SnapshotPointer &Builtins) -> bool
    {
        const auto Parsed = Parser::Parse(
            {.Json = ScenarioValue.Json, .Options = MakeValidationOptions(Builtins)});
        const auto Validated = Parser::Validate(
            ValidationRequest{ScenarioValue.Configuration,
                              MakeValidationOptions(Builtins)});
        const auto ParserError = CaptureError(Parsed);
        const auto ValidatorError = CaptureError(Validated);
        return MatchesExpected(ParserError, ScenarioValue.Expected) &&
               MatchesExpected(ValidatorError, ScenarioValue.Expected) &&
               SameError(ParserError, ValidatorError);
    }

} // namespace Preview::Application::Configuration::Perf::Scenario
