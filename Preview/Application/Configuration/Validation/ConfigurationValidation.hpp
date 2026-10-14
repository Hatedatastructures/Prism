/**
 * @file ConfigurationValidation.hpp
 * @brief Preview 配置校验的顺序编排入口。
 */
#pragma once

#include <Preview/Application/Configuration/ReferenceGraph.hpp>
#include <Preview/Application/Configuration/Validation/CapabilityValidation.hpp>
#include <Preview/Application/Configuration/Validation/CarrierValidation.hpp>
#include <Preview/Application/Configuration/Validation/ReferenceValidation.hpp>
#include <Preview/Application/Configuration/Validation/SchemaValidation.hpp>

#include <string>
#include <unordered_set>
#include <vector>

namespace Preview::Application::Configuration::Validation
{

    /**
     * @brief 拥有配置引用图、协议 descriptor 和跨阶段唯一 ID 集合的冷校验 owner。
     * @details 该 owner 只在同步冷路径运行；输入配置与选项由调用者保持有效，输出只返回首个 typed 错误。
     *          不持有运行时服务、不跨越 await，也不复制凭据或注册表。
     */
    class ReferenceValidationOwner final
    {
    public:
        ReferenceValidationOwner(const PreviewConfiguration &Configuration,
                                 const ValidationOptions &Options)
            : Configuration_(Configuration), Options_(Options),
              References_(ReferenceGraph::Build(Configuration)),
              ProtocolDescriptors_(Configuration.Protocols.size(), nullptr)
        {
        }

        /**
         * @brief 按固定阶段顺序执行引用、能力和路由校验。
         * @return 空结果表示通过；失败保留首个阶段的 code/path/message。
         * @note 同步冷调用；不接管 Configuration 或 Options，不执行取消、半关闭或异步操作。
         */
        [[nodiscard]] auto Validate() -> Result
        {
            if (const auto ResultValue = ValidateListeners(Configuration_, Ids_); !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateNativeTls(Configuration_); !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateBuiltins(Configuration_.Builtins, Options_, Ids_);
                !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateProtocolStage(); !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateCarriers(Configuration_.Carriers, Options_, Ids_);
                !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateBindingStage(); !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateBindingRouteStage(); !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateCarrierRouteAmbiguity(Configuration_, References_);
                !ResultValue)
            {
                return ResultValue;
            }
            if (const auto ResultValue = ValidateAccounts(Configuration_, Options_, Ids_); !ResultValue)
            {
                return ResultValue;
            }
            return ValidateRoutes(Configuration_, Ids_);
        }

    private:
        [[nodiscard]] auto ValidateProtocolStage() -> Result
        {
            for (std::size_t Index = 0; Index < Configuration_.Protocols.size(); ++Index)
            {
                const auto &Protocol = Configuration_.Protocols[Index];
                const auto Path = "Protocols[" + std::to_string(Index) + "]";
                if (const auto ResultValue = AddId(Ids_, Protocol.Id, Path + ".Id"); !ResultValue)
                {
                    return ResultValue;
                }
                if (Protocol.Name.empty() || Protocol.Builtin.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path,
                                   "protocol Name and Builtin are required");
                }
                if (IsCarrierBuiltin(Protocol.Builtin))
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".Builtin",
                                   "carrier builtin cannot be configured as a protocol");
                }
                if (Options_.Builtins)
                {
                    const auto *Entry = FindBuiltinDescriptor(
                        *Options_.Builtins, "protocol", Protocol.Builtin);
                    if (!Entry)
                    {
                        return Failure(ConfigurationErrorCode::MissingReference,
                                       Path + ".Builtin",
                                       "protocol builtin is unavailable in the frozen snapshot");
                    }
                    ProtocolDescriptors_[Index] = Entry;
                }
                else if (Options_.RequireBuiltinSnapshot)
                {
                    return Failure(ConfigurationErrorCode::MissingReference,
                                   Path + ".Builtin",
                                   "configured protocol requires a frozen builtin snapshot");
                }

                const bool IsQuic = Protocol.Builtin == "hysteria2" || Protocol.Builtin == "tuic";
                if (IsQuic && !QuicProtocolNames_.insert(Protocol.Builtin).second)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".Builtin",
                                   "duplicate QUIC protocol builtin");
                }
                if (IsQuic && QuicProtocolNames_.size() > 1U)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".Builtin",
                                   "shared QUIC listener supports exactly one protocol; Hysteria2 and TUIC "
                                   "cannot be admitted by trialing multiple QUIC engines");
                }
                if (IsQuic && !Protocol.Quic)
                {
                    return Failure(ConfigurationErrorCode::MissingField,
                                   Path + ".Quic",
                                   "QUIC protocol configuration is required");
                }
                if (!IsQuic && Protocol.Quic)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".Quic",
                                   "Quic options are only valid for hysteria2 or tuic");
                }
                if (Protocol.Quic)
                {
                    if (Protocol.Builtin == "tuic" && !IsValidUuidText(Protocol.Quic->Uuid))
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".Quic.Uuid",
                                       "TUIC requires a 16-byte UUID text");
                    }
                    if (Protocol.Quic->Alpn != "h3")
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".Quic.Alpn",
                                       "Hysteria2 and TUIC require ALPN h3");
                    }
                    if (Protocol.Quic->ServerName.empty())
                    {
                        return Failure(ConfigurationErrorCode::MissingField,
                                       Path + ".Quic.ServerName",
                                       "QUIC ServerName is required");
                    }
                    if (Protocol.Quic->MaxStreams == 0U || Protocol.Quic->MaxDatagrams == 0U)
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".Quic",
                                       "QUIC stream and datagram limits must be positive");
                    }
                    if (const auto ResultValue = ValidateSecretReference(
                            Protocol.Quic->CredentialSecretRef,
                            Path + ".Quic.CredentialSecretRef",
                            Options_);
                        !ResultValue)
                    {
                        return ResultValue;
                    }
                }
            }
            return {};
        }

        [[nodiscard]] auto ValidateBindingStage() -> Result
        {
            for (std::size_t Index = 0; Index < Configuration_.ProtocolBindings.size(); ++Index)
            {
                const auto &Binding = Configuration_.ProtocolBindings[Index];
                const auto Path = "ProtocolBindings[" + std::to_string(Index) + "]";
                if (const auto ResultValue = AddId(Ids_, Binding.Id, Path + ".Id"); !ResultValue)
                {
                    return ResultValue;
                }
                if (Binding.ProtocolId.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".ProtocolId",
                                   "ProtocolId is required");
                }
                const auto ProtocolIndex = References_.FindProtocolIndex(Binding.ProtocolId);
                if (!ProtocolIndex)
                {
                    return Failure(ConfigurationErrorCode::MissingReference,
                                   Path + ".ProtocolId",
                                   "ProtocolId does not reference a configured protocol");
                }
                if (Binding.CarrierId)
                {
                    if (Binding.CarrierId->empty())
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".CarrierId",
                                       "CarrierId must not be empty when present");
                    }
                    const auto CarrierIndex = References_.FindCarrierIndex(*Binding.CarrierId);
                    if (!CarrierIndex)
                    {
                        return Failure(ConfigurationErrorCode::MissingReference,
                                       Path + ".CarrierId",
                                       "CarrierId does not reference a configured carrier");
                    }
                    const auto &Protocol = Configuration_.Protocols[*ProtocolIndex];
                    const auto &Carrier = Configuration_.Carriers[*CarrierIndex];
                    if (IsStackProtocolBuiltin(Protocol.Builtin) &&
                        !(Protocol.Builtin == "anytls" && Carrier.Builtin == "native"))
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".CarrierId",
                                       "stack protocol can only use the native TLS outer carrier");
                    }
                }
                if (const auto ResultValue = ValidateRecognitionRoute(
                        Binding.Recognition, Path + ".Recognition");
                    !ResultValue)
                {
                    return ResultValue;
                }
                if (!Binding.TcpEnabled && !Binding.UdpEnabled)
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path,
                                   "at least one of TcpEnabled and UdpEnabled is required");
                }
                for (std::size_t MuxIndex = 0; MuxIndex < Binding.MuxModes.size(); ++MuxIndex)
                {
                    if (Binding.MuxModes[MuxIndex] == "4C64S" ||
                        Binding.MuxModes[MuxIndex] == "1C256S")
                    {
                        return Failure(ConfigurationErrorCode::InvalidValue,
                                       Path + ".MuxModes[" + std::to_string(MuxIndex) + "]",
                                       "mux connection profiles require a physical connection pool");
                    }
                    if (!IsMuxMode(Binding.MuxModes[MuxIndex]))
                    {
                        return Failure(ConfigurationErrorCode::UnknownMuxMode,
                                       Path + ".MuxModes[" + std::to_string(MuxIndex) + "]",
                                       "unknown mux mode");
                    }
                }
                const auto &Protocol = Configuration_.Protocols[*ProtocolIndex];
                if (Protocol.Builtin == "anytls" && !Binding.MuxModes.empty())
                {
                    return Failure(ConfigurationErrorCode::InvalidValue,
                                   Path + ".MuxModes",
                                   "AnyTLS owns application-layer multiplexing; generic mux modes are not supported");
                }
                const auto *Entry = ProtocolDescriptors_[*ProtocolIndex];
                if (Entry)
                {
                    const auto &Provides = Entry->Descriptor.Provides;
                    if (Binding.TcpEnabled &&
                        !Provides.Declares(Preview::Composition::Builtin::Capability::Stream))
                    {
                        return Failure(ConfigurationErrorCode::MissingCapability,
                                       Path + ".TcpEnabled",
                                       "protocol builtin does not provide Stream");
                    }
                    if (Binding.UdpEnabled &&
                        !Provides.Declares(Preview::Composition::Builtin::Capability::Datagram) &&
                        !Provides.Declares(Preview::Composition::Builtin::Capability::Quic))
                    {
                        return Failure(ConfigurationErrorCode::MissingCapability,
                                       Path + ".UdpEnabled",
                                       "protocol builtin does not provide Datagram or Quic");
                    }
                    if (!Binding.MuxModes.empty() &&
                        !Provides.Declares(Preview::Composition::Builtin::Capability::Multiplex))
                    {
                        return Failure(ConfigurationErrorCode::MissingCapability,
                                       Path + ".MuxModes",
                                       "protocol builtin does not provide Multiplex");
                    }
                }
            }
            return {};
        }

        [[nodiscard]] auto ValidateBindingRouteStage() const -> Result
        {
            for (std::size_t LeftIndex = 0; LeftIndex < Configuration_.ProtocolBindings.size(); ++LeftIndex)
            {
                const auto &Left = Configuration_.ProtocolBindings[LeftIndex];
                const auto LeftName = std::string_view(Left.Recognition.Pattern);
                if (LeftName.empty() && !Left.Recognition.Fallback)
                {
                    continue;
                }
                for (std::size_t RightIndex = LeftIndex + 1U;
                     RightIndex < Configuration_.ProtocolBindings.size();
                     ++RightIndex)
                {
                    const auto &Right = Configuration_.ProtocolBindings[RightIndex];
                    if (Left.Priority != Right.Priority ||
                        Left.Recognition.Fallback != Right.Recognition.Fallback)
                    {
                        continue;
                    }
                    const auto RightName = std::string_view(Right.Recognition.Pattern);
                    if (RightName.empty() && !Right.Recognition.Fallback)
                    {
                        continue;
                    }
                    if (LeftName.empty() || RightName.empty() ||
                        ServerNamePatternsOverlap(LeftName, RightName))
                    {
                        return Failure(
                            ConfigurationErrorCode::InvalidValue,
                            "ProtocolBindings[" + std::to_string(RightIndex) + "].Recognition",
                            "protocol recognition route is ambiguous at equal priority");
                    }
                }
            }
            return {};
        }

        const PreviewConfiguration &Configuration_;
        const ValidationOptions &Options_;
        ReferenceGraph References_;
        std::unordered_set<std::string> Ids_;
        std::unordered_set<std::string> QuicProtocolNames_;
        std::vector<BuiltinEntryPointer> ProtocolDescriptors_;
    };

    [[nodiscard]] inline auto ValidateConfiguration(
        const ValidationRequest &Request) -> Result
    {
        const auto &Configuration = Request.Configuration;
        if (const auto ResultValue = ValidateSchema(Configuration); !ResultValue)
        {
            return ResultValue;
        }

        ReferenceValidationOwner ReferenceOwner(Configuration, Request.Options);
        if (const auto ResultValue = ReferenceOwner.Validate(); !ResultValue)
        {
            return ResultValue;
        }
        if (const auto ResultValue = ValidateDnsAndPublicSettings(Configuration); !ResultValue)
        {
            return ResultValue;
        }
        return ValidateRequiredCapabilities(Configuration, Request.Options);
    }

} // namespace Preview::Application::Configuration::Validation
