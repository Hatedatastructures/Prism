# Prism Foundation and the standalone Prism target graph.

include(CMake/PrismBoundary.cmake)
include(CMake/PrismSqlite.cmake)

function(ConfigurePrismTarget Target)
    if(NOT "${Target}" MATCHES "^[A-Z][A-Za-z0-9]*$")
        message(FATAL_ERROR "Prism/TestSupport target 必须使用 PascalCase：${Target}")
    endif()
    target_include_directories(${Target} INTERFACE ${CMAKE_SOURCE_DIR})
endfunction()

add_library(PrismFoundation INTERFACE)
ConfigurePrismTarget(PrismFoundation)
target_link_libraries(PrismFoundation INTERFACE PrismSqlite)
target_sources(PrismFoundation INTERFACE
        Foundation/Error.hpp
        Foundation/ByteSpan.hpp
        Foundation/FlatBuffer.hpp
        Foundation/Foundation.hpp
        Foundation/Parser.hpp
        Foundation/Role.hpp
        Foundation/Utility/TrafficSink.hpp
        Foundation/Utility/Http/HeaderFields.hpp
        Foundation/Utility/Http/ForwardResponseFields.hpp
        Foundation/Utility/Http/ForwardResponseFraming.hpp
        Foundation/Utility/Http/ForwardResponseFramingDetail.hpp
        Foundation/Utility/Text/Redaction.hpp
        Foundation/Utility/Text/TraceSelection.hpp
        Foundation/Utility/Text/View.hpp
        Foundation/Utility/Text/Truncate.hpp
        Foundation/Utility/Crypto/Aead.hpp
        Foundation/Utility/Crypto/Base64.hpp
        Foundation/Utility/Crypto/Blake3.hpp
        Foundation/Utility/Crypto/Block.hpp
        Foundation/Utility/Crypto/Crypto.hpp
        Foundation/Utility/Crypto/Hkdf.hpp
        Foundation/Utility/Crypto/Operation.hpp
        Foundation/Utility/Crypto/SecretScope.hpp
        Foundation/Utility/Crypto/Random.hpp
        Foundation/Utility/Crypto/Sha224.hpp
        Foundation/Utility/Crypto/X25519.hpp
        Foundation/Utility/Diagnose/Observability.hpp
        Foundation/Utility/Diagnose/Facade.hpp
        Foundation/Utility/Diagnose/ContextState.hpp
        Foundation/Utility/Diagnose/FieldKey.hpp
        Foundation/Utility/Diagnose/FieldCodec.hpp
        Foundation/Utility/Diagnose/FieldCatalog.hpp
        Foundation/Utility/Diagnose/PrefixCache.hpp
        Foundation/Utility/Diagnose/RenderMode.hpp
        Foundation/Utility/Diagnose/RuntimeOptions.hpp
        Foundation/Utility/Diagnose/FormattingLimits.hpp
        Foundation/Utility/Diagnose/SubmissionReceipt.hpp
        Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp
        Foundation/Utility/Diagnose/Detail/SubmissionSlot.hpp
        Foundation/Utility/Diagnose/Detail/FormatValidation.hpp
        Foundation/Utility/Diagnose/Detail/BackendWorker.hpp
        Foundation/Utility/Diagnose/Detail/ContextSnapshot.hpp
        Foundation/Utility/Diagnose/Detail/ContextStorage.hpp
        Foundation/Utility/Diagnose/Detail/DeferredMessage.hpp
        Foundation/Utility/Diagnose/Detail/RenderRecord.hpp
        Foundation/Utility/Text/Case.hpp
        Foundation/Utility/Text/FixedText.hpp
        Foundation/Exception/Deviant.hpp
        Foundation/Exception/Network.hpp
        Foundation/Exception/Protocol.hpp
        Foundation/Exception/Security.hpp
        Foundation/Fault/Code.hpp
        Foundation/Fault/Failure.hpp
        Foundation/Fault/FailureState.hpp
        Foundation/Fault/Compatible.hpp
        Foundation/Fault/Handling.hpp
        Foundation/Cancellation/Mode.hpp
        Foundation/Cancellation/Types.hpp
        Foundation/Error/Code.hpp
        Foundation/Error/Error.hpp
        Foundation/Error/Expected.hpp
        Foundation/Executor/Affinity.hpp
        Foundation/Executor/Types.hpp
        Foundation/Executor/ExecutorReclaimer.hpp
        Foundation/Executor/PreparedAction.hpp
        Foundation/Executor/ClosingStorage.hpp
        Foundation/Executor/ContextOwner.hpp
        Foundation/Executor/FatalState.hpp
        Foundation/Executor/RunContext.hpp
        Foundation/Identifier/Id.hpp
        Foundation/Identifier/SessionIdAllocator.hpp
        Foundation/Generation/Lifetime.hpp
        Foundation/Identifier/Identifier.hpp
        Foundation/Identifier/Types.hpp
        Foundation/Memory/Container.hpp
        Foundation/Memory/BytePoolOptions.hpp
        Foundation/Memory/BytePool.hpp
        Foundation/Memory/OwnedBytes.hpp
        Foundation/Memory/Detail/BytePoolState.hpp
        Foundation/Memory/CowMap.hpp
        Foundation/Memory/Domain.hpp
        Foundation/Memory/Pointer.hpp
        Foundation/Memory/Pool.hpp
        Foundation/Memory/Types.hpp
        Foundation/Utility/Rate/TokenBucket.hpp
)
target_link_libraries(PrismFoundation INTERFACE
        OpenSSL::Crypto
        Blake3C
        BoostSystemHeaderOnly
)

add_library(PrismAccount INTERFACE)
ConfigurePrismTarget(PrismAccount)
target_sources(PrismAccount INTERFACE
        Account/Account.hpp
        Account/Authenticator.hpp
        Account/Binding.hpp
        Account/Credential.hpp
        Account/CredentialScope.hpp
        Account/Detail/LeasePool.hpp
        Account/Detail/RateLedger.hpp
        Account/Failure.hpp
        Account/Index.hpp
        Account/Lease.hpp
        Account/Materials.hpp
        Account/Policy.hpp
        Account/PolicyVersion.hpp
        Account/Quota.hpp
        Account/Rate.hpp
        Account/RateTypes.hpp
        Account/Runtime.hpp
        Account/SecureBytes.hpp
        Account/Store.hpp
)
LinkPrismTargets(PrismAccount PrismFoundation)

add_library(PrismLifecycle INTERFACE)
ConfigurePrismTarget(PrismLifecycle)
target_sources(PrismLifecycle INTERFACE
        Lifecycle/CancellationDomain.hpp
        Lifecycle/DrainBarrier.hpp
        Lifecycle/Detail/DrainNotification.hpp
        Lifecycle/CloseFailure.hpp
        Lifecycle/DrainReservation.hpp
        Lifecycle/TaskReservation.hpp
        Lifecycle/TaskSubmission.hpp
        Lifecycle/Lifecycle.hpp
        Lifecycle/TaskRegistry.hpp
        Lifecycle/TaskRetirementReceipt.hpp
        Lifecycle/TaskRegistryState.hpp
        Lifecycle/TaskRegistryCommands.hpp
        Lifecycle/TaskState.hpp
        Lifecycle/TaskIdSet.hpp
)
LinkPrismTargets(PrismLifecycle PrismFoundation)

add_library(PrismResource INTERFACE)
ConfigurePrismTarget(PrismResource)
target_sources(PrismResource INTERFACE
        Resource/ProcessResources.hpp
        Resource/Resource.hpp
        Resource/SessionResources.hpp
        Resource/StreamResources.hpp
        Resource/WorkerResources.hpp
)
LinkPrismTargets(PrismResource PrismFoundation PrismLifecycle)

add_library(PrismStatistics INTERFACE)
ConfigurePrismTarget(PrismStatistics)
target_sources(PrismStatistics INTERFACE
        Statistics/Counters.hpp
        Statistics/EventRing.hpp
        Statistics/History.hpp
        Statistics/Events.hpp
        Statistics/Snapshots.hpp
        Statistics/SparseCounters.hpp
        Statistics/Statistics.hpp
        Statistics/TrafficDelta.hpp
        Statistics/Types.hpp
)
LinkPrismTargets(PrismStatistics PrismFoundation)

add_library(PrismOperations INTERFACE)
ConfigurePrismTarget(PrismOperations)
target_include_directories(PrismOperations INTERFACE ${CMAKE_SOURCE_DIR})
target_sources(PrismOperations INTERFACE
        Operations/Controller.hpp
        Operations/HttpConnection.hpp
        Operations/HttpServer.hpp
        Operations/Models.hpp
        Operations/Operations.hpp
        Operations/Redaction.hpp
        Operations/Router.hpp
        Operations/OperationPublicationReceipt.hpp
        Operations/QueryNormalization.hpp
        Operations/ResponseDeliveryReceipt.hpp
        Operations/Http/Limits.hpp
        Operations/Http/JsonWriter.hpp
        Operations/Routes/HttpJson.hpp
        Operations/Routes/BootstrapJson.hpp
        Operations/Routes/RequestParser.hpp
        Operations/Routes/RouteDispatch.hpp
        Operations/Routes/RouteTarget.hpp
)
AssertPrismDependency(PrismOperations PrismFoundation)
AssertPrismDependency(PrismOperations PrismStatistics)
target_link_libraries(PrismOperations INTERFACE PrismFoundation PrismStatistics OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(PrismOperations INTERFACE ws2_32 mswsock)
endif()

add_library(PrismIoContracts INTERFACE)
ConfigurePrismTarget(PrismIoContracts)
target_sources(PrismIoContracts INTERFACE
        Contract/Io/CarrierActivity.hpp
        Contract/Io/CarrierCloseReceipt.hpp
        Contract/Io/IoResult.hpp
        Contract/Io/PacketTransferResult.hpp
)
LinkPrismTargets(PrismIoContracts PrismFoundation)

add_library(PrismTransport INTERFACE)
ConfigurePrismTarget(PrismTransport)
target_sources(PrismTransport INTERFACE
        Transport/Transmission.hpp
        Transport/Detail/ActivityGroup.hpp
        Transport/Detail/ForwardActivity.hpp
        Transport/Detail/IoCompletion.hpp
        Transport/Detail/PadDriver.hpp
        Transport/Detail/TlsOperations.hpp
        Transport/Detail/TlsStream.hpp
        Transport/Detail/TlsWriteDriver.hpp
        Transport/PadPolicy.hpp
        Transport/WriteDriver.hpp
        Transport/Writer.hpp
        Transport/Detail/IoActivity.hpp
        Transport/Detail/TransmissionControl.hpp
        Transport/Detail/TrackedCompletion.hpp
        Transport/Replay.hpp
        Transport/Algorithm.hpp
        Transport/Connector.hpp
        Transport/Encrypted.hpp
        Transport/NativeTls.hpp
        Transport/MemoryStream.hpp
        Transport/Pad.hpp
        Transport/Preview.hpp
        Transport/Reliable.hpp
        Transport/Stream.hpp
        Transport/UnreliableEndpoint.hpp
        Transport/Unreliable.hpp
)
LinkPrismTargets(PrismTransport PrismFoundation PrismLifecycle PrismIoContracts)
if(WIN32)
    target_link_libraries(PrismTransport INTERFACE ws2_32 mswsock crypt32)
endif()

add_library(PrismIngressModel INTERFACE)
ConfigurePrismTarget(PrismIngressModel)
target_sources(PrismIngressModel INTERFACE
        Contract/Ingress/Protocol.hpp
        Contract/Ingress/ProtocolConfiguration.hpp
        Contract/Ingress/RequestMetadata.hpp
        Contract/Ingress/ProviderFailure.hpp)
LinkPrismTargets(PrismIngressModel PrismFoundation PrismLifecycle)

add_library(PrismNetworkModel INTERFACE)
ConfigurePrismTarget(PrismNetworkModel)
target_sources(PrismNetworkModel INTERFACE
        Net/Target.hpp
        Net/DomainName.hpp
        Net/Host.hpp
        Net/HostText.hpp
)
LinkPrismTargets(PrismNetworkModel PrismFoundation)

add_library(PrismStreamContract INTERFACE)
ConfigurePrismTarget(PrismStreamContract)
target_sources(PrismStreamContract INTERFACE
        Contract/Services/Stream.hpp
)
LinkPrismTargets(PrismStreamContract PrismNetworkModel PrismFoundation PrismAccount PrismTransport PrismIngressModel)

add_library(PrismDatagramContract INTERFACE)
ConfigurePrismTarget(PrismDatagramContract)
target_sources(PrismDatagramContract INTERFACE
        Contract/Ingress/RawDatagramIngress.hpp
        Contract/Services/Datagram.hpp
        Contract/Services/DatagramEgress.hpp)
LinkPrismTargets(PrismDatagramContract PrismFoundation)

add_library(PrismNet INTERFACE)
ConfigurePrismTarget(PrismNet)
target_sources(PrismNet INTERFACE
        Net/Datagram/Egress.hpp
        Net/Services/WorkerDialService.hpp
        Net/Services/StreamEgress.hpp
        Net/Services/StreamRelay.hpp
        Net/Relay/State.hpp
        Net/Relay/Pump.hpp
        Net/Relay/Relay.hpp
        Net/Dialer/Dialer.hpp
        Net/Tcp/SocketExecutorTransfer.hpp
        Net/Dns/Config.hpp
        Net/Dns/Format.hpp
        Net/Dns/Types.hpp
        Net/Dns/Answer.hpp
        Net/Dns/AddressList.hpp
        Net/Dns/AnswerSet.hpp
        Net/Dns/QueryType.hpp
        Net/Dns/QueryIdentity.hpp
        Net/Dns/QueryIds.hpp
        Net/Dns/Detail/Name.hpp
        Net/Dns/Detail/Wire.hpp
        Net/Dns/Detail/Record.hpp
        Net/Dns/Detail/Scan.hpp
        Net/Dns/Detail/CheckedAnswer.hpp
        Net/Dns/Detail/AliasIndex.hpp
        Net/Dns/Detail/Deadline.hpp
        Net/Dns/Transport.hpp
        Net/Dns/Detail/UdpTransport.hpp
        Net/Dns/Detail/TcpTransport.hpp
        Net/Dns/Detail/TlsTransport.hpp
        Net/Dns/ConnPool.hpp
        Net/Dns/Doh.hpp
        Net/Dns/Cache.hpp
        Net/Dns/Coalescer.hpp
        Net/Dns/Rules.hpp
        Net/Dns/Upstream.hpp
        Net/Dns/Resolver.hpp
        Net/Dns/Detail/ResolverFailure.hpp
        Net/Dns/Detail/ResolverSharedState.hpp
        Net/Dns/Detail/ResolverState.hpp
        Net/Dns/Detail/UpstreamState.hpp
        Net/Dns/Detail/EndpointResolver.hpp
        Net/Dns/Detail/QueryExecutor.hpp
        Net/Dns/Detail/ConfigOptions.hpp
        Net/Dns/Detail/Exchange.hpp
        Net/Dns/Detail/Maintenance.hpp
        Net/Dns/Detail/Fallback.hpp
        Net/Dns/Detail/FamilyMerge.hpp
        Net/UdpRelay.hpp
        Net/Udp/EndpointRetirement.hpp
)
LinkPrismTargets(PrismNet PrismTransport PrismFoundation PrismDatagramContract PrismNetworkModel PrismStreamContract)
# DNS 的 DoT/DoH owner 实际使用 TLS，依赖由 Net target 直接表达。
target_link_libraries(PrismNet INTERFACE OpenSSL::SSL)

add_library(PrismIngressContract INTERFACE)
ConfigurePrismTarget(PrismIngressContract)
target_sources(PrismIngressContract INTERFACE
        Contract/Ingress/DataPlane.hpp
        Contract/Ingress/DatagramSession.hpp
        Contract/Ingress/StreamFactory.hpp
        Contract/Ingress/MuxSession.hpp
        Contract/Ingress/StreamCatalog.hpp
        Contract/Ingress/InboundAdmission.hpp
        Contract/Ingress/QuicConnection.hpp
        Contract/Services/Authentication.hpp
        Contract/Services/Quic.hpp
)
LinkPrismTargets(PrismIngressContract PrismFoundation PrismAccount PrismLifecycle PrismTransport PrismNet PrismIngressModel PrismDatagramContract PrismStreamContract)

add_library(PrismBoundary INTERFACE)
ConfigurePrismTarget(PrismBoundary)
target_sources(PrismBoundary INTERFACE
        Boundary/Datagram/DatagramAssociation.hpp
        Boundary/Datagram/DatagramClassifier.hpp
        Boundary/Datagram/DatagramListener.hpp
        Boundary/Datagram/DatagramSender.hpp
        Boundary/Quic/QuicPacketGateway.hpp
        Boundary/Contract/BoundaryDispatcher.hpp
        Boundary/Quic/QuicConnectionRegistry.hpp
)
LinkPrismTargets(PrismBoundary
        PrismFoundation
        PrismNet
        PrismProtocolQuic
        PrismProtocolQuicNative)

add_library(PrismRuntime INTERFACE)
ConfigurePrismTarget(PrismRuntime)
target_include_directories(PrismRuntime INTERFACE ${CMAKE_SOURCE_DIR})
target_sources(PrismRuntime INTERFACE
        # Runtime middleware
        Runtime/Middleware/Context.hpp
        Runtime/Middleware/Pipeline.hpp
        Runtime/Middleware/Builtin/Dial.hpp
        Runtime/Middleware/Builtin/Pad.hpp
        Runtime/Middleware/Builtin/Relay.hpp
        Runtime/Middleware/Builtin/Throttle.hpp
        # Runtime recognition
        Runtime/Recognition/Protocol.hpp
        Runtime/Recognition/Probe.hpp
        Runtime/Recognition/Types.hpp
        Runtime/Recognition/ProbeBuffer.hpp
        Runtime/Recognition/DecisionTable.hpp
        Runtime/Recognition/Candidate.hpp
        Runtime/Recognition/CandidateHandle.hpp
        Runtime/Recognition/ProfileModel.hpp
        Runtime/Recognition/ProfileTypes.hpp
        Runtime/Recognition/ProfileValidation.hpp
        Runtime/Recognition/ProfileDecision.hpp
        Runtime/Recognition/ProfileRoutes.hpp
        Runtime/Recognition/Profile.hpp
        Runtime/Recognition/RecognitionConfig.hpp
        Runtime/Recognition/CandidateSelection.hpp
        Runtime/Recognition/ConfiguredAcceptor.hpp
        Runtime/Recognition/ConfiguredMode.hpp
        Runtime/Recognition/DeterministicMode.hpp
        Runtime/Recognition/MixedTrialPlan.hpp
        Runtime/Recognition/MixedTrialAttempt.hpp
        Runtime/Recognition/MixedTrialDecision.hpp
        Runtime/Recognition/MixedTrialCleanup.hpp
        Runtime/Recognition/MixedTrialModel.hpp
        Runtime/Recognition/MixedTrialMode.hpp
        Runtime/Recognition/Recognition.hpp
        Runtime/Recognition/Tls.hpp
        Runtime/Recognition/TlsRecordReader.hpp
        Runtime/Recognition/RawIngressProbe.hpp
        # Runtime session/front/resource and stable protocol contract
        Runtime/SessionControl.hpp
        Runtime/SessionServices.hpp
        Runtime/ActiveTransports.hpp
        Runtime/CarrierDomain.hpp
        Runtime/Session.hpp
        Runtime/ListenerAdmissionOwner.hpp
        Runtime/Session/LogState.hpp
        Runtime/Session/Logging.hpp
        Runtime/Session/RecognitionLogging.hpp
        Runtime/Session/ClosePolicy.hpp
        Runtime/Session/CarrierInstallation.hpp
        Runtime/Session/Delivery.hpp
        Runtime/Session/RunContext.hpp
        Runtime/Session/RecognitionAdmission.hpp
        Runtime/Session/RecognitionLatencyScope.hpp
        Runtime/Session/Detail/NegotiatedTlsRoute.hpp
        Runtime/Session/DataPlaneRelay.hpp
        Runtime/Listener.hpp
        Runtime/ListenerConnectionGate.hpp
        Runtime/ListenerConnectionDrain.hpp
        Runtime/AffinityBalancer.hpp
        Runtime/ListenerCompletion.hpp
        Runtime/SessionRegistryModel.hpp
        Runtime/SessionRegistry.hpp
        Runtime/SessionRegistryStorage.hpp
        Runtime/SessionRegistryRetirement.hpp
        Runtime/Statistics.hpp
        Runtime/Statistics/RecognitionLatency.hpp
        Runtime/Process.hpp
        Runtime/Worker.hpp
        Runtime/WorkerGroup.hpp
)
AssertPrismDependency(PrismRuntime PrismFoundation)
target_link_libraries(PrismRuntime INTERFACE PrismFoundation)
LinkPrismTargets(PrismRuntime
        PrismIngressContract
        PrismStatistics
        PrismNet
        PrismTransport
        PrismFoundation
        PrismLifecycle
        PrismAccount
        PrismResource
)

add_library(PrismComposition INTERFACE
)
ConfigurePrismTarget(PrismComposition)
target_sources(PrismComposition INTERFACE
        # Composition adapters; protocol binding remains outside Runtime
        Composition/Recognition/CandidateModel.hpp
        Composition/Recognition/CandidateFactoryHelpers.hpp
        Composition/Recognition/CandidateRegistry.hpp
        Composition/Recognition/CandidateFactory.hpp
        Composition/Recognition/AnytlsCarrier.hpp
        Composition/Recognition/ProfileBuilder.hpp
        Composition/Recognition/TlsCandidateFactory.hpp
        Composition/Recognition/TlsCandidateModel.hpp
        Composition/Recognition/TlsCarrierHelpers.hpp
        Composition/Recognition/TlsRecognitionHelpers.hpp
        Composition/Recognition/ShadowtlsCarrier.hpp
        Composition/Recognition/RestlsCarrier.hpp
        Composition/Recognition/TrusttunnelCandidate.hpp
        Composition/Recognition/LayeredCandidateFactory.hpp
        Composition/Recognition/ProtocolMatrix.hpp
        Composition/Builtin/Builtin.hpp
        Composition/Builtin/Capability.hpp
        Composition/Builtin/Descriptor.hpp
        Composition/Builtin/Freeze.hpp
        Composition/Builtin/ProtocolBuiltins.hpp
        Composition/Builtin/Registry.hpp
        Composition/Builtin/Snapshot.hpp
        Composition/Protocol/ProtocolCatalog.hpp
        Composition/Provider/ProviderCatalog.hpp
        Composition/Provider/ConfigurationCompiler.hpp
)
LinkPrismTargets(PrismComposition
        PrismRuntime
        PrismProtocolMux
        PrismProtocolXhttp
        PrismProtocolGun
        PrismProtocolTuic
        PrismProtocolReality
        PrismProtocolHttp3
)
# C05 过渡：Composition 暂时消费 Operations/Statistics（tests/Prism/Performance 依赖其传递包含）。
# 走 LinkPrismTargets 而非裸 target_link_libraries，令 AssertPrismDependency 与
# _GetPrismAllowedInternalLinks 同时生效；过渡结束后应删掉本边与两处例外，而不是继续绕过。
LinkPrismTargets(PrismComposition PrismOperations PrismStatistics)

add_library(PrismConfiguration INTERFACE
)
ConfigurePrismTarget(PrismConfiguration)
target_sources(PrismConfiguration INTERFACE
        Application/Configuration/Configuration.hpp
        Application/Configuration/ConfigurationError.hpp
        Application/Configuration/ConfigurationGeneration.hpp
        Application/Configuration/ConfigurationParser.hpp
        Application/Configuration/ConfigurationStore.hpp
        Application/Configuration/ConfigurationValidator.hpp
        Application/Configuration/GenerationBuilder.hpp
        Application/Configuration/PreparedConfiguration.hpp
        Application/Configuration/PrismConfiguration.hpp
        Application/Configuration/PrismConfigurationSchema.hpp
        Application/Configuration/PrismConfiguration.json
        Application/Configuration/PrismConfigurationJson.hpp
        Application/Configuration/PublicSettingsValidator.hpp
        Application/Configuration/ReferenceGraph.hpp
        Application/Configuration/ReloadCoordinator.hpp
        Application/Configuration/ResolvedSecrets.hpp
        Application/Configuration/SecretRefResolver.hpp
        Application/Configuration/Validation/ValidationTypes.hpp
        Application/Configuration/Validation/CommonValidation.hpp
        Application/Configuration/Validation/SchemaValidation.hpp
        Application/Configuration/Validation/ProtocolIndependentValidation.hpp
        Application/Configuration/Validation/ReferenceValidation.hpp
        Application/Configuration/Validation/CapabilityValidation.hpp
        Application/Configuration/Validation/SecretValidation.hpp
        Application/Configuration/Validation/CarrierValidation.hpp
        Application/Configuration/Validation/ConfigurationValidation.hpp
)
AssertPrismDependency(PrismConfiguration PrismFoundation)
AssertPrismDependency(PrismConfiguration PrismAccount)
target_link_libraries(PrismConfiguration
        INTERFACE
        PrismFoundation
        PrismAccount
        glaze::glaze
)

add_library(PrismProtocolsCommon INTERFACE)
ConfigurePrismTarget(PrismProtocolsCommon)
target_sources(PrismProtocolsCommon INTERFACE
        Protocols/Common/DatagramRelay.hpp
        Protocols/Common/DatagramRelayPump.hpp
        Protocols/Common/DatagramRetirement.hpp
        Protocols/Common/DatagramFailure.hpp
        Protocols/Common/DatagramDeadline.hpp
        Protocols/Common/DatagramBinding.hpp
        Protocols/Common/BindingLifetime.hpp
        Protocols/Common/Authentication/ScopedMaterial.hpp
        Protocols/Common/QuicPreparation.hpp
        Protocols/Common/QuicBindingState.hpp
        Protocols/Common/DatagramObservation.hpp
        Protocols/Common/Address.hpp
        Protocols/Common/Form.hpp
        Protocols/Common/Framing.hpp
        Protocols/Common/Mux.hpp
        Protocols/Common/Read.hpp
        Protocols/Common/IoBridge.hpp
        Protocols/Common/ProtocolActivity.hpp
)

add_library(PrismProtocolHttp2 INTERFACE)
ConfigurePrismTarget(PrismProtocolHttp2)
target_sources(PrismProtocolHttp2 INTERFACE
        Protocols/Http2/Session.hpp
        Protocols/Http2/Types.hpp
        Protocols/Http2/Detail/Codec.hpp
        Protocols/Http2/Detail/Frame.hpp
        Protocols/Http2/Detail/SessionState.hpp
        Protocols/Http2/Stream.hpp
        Protocols/Http2/Detail/ConnectionState.hpp
        Protocols/Http2/Detail/CodecState.hpp
        Protocols/Http2/Detail/StreamController.hpp
        Protocols/Http2/Detail/FrameProcessor.hpp
)

# HTTP/2 and Hysteria2 reuse the QPACK/Huffman primitives through this
# standalone compiled core; neither target consumes the full HTTP/3 stack.
add_library(PrismProtocolHttp3Core INTERFACE)
ConfigurePrismTarget(PrismProtocolHttp3Core)
target_include_directories(PrismProtocolHttp3Core INTERFACE ${CMAKE_SOURCE_DIR})
target_sources(PrismProtocolHttp3Core INTERFACE
        Protocols/Http3/Auth.hpp
        Protocols/Http3/HeaderLimits.hpp
        Protocols/Http3/Detail/Varint.hpp
        Protocols/Http3/Huffman.hpp
        Protocols/Http3/StaticTable.hpp
        Protocols/Http3/DynamicTable.hpp
        Protocols/Http3/Decoder.hpp
        Protocols/Http3/Encoder.hpp
        Protocols/Http3/Qpack.hpp
)
AssertPrismDependency(PrismProtocolHttp3Core PrismProtocolsCommon)
target_link_libraries(PrismProtocolHttp3Core INTERFACE PrismProtocolsCommon)
LinkPrismTargets(PrismProtocolHttp3Core PrismProtocolsCommon)

add_library(PrismProtocolQuic INTERFACE)
ConfigurePrismTarget(PrismProtocolQuic)
target_sources(PrismProtocolQuic INTERFACE
        Protocols/Quic/DatagramAdapter.hpp
        Protocols/Quic/Native.hpp
        Protocols/Quic/Detail/NativeConnection.hpp
        Protocols/Quic/Detail/NativeConnectionProviders.hpp
        Protocols/Quic/Detail/NativeConnectionLifecycle.hpp
        Protocols/Quic/Detail/NativeConnectionStreams.hpp
        Protocols/Quic/Detail/NativeConnectionStreamAdmission.hpp
        Protocols/Quic/Detail/NativeConnectionDatagrams.hpp
        Protocols/Quic/Detail/NativeConnectionTransport.hpp
        Protocols/Quic/Detail/NativeConnectionCallbacks.hpp
        Protocols/Quic/Detail/NativeFacades.hpp
        Protocols/Quic/Detail/NativeConnectionState.hpp
        Protocols/Quic/Detail/NativeStreamActivity.hpp
        Protocols/Quic/Detail/StreamAdapterActivity.hpp
        Protocols/Quic/StreamAdapter.hpp
)

add_library(PrismProtocolQuicNative INTERFACE)
ConfigurePrismTarget(PrismProtocolQuicNative)
target_sources(PrismProtocolQuicNative
        INTERFACE
        Protocols/Quic/Detail/DatagramInbox.hpp
        Protocols/Quic/ConnectionLifecycle.hpp
)
target_include_directories(PrismProtocolQuicNative INTERFACE
        ${ngtcp2_SOURCE_DIR}/lib/includes
        ${ngtcp2_SOURCE_DIR}/crypto/includes
)
target_link_libraries(PrismProtocolQuicNative INTERFACE
        PrismProtocolQuic
        OpenSSL::SSL
        OpenSSL::Crypto
        ngtcp2_static
        ngtcp2_crypto_boringssl_static
)
LinkPrismTargets(PrismProtocolQuicNative PrismProtocolQuic)
LinkPrismTargets(PrismProtocolQuicNative PrismIngressContract PrismProtocolsCommon PrismLifecycle PrismFoundation)

add_library(PrismProtocolHttp INTERFACE
)
ConfigurePrismTarget(PrismProtocolHttp)
AssertPrismDependency(PrismProtocolHttp PrismProtocolsCommon)
target_link_libraries(PrismProtocolHttp INTERFACE PrismProtocolsCommon)
target_sources(PrismProtocolHttp INTERFACE
          Protocols/Http1/Parser.hpp
          Protocols/Http1/ForwardRequest.hpp
          Protocols/Http1/ForwardRequestFraming.hpp
          Protocols/Http1/ForwardRequestUpgrade.hpp
          Protocols/Http1/ForwardRequestTransport.hpp
          Protocols/Http1/ForwardRequestState.hpp
          Protocols/Http1/ForwardRequestSource.hpp
          Protocols/Http1/ForwardResponseTransport.hpp
        Protocols/Http1/Conn.hpp
        Protocols/Http1/IngressFactory.hpp
)

add_library(PrismProtocolHttp3 INTERFACE)
ConfigurePrismTarget(PrismProtocolHttp3)
target_include_directories(PrismProtocolHttp3 INTERFACE ${CMAKE_SOURCE_DIR})
target_sources(PrismProtocolHttp3 INTERFACE
        Protocols/Http3/Server.hpp
        Protocols/Http3/ServerFactory.hpp
        Protocols/Http3/Session.hpp
        Protocols/Http3/Detail/SessionContract.hpp
        Protocols/Http3/Detail/SessionLifecycle.hpp
        Protocols/Http3/Detail/SessionInput.hpp
        Protocols/Http3/Detail/SessionOutput.hpp
        Protocols/Http3/Detail/SessionCallbacks.hpp
        Protocols/Http3/NativeServer.hpp
        Protocols/Http3/NativeClient.hpp
        Protocols/Http3/Detail/BoundedEventQueue.hpp
        Protocols/Http3/Detail/NativeClient.hpp
        Protocols/Http3/Detail/NativeClientCallbackApi.hpp
        Protocols/Http3/Detail/NativeClientCallbacks.hpp
        Protocols/Http3/Detail/NativeClientLifecycle.hpp
        Protocols/Http3/Detail/NativeClientRequests.hpp
        Protocols/Http3/Detail/NativeServer.hpp
        Protocols/Http3/Detail/NativeServerLifecycle.hpp
        Protocols/Http3/Detail/NativeServerRun.hpp
        Protocols/Http3/Detail/NativeServerOutputDriver.hpp
        Protocols/Http3/Detail/TrackedSessionTasks.hpp
)
LinkPrismTargets(PrismProtocolHttp3 PrismProtocolHttp3Core)
LinkPrismTargets(PrismProtocolHttp3 PrismProtocolQuic)
LinkPrismTargets(PrismProtocolHttp3 PrismProtocolQuicNative)
target_include_directories(PrismProtocolHttp3 INTERFACE
        ${nghttp3_SOURCE_DIR}/lib/includes
        ${ngtcp2_SOURCE_DIR}/lib/includes
        ${ngtcp2_SOURCE_DIR}/crypto/includes
)
target_link_libraries(PrismProtocolHttp3 INTERFACE
        PrismProtocolQuicNative
        OpenSSL::SSL
        OpenSSL::Crypto
        ngtcp2_static
        ngtcp2_crypto_boringssl_static
        nghttp3_static
)

add_library(PrismProtocolHysteria2 INTERFACE)
ConfigurePrismTarget(PrismProtocolHysteria2)
target_include_directories(PrismProtocolHysteria2 INTERFACE ${CMAKE_SOURCE_DIR})
target_sources(PrismProtocolHysteria2 INTERFACE
        Protocols/Hysteria2/Types.hpp
        Protocols/Hysteria2/Detail/Target.hpp
        Protocols/Hysteria2/Detail/DatagramFragments.hpp
        Protocols/Hysteria2/Codec.hpp
        Protocols/Hysteria2/Conn.hpp
        Protocols/Hysteria2/Io.hpp
        Protocols/Hysteria2/Dgram.hpp
        Protocols/Hysteria2/Http3Auth.hpp
        Protocols/Hysteria2/Admission.hpp
        Protocols/Hysteria2/AdmissionLifecycle.hpp
        Protocols/Hysteria2/AdmissionRuntime.hpp
        Protocols/Hysteria2/StreamSession.hpp
        Protocols/Hysteria2/DatagramSession.hpp
        Protocols/Hysteria2/Hysteria2.hpp
        Protocols/Hysteria2/Prepared.hpp
        Protocols/Hysteria2/Binding.hpp
        Protocols/Hysteria2/NativeSession.hpp
        Protocols/Hysteria2/ServiceBinding.hpp
)
AssertPrismDependency(PrismProtocolHysteria2 PrismFoundation)
AssertPrismDependency(PrismProtocolHysteria2 PrismAccount)
AssertPrismDependency(PrismProtocolHysteria2 PrismTransport)
AssertPrismDependency(PrismProtocolHysteria2 PrismProtocolsCommon)
AssertPrismDependency(PrismProtocolHysteria2 PrismProtocolHttp3Core)
AssertPrismDependency(PrismProtocolHysteria2 PrismProtocolQuic)
target_link_libraries(PrismProtocolHysteria2 INTERFACE
        PrismFoundation
        PrismAccount
        PrismTransport
        PrismProtocolsCommon
        PrismProtocolHttp3Core
        PrismProtocolQuic
)

add_library(PrismProtocolShadowsocks2022 INTERFACE)
ConfigurePrismTarget(PrismProtocolShadowsocks2022)
target_sources(PrismProtocolShadowsocks2022 INTERFACE
        Protocols/Shadowsocks2022/Types.hpp
        Protocols/Shadowsocks2022/Detail/Target.hpp
        Protocols/Shadowsocks2022/Prepared.hpp
        Protocols/Shadowsocks2022/TcpAdmission.hpp
        Protocols/Shadowsocks2022/Binding.hpp
        Protocols/Shadowsocks2022/ChunkCodec.hpp
        Protocols/Shadowsocks2022/KeyDerivation.hpp
        Protocols/Shadowsocks2022/RequestCodec.hpp
        Protocols/Shadowsocks2022/ResponseCodec.hpp
        Protocols/Shadowsocks2022/Codec.hpp
        Protocols/Shadowsocks2022/Conn.hpp
        Protocols/Shadowsocks2022/ConnSession.hpp
        Protocols/Shadowsocks2022/ConnRecord.hpp
        Protocols/Shadowsocks2022/ConnHandshake.hpp
        Protocols/Shadowsocks2022/ConnDatagram.hpp
        Protocols/Shadowsocks2022/Dgram.hpp
        Protocols/Shadowsocks2022/RequestState.hpp
        Protocols/Shadowsocks2022/RequestWire.hpp
        Protocols/Shadowsocks2022/Ss2022Gateway.hpp
        Protocols/Shadowsocks2022/GatewayState.hpp
        Protocols/Shadowsocks2022/Shadowsocks2022.hpp
)

add_library(PrismProtocolSocks5 INTERFACE)
ConfigurePrismTarget(PrismProtocolSocks5)
target_include_directories(PrismProtocolSocks5 INTERFACE ${CMAKE_SOURCE_DIR})
AssertPrismDependency(PrismProtocolSocks5 PrismProtocolsCommon)
target_link_libraries(PrismProtocolSocks5 INTERFACE PrismProtocolsCommon)
target_sources(PrismProtocolSocks5 INTERFACE
        Protocols/Socks5/Types.hpp
        Protocols/Socks5/Detail/Target.hpp
        Protocols/Socks5/Prepared.hpp
        Protocols/Socks5/Binding.hpp
        Protocols/Socks5/AddressCodec.hpp
        Protocols/Socks5/AuthCodec.hpp
        Protocols/Socks5/MessageCodec.hpp
        Protocols/Socks5/BeastCodec.hpp
        Protocols/Socks5/TransportCodec.hpp
        Protocols/Socks5/Codec.hpp
        Protocols/Socks5/ConnTransport.hpp
        Protocols/Socks5/ConnAuth.hpp
        Protocols/Socks5/ConnHandshake.hpp
        Protocols/Socks5/Conn.hpp
        Protocols/Socks5/Dgram.hpp
        Protocols/Socks5/UdpAssoc.hpp
        Protocols/Socks5/AssociationFactory.hpp
        Protocols/Socks5/Socks5.hpp
        Protocols/Socks5/Reply.hpp
)
AssertPrismDependency(PrismComposition PrismRuntime)
AssertPrismDependency(PrismComposition PrismProtocolSocks5)
AssertPrismDependency(PrismComposition PrismAccount)
AssertPrismDependency(PrismComposition PrismFoundation)
AssertPrismDependency(PrismComposition PrismNet)
AssertPrismDependency(PrismComposition PrismProtocolQuic)
AssertPrismDependency(PrismComposition PrismProtocolQuicNative)
AssertPrismDependency(PrismComposition PrismProtocolHysteria2)
AssertPrismDependency(PrismComposition PrismProtocolTuic)
target_link_libraries(PrismComposition INTERFACE
        PrismRuntime
        PrismProtocolSocks5
)

add_library(PrismProtocolTrojan INTERFACE)
ConfigurePrismTarget(PrismProtocolTrojan)
target_sources(PrismProtocolTrojan INTERFACE
        Protocols/Trojan/IngressFactory.hpp
        Protocols/Trojan/Types.hpp
        Protocols/Trojan/Detail/Target.hpp
        Protocols/Trojan/Codec.hpp
        Protocols/Trojan/CredentialCodec.hpp
        Protocols/Trojan/AddressCodec.hpp
        Protocols/Trojan/UdpCodec.hpp
        Protocols/Trojan/RequestCodec.hpp
        Protocols/Trojan/BeastCodec.hpp
        Protocols/Trojan/Conn.hpp
        Protocols/Trojan/Dgram.hpp
        Protocols/Trojan/DatagramSession.hpp
        Protocols/Trojan/Trojan.hpp
)

add_library(PrismProtocolTuic INTERFACE)
ConfigurePrismTarget(PrismProtocolTuic)
target_include_directories(PrismProtocolTuic INTERFACE ${CMAKE_SOURCE_DIR})
target_sources(PrismProtocolTuic INTERFACE
        Protocols/Tuic/Types.hpp
        Protocols/Tuic/Detail/Target.hpp
        Protocols/Tuic/Detail/DatagramPackets.hpp
        Protocols/Tuic/Codec.hpp
        Protocols/Tuic/Conn.hpp
        Protocols/Tuic/ConnSession.hpp
        Protocols/Tuic/ConnIo.hpp
        Protocols/Tuic/ConnAuth.hpp
        Protocols/Tuic/ConnStream.hpp
        Protocols/Tuic/ConnDatagram.hpp
        Protocols/Tuic/Dgram.hpp
        Protocols/Tuic/Tuic.hpp
        Protocols/Tuic/Admission.hpp
        Protocols/Tuic/AdmissionInput.hpp
        Protocols/Tuic/AdmissionRetirement.hpp
        Protocols/Tuic/AdmissionRuntime.hpp
        Protocols/Tuic/Prepared.hpp
        Protocols/Tuic/Binding.hpp
        Protocols/Tuic/NativeSession.hpp
        Protocols/Tuic/ServiceBinding.hpp
)
AssertPrismDependency(PrismProtocolTuic PrismAccount)
AssertPrismDependency(PrismProtocolTuic PrismFoundation)
AssertPrismDependency(PrismProtocolTuic PrismTransport)
AssertPrismDependency(PrismProtocolTuic PrismProtocolQuic)
target_link_libraries(PrismProtocolTuic INTERFACE
        PrismAccount
        PrismFoundation
        PrismTransport
        PrismProtocolQuic
)

add_library(PrismProtocolVless INTERFACE)
ConfigurePrismTarget(PrismProtocolVless)
target_sources(PrismProtocolVless INTERFACE
        Protocols/Vless/IngressFactory.hpp
        Protocols/Vless/Xudp/Codec.hpp
        Protocols/Vless/Xudp/Writer.hpp
        Protocols/Vless/Xudp/State.hpp
        Protocols/Vless/Xudp/Association.hpp
        Protocols/Vless/Xudp/RootSession.hpp
        Protocols/Vless/Types.hpp
        Protocols/Vless/Detail/Target.hpp
        Protocols/Vless/Codec.hpp
        Protocols/Vless/AddressCodec.hpp
        Protocols/Vless/RequestCodec.hpp
        Protocols/Vless/UdpCodec.hpp
        Protocols/Vless/BeastCodec.hpp
        Protocols/Vless/Conn.hpp
        Protocols/Vless/Dgram.hpp
        Protocols/Vless/UdpTunnel.hpp
        Protocols/Vless/AssociationFactory.hpp
        Protocols/Vless/Vless.hpp
)

add_library(PrismProtocolVmess INTERFACE)
ConfigurePrismTarget(PrismProtocolVmess)
target_sources(PrismProtocolVmess INTERFACE
        Protocols/Vmess/IngressFactory.hpp
        Protocols/Vmess/Credentials.hpp
        Protocols/Vmess/Types.hpp
        Protocols/Vmess/Detail/Target.hpp
        Protocols/Vmess/Auth.hpp
        Protocols/Vmess/AuthCrypto.hpp
        Protocols/Vmess/AuthHeader.hpp
        Protocols/Vmess/AuthId.hpp
        Protocols/Vmess/AuthKdf.hpp
        Protocols/Vmess/ChunkMask.hpp
        Protocols/Vmess/ChunkCodec.hpp
        Protocols/Vmess/RequestCodec.hpp
        Protocols/Vmess/ResponseCodec.hpp
        Protocols/Vmess/Codec.hpp
        Protocols/Vmess/ConnSession.hpp
        Protocols/Vmess/ConnIo.hpp
        Protocols/Vmess/ConnChunk.hpp
        Protocols/Vmess/ConnHandshake.hpp
        Protocols/Vmess/Conn.hpp
        Protocols/Vmess/Dgram.hpp
        Protocols/Vmess/DatagramSession.hpp
        Protocols/Vmess/Vmess.hpp
)

add_library(PrismProtocolMux INTERFACE)
ConfigurePrismTarget(PrismProtocolMux)
target_sources(PrismProtocolMux INTERFACE
        Protocols/Mux/Detail/Root/RootState.hpp
        Protocols/Mux/Detail/Root/RootChild.hpp
        Protocols/Mux/Detail/Root/RootSession.hpp
        Protocols/Mux/RootBinding.hpp
        Protocols/Mux/RootOptions.hpp
        Protocols/Mux/Detail/Root/RootRegistry.hpp
        Protocols/Mux/Detail/SingMux/Codec.hpp
        Protocols/Mux/Detail/SingMux/Handshake.hpp
        Protocols/Mux/SingMux/Stream.hpp
        Protocols/Mux/H2Mux/Http2State.hpp
        Protocols/Mux/H2Mux/Http2Stream.hpp
        Protocols/Mux/H2Mux/Http2Dispatch.hpp
        Protocols/Mux/H2Mux/Http2Server.hpp
        Protocols/Mux/Types.hpp
        Protocols/Mux/Codec.hpp
        Protocols/Mux/Detail/Stream/StreamState.hpp
        Protocols/Mux/Detail/Session/SessionWriteLoop.hpp
        Protocols/Mux/Detail/Session/SessionContract.hpp
        Protocols/Mux/Detail/Session/SessionState.hpp
        Protocols/Mux/Detail/Session/SessionFlowControl.hpp
        Protocols/Mux/Detail/Session/SessionWriter.hpp
        Protocols/Mux/Detail/Session/SessionFrames.hpp
        Protocols/Mux/Detail/Session/SessionTeardown.hpp
        Protocols/Mux/Stream.hpp
        Protocols/Mux/Session.hpp
        Protocols/Mux/Client.hpp
        Protocols/Mux/Server.hpp
        Protocols/Mux/Smux/Detail/Wire/Types.hpp
        Protocols/Mux/Smux/Detail/Wire/Codec.hpp
        Protocols/Mux/Smux/Session.hpp
        Protocols/Mux/Smux/Client.hpp
        Protocols/Mux/Smux/Server.hpp
        Protocols/Mux/Smux/Smux.hpp
        Protocols/Mux/Yamux/Detail/Wire/Types.hpp
        Protocols/Mux/Yamux/Detail/Wire/Codec.hpp
        Protocols/Mux/Yamux/Session.hpp
        Protocols/Mux/Yamux/Client.hpp
        Protocols/Mux/Yamux/Server.hpp
        Protocols/Mux/Yamux/Yamux.hpp
        Protocols/Mux/H2Mux/Types.hpp
        Protocols/Mux/H2Mux/Codec.hpp
        Protocols/Mux/H2Mux/Session.hpp
        Protocols/Mux/H2Mux/Client.hpp
        Protocols/Mux/H2Mux/Server.hpp
        Protocols/Mux/H2Mux/H2Mux.hpp
)

add_library(PrismProtocolAnytls INTERFACE)
ConfigurePrismTarget(PrismProtocolAnytls)
target_sources(PrismProtocolAnytls INTERFACE
        Protocols/Anytls/Frame.hpp
        Protocols/Anytls/Detail/Session/Writer.hpp
        Protocols/Anytls/Detail/Session/Target.hpp
        Protocols/Anytls/Detail/Session/State.hpp
        Protocols/Anytls/Detail/Stream/Stream.hpp
        Protocols/Anytls/Detail/Session/Relay.hpp
        Protocols/Anytls/Detail/Session/Session.hpp
        Protocols/Anytls/IngressFactory.hpp
        Protocols/Anytls/Types.hpp
        Protocols/Anytls/Codec.hpp
        Protocols/Anytls/Conn.hpp
        Protocols/Anytls/Anytls.hpp
)

add_library(PrismProtocolEch INTERFACE)
ConfigurePrismTarget(PrismProtocolEch)
target_sources(PrismProtocolEch INTERFACE
        Protocols/Ech/ServerKeys.hpp
)

add_library(PrismProtocolGun INTERFACE)
ConfigurePrismTarget(PrismProtocolGun)
target_sources(PrismProtocolGun INTERFACE
        Protocols/Gun/Types.hpp
        Protocols/Gun/Codec.hpp
        Protocols/Gun/Conn.hpp
        Protocols/Gun/Grpc.hpp
        Protocols/Gun/GrpcTypes.hpp
        Protocols/Gun/GrpcMetadata.hpp
        Protocols/Gun/GrpcFraming.hpp
        Protocols/Gun/GrpcStream.hpp
        Protocols/Gun/Gun.hpp
)
LinkPrismTargets(PrismProtocolGun PrismProtocolHttp2)

add_library(PrismProtocolNative INTERFACE)
ConfigurePrismTarget(PrismProtocolNative)
target_sources(PrismProtocolNative INTERFACE
        Protocols/Native/Types.hpp
        Protocols/Native/Conn.hpp
        Protocols/Native/Native.hpp
)

add_library(PrismProtocolReality INTERFACE)
ConfigurePrismTarget(PrismProtocolReality)
target_sources(PrismProtocolReality INTERFACE
          Protocols/Reality/Types.hpp
          Protocols/Reality/Prepared.hpp
)

add_library(PrismProtocolRestls INTERFACE)
ConfigurePrismTarget(PrismProtocolRestls)
target_sources(PrismProtocolRestls INTERFACE
        Protocols/Restls/Types.hpp
        Protocols/Restls/Server.hpp
        Protocols/Restls/Restls.hpp
)

add_library(PrismProtocolShadowtls INTERFACE)
ConfigurePrismTarget(PrismProtocolShadowtls)
target_sources(PrismProtocolShadowtls INTERFACE
        Protocols/Shadowtls/Types.hpp
        Protocols/Shadowtls/Shadowtls.hpp
        Protocols/Shadowtls/Server.hpp
)

add_library(PrismProtocolTrusttunnel INTERFACE)
ConfigurePrismTarget(PrismProtocolTrusttunnel)
target_sources(PrismProtocolTrusttunnel INTERFACE
        Protocols/Trusttunnel/Types.hpp
        Protocols/Trusttunnel/Codec.hpp
        Protocols/Trusttunnel/Conn.hpp
        Protocols/Trusttunnel/Http2.hpp
        Protocols/Trusttunnel/Http2Server.hpp
        Protocols/Trusttunnel/Http2Client.hpp
        Protocols/Trusttunnel/IngressFactory.hpp
        Protocols/Trusttunnel/Dgram.hpp
        Protocols/Trusttunnel/Trusttunnel.hpp
)

add_library(PrismProtocolWs INTERFACE)
ConfigurePrismTarget(PrismProtocolWs)
target_sources(PrismProtocolWs INTERFACE
        Protocols/Ws/Ws.hpp
)

add_library(PrismProtocolXhttp INTERFACE)
ConfigurePrismTarget(PrismProtocolXhttp)
target_sources(PrismProtocolXhttp INTERFACE
        Protocols/Xhttp/Types.hpp
        Protocols/Xhttp/Conn.hpp
        Protocols/Xhttp/Entry.hpp
        Protocols/Xhttp/Xhttp.hpp
)

# Protocol dependencies are declared beside the Prism targets they compose.
LinkPrismTargets(PrismProtocolsCommon PrismTransport PrismFoundation PrismIngressContract PrismLifecycle)

foreach(ProtocolTarget IN ITEMS
        PrismProtocolHttp
        PrismProtocolHttp3
        PrismProtocolHttp2
        PrismProtocolQuic
        PrismProtocolHysteria2
        PrismProtocolShadowsocks2022
        PrismProtocolTrojan
        PrismProtocolTuic
        PrismProtocolVless
        PrismProtocolVmess
        PrismProtocolMux
        PrismProtocolAnytls
        PrismProtocolEch
        PrismProtocolGun
        PrismProtocolNative
        PrismProtocolReality
        PrismProtocolRestls
        PrismProtocolShadowtls
        PrismProtocolTrusttunnel
        PrismProtocolWs
        PrismProtocolXhttp)
    LinkPrismTargets(${ProtocolTarget} PrismProtocolsCommon)
endforeach()

add_library(PrismDiagnoseBackend INTERFACE)
ConfigurePrismTarget(PrismDiagnoseBackend)
target_sources(PrismDiagnoseBackend INTERFACE
        Foundation/Utility/Diagnose/Detail/BackendBridge.hpp
        Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp
        Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp
        Foundation/Utility/Diagnose/Detail/SinkSet.hpp
        Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp
        Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp
        Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp
)
LinkPrismTargets(PrismDiagnoseBackend PrismFoundation)
add_subdirectory(Application)
target_sources(PrismApplication INTERFACE
        Application/TrustTunnelCredentials.hpp
)



LinkPrismTargets(PrismProtocolHttp2 PrismProtocolsCommon PrismProtocolHttp3Core)
LinkPrismTargets(PrismProtocolQuic PrismProtocolsCommon)
LinkPrismTargets(PrismProtocolHysteria2 PrismProtocolsCommon PrismProtocolHttp3Core)
LinkPrismTargets(PrismProtocolHysteria2 PrismProtocolQuic)
LinkPrismTargets(PrismProtocolHysteria2 PrismProtocolHttp3 PrismProtocolQuicNative PrismIngressContract PrismLifecycle)
LinkPrismTargets(PrismProtocolTuic PrismProtocolQuic)
LinkPrismTargets(PrismProtocolTuic PrismProtocolQuicNative PrismIngressContract PrismLifecycle)
LinkPrismTargets(PrismProtocolXhttp PrismProtocolHttp2)
LinkPrismTargets(PrismProtocolTrusttunnel PrismProtocolHttp2 PrismIngressContract PrismAccount)

LinkPrismTargets(PrismComposition
        PrismAccount
        PrismFoundation
        PrismNet
        PrismProtocolsCommon
        PrismProtocolHttp
        PrismProtocolSocks5
        PrismProtocolVmess
        PrismProtocolVless
        PrismProtocolTrojan
        PrismProtocolShadowsocks2022
        PrismProtocolAnytls
        PrismProtocolRestls
        PrismProtocolTrusttunnel
        PrismProtocolShadowtls
        PrismProtocolWs
        PrismProtocolNative
        PrismProtocolQuic
        PrismProtocolQuicNative
        PrismProtocolHysteria2
        PrismProtocolTuic
)

# C02 负向边的可选配置注入；默认空值不改变生产图。
if(DEFINED PRISM_BOUNDARY_FAULT AND
   NOT "${PRISM_BOUNDARY_FAULT}" STREQUAL "")
    if("${PRISM_BOUNDARY_FAULT}" STREQUAL "RuntimeComposition")
        target_link_libraries(PrismRuntime INTERFACE PrismComposition)
    elseif("${PRISM_BOUNDARY_FAULT}" STREQUAL "ProtocolApplication")
        target_link_libraries(PrismProtocolHttp INTERFACE PrismApplication)
    elseif("${PRISM_BOUNDARY_FAULT}" STREQUAL "FoundationRuntime")
        target_link_libraries(PrismFoundation INTERFACE PrismRuntime)
    elseif("${PRISM_BOUNDARY_FAULT}" STREQUAL "BoundaryHysteria2")
        target_link_libraries(PrismBoundary INTERFACE PrismProtocolHysteria2)
    elseif("${PRISM_BOUNDARY_FAULT}" STREQUAL "BoundaryTuic")
        target_link_libraries(PrismBoundary INTERFACE PrismProtocolTuic)
    else()
        message(FATAL_ERROR
            "Unknown PRISM_BOUNDARY_FAULT='${PRISM_BOUNDARY_FAULT}'; "
            "expected RuntimeComposition, ProtocolApplication, FoundationRuntime, "
            "BoundaryHysteria2, or BoundaryTuic")
    endif()
endif()

LinkPrismTargets(PrismBoundary PrismDatagramContract)
LinkPrismTargets(PrismBoundary PrismIngressContract)
LinkPrismTargets(PrismConfiguration PrismIngressModel)
LinkPrismTargets(PrismProtocolSocks5 PrismIngressContract PrismAccount PrismLifecycle PrismProtocolMux)
LinkPrismTargets(PrismProtocolShadowsocks2022 PrismIngressContract PrismAccount PrismLifecycle PrismProtocolMux)

LinkPrismTargets(PrismProtocolHttp PrismIngressContract)
LinkPrismTargets(PrismProtocolReality PrismIngressContract)
LinkPrismTargets(PrismProtocolRestls PrismIngressContract)
LinkPrismTargets(PrismProtocolShadowtls PrismIngressContract)
LinkPrismTargets(PrismProtocolMux PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolHttp2)
LinkPrismTargets(PrismProtocolAnytls PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)
LinkPrismTargets(PrismProtocolVless PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)
LinkPrismTargets(PrismProtocolTrojan PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)
LinkPrismTargets(PrismProtocolVmess PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)


# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismAccount INTERFACE
    Account/RuntimeRegistry.hpp
    Contract/Account/AdmissionAuthority.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismBoundary INTERFACE
    Boundary/Quic/QuicAdmissionBudget.hpp
    Boundary/Quic/QuicConnectionId.hpp
    Boundary/Quic/QuicConnectionRegistryAdmission.hpp
    Boundary/Quic/QuicConnectionRegistryCloseOwner.hpp
    Boundary/Quic/QuicConnectionRegistryDiagnostics.hpp
    Boundary/Quic/QuicInitial.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismComposition INTERFACE
    Composition/Provider/MuxProvider.hpp
    Composition/Provider/ProtocolCredentialPreparation.hpp
    Composition/Provider/ProviderCatalogInputs.hpp
    Composition/Provider/ProviderCatalogTypes.hpp
    Composition/Provider/ProviderInstancePreparation.hpp
    Composition/Provider/TlsCarrierProvider.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismIngressContract INTERFACE
    Contract/Ingress/AdmissionRetirement.hpp
    Contract/Ingress/DatagramIngressSelection.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismIngressModel INTERFACE
    Contract/Ingress/CarrierConfiguration.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismDiagnoseBackend INTERFACE
    Foundation/Utility/Diagnose/Detail/PathSinkOwner.hpp
    Foundation/Utility/Diagnose/Detail/RenderEpoch.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismNet INTERFACE
    Net/Dns/Detail/ResolverCacheResults.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismOperations INTERFACE
    Operations/CommandTargetScope.hpp
    Operations/ConfigurationIssue.hpp
    Operations/HttpConnectionLifecycle.hpp
    Operations/HttpRequestBudget.hpp
    Operations/Metrics.hpp
    Operations/QueryPage.hpp
    Operations/Routes/ConfigurationResultJson.hpp
    Operations/Routes/EventJson.hpp
    Operations/Routes/GetCollectionRoute.hpp
    Operations/Routes/JsonPrimitives.hpp
    Operations/Routes/MetricsJson.hpp
    Operations/Routes/QueryPageParser.hpp
    Operations/Routes/ReloadJson.hpp
    Operations/Routes/ScopedCollectionRoutes.hpp
    Operations/Routes/StreamJson.hpp
    Operations/Routes/TrafficJson.hpp
    Operations/ScopedCollectionModels.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolAnytls INTERFACE
    Protocols/Anytls/Binding.hpp
    Protocols/Anytls/Detail/Session/Retirement.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolsCommon INTERFACE
    Protocols/Common/DatagramOperationDeadline.hpp
    Protocols/Common/DatagramRelayState.hpp
    Protocols/Common/ExactIo.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolGun INTERFACE
    Protocols/Gun/Detail/GrpcSession.hpp
    Protocols/Gun/Detail/GrpcStreamFactory.hpp
    Protocols/Gun/Detail/GrpcStreamOwner.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolHttp INTERFACE
    Protocols/Http1/Binding.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolQuic INTERFACE
    Protocols/Quic/Detail/NativeConnectionShutdown.hpp
    Protocols/Quic/Detail/NativeConnectionSocketRegistry.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolReality INTERFACE
    Protocols/Reality/CarrierPreparation.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolSocks5 INTERFACE
    Protocols/Socks5/UdpAssocBindGate.hpp
    Protocols/Socks5/UdpAssocRetirement.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolTrojan INTERFACE
    Protocols/Trojan/Binding.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolTrusttunnel INTERFACE
    Protocols/Trusttunnel/Binding.hpp
    Protocols/Trusttunnel/Detail/CarrierOwner.hpp
    Protocols/Trusttunnel/Detail/Conn.hpp
    Protocols/Trusttunnel/Detail/Dgram.hpp
    Protocols/Trusttunnel/Detail/Http2Accept.hpp
    Protocols/Trusttunnel/Detail/Http2Client.hpp
    Protocols/Trusttunnel/Detail/Http2Transport.hpp
    Protocols/Trusttunnel/Detail/Http2WireWriter.hpp
    Protocols/Trusttunnel/Detail/Http2DataSubmitter.hpp
    Protocols/Trusttunnel/Http2ClientTypes.hpp
    Protocols/Trusttunnel/Http2ServerTypes.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolVless INTERFACE
    Protocols/Vless/Binding.hpp
    Protocols/Vless/UdpTunnelFrames.hpp
    Protocols/Vless/UdpTunnelRetirement.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolVmess INTERFACE
    Protocols/Vmess/Binding.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolXhttp INTERFACE
    Protocols/Xhttp/Detail/ClientTls.hpp
    Protocols/Xhttp/Detail/Common.hpp
    Protocols/Xhttp/Detail/FactoryRetirement.hpp
    Protocols/Xhttp/Detail/SplitClient.hpp
    Protocols/Xhttp/Detail/SplitClientState.hpp
    Protocols/Xhttp/Detail/SplitPath.hpp
    Protocols/Xhttp/Detail/SplitServer.hpp
    Protocols/Xhttp/Detail/SplitServerAccept.hpp
    Protocols/Xhttp/Detail/SplitServerWireWriter.hpp
    Protocols/Xhttp/Detail/SplitTransport.hpp
    Protocols/Xhttp/Detail/StreamClient.hpp
    Protocols/Xhttp/Detail/StreamClientState.hpp
    Protocols/Xhttp/Detail/StreamServer.hpp
    Protocols/Xhttp/Detail/StreamTransport.hpp
    Protocols/Xhttp/Detail/StreamWriteQueue.hpp
    Protocols/Xhttp/Detail/Wire.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismRuntime INTERFACE
    Runtime/GenerationPublication.hpp
    Runtime/ListenerSessionRunner.hpp
    Runtime/SessionAdmission.hpp
    Runtime/SessionRegistryMetadata.hpp
    Runtime/SessionRegistryStreamCatalog.hpp
    Runtime/WorkerAdmissionReceipt.hpp
)

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismProtocolMux INTERFACE
    Protocols/Mux/Detail/Root/RootRetirement.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismComposition INTERFACE
    Composition/Provider/BoundCatalog.hpp
    Composition/Provider/TlsCarrierCatalogOwner.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismIngressContract INTERFACE
    Contract/Ingress/AdmissionTransportRetirement.hpp
    Contract/Ingress/CarrierCatalogOwner.hpp
    Contract/Ingress/MuxRootCreateRequest.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismOperations INTERFACE
    Operations/Web/Catalog.hpp
    Operations/Web/Loader.hpp
    Operations/Web/Resource.hpp
    Operations/Web/Response.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolAnytls INTERFACE
    Protocols/Anytls/Detail/Session/RetirementExecutor.hpp
    Protocols/Anytls/Detail/Session/RetirementFailure.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolsCommon INTERFACE
    Protocols/Common/ProviderBindingLifecycle.hpp
    Protocols/Common/ProviderCredentials.hpp
    Protocols/Common/ProviderMuxRootState.hpp
    Protocols/Common/ProviderSessionDrainAttempt.hpp
    Protocols/Common/ProviderSessionRetirement.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolEch INTERFACE
    Protocols/Ech/Detail/Hello.hpp
    Protocols/Ech/Detail/Key.hpp
    Protocols/Ech/Detail/ServerKeyMaterial.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolGun INTERFACE
    Protocols/Gun/Detail/GrpcStreamActivity.hpp
    Protocols/Gun/Detail/GrpcStreamDriver.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolNative INTERFACE
    Protocols/Native/Detail/Tls.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolReality INTERFACE
    Protocols/Reality/Detail/Authentication.hpp
    Protocols/Reality/Detail/Handshake.hpp
    Protocols/Reality/Detail/Hello.hpp
    Protocols/Reality/Detail/Key.hpp
    Protocols/Reality/Detail/Record.hpp
    Protocols/Reality/Detail/RecordStream.hpp
    Protocols/Reality/Detail/Tls.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolRestls INTERFACE
    Protocols/Restls/Detail/Control.hpp
    Protocols/Restls/Detail/Handshake.hpp
    Protocols/Restls/Detail/Io.hpp
    Protocols/Restls/Detail/Record.hpp
    Protocols/Restls/Detail/Session.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolShadowtls INTERFACE
    Protocols/Shadowtls/Detail/Control.hpp
    Protocols/Shadowtls/Detail/Handshake.hpp
    Protocols/Shadowtls/Detail/Hello.hpp
    Protocols/Shadowtls/Detail/Io.hpp
    Protocols/Shadowtls/Detail/Record.hpp
    Protocols/Shadowtls/Detail/Session.hpp
    Protocols/Shadowtls/Detail/Wire.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolTrusttunnel INTERFACE
    Protocols/Trusttunnel/Detail/AcceptedCarrierActivity.hpp
    Protocols/Trusttunnel/Detail/AcceptedClientTransport.hpp
    Protocols/Trusttunnel/Detail/ForwardedActivity.hpp
    Protocols/Trusttunnel/Detail/Http2ClientDriver.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolWs INTERFACE
    Protocols/Ws/Detail/Codec.hpp
    Protocols/Ws/Detail/ConnClose.hpp
    Protocols/Ws/Detail/ConnFrame.hpp
    Protocols/Ws/Detail/FrameWriteGate.hpp
    Protocols/Ws/Detail/ConnHandshake.hpp
    Protocols/Ws/Detail/ConnSession.hpp
    Protocols/Ws/Detail/ConnStream.hpp
    Protocols/Ws/Detail/ConnTransport.hpp
    Protocols/Ws/Detail/StreamOwner.hpp
    Protocols/Ws/Detail/Types.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismProtocolXhttp INTERFACE
    Protocols/Xhttp/Detail/AcceptedTransport.hpp
    Protocols/Xhttp/Detail/SplitServerState.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PrismRuntime INTERFACE
    Runtime/Detail/Mailbox.hpp
    Runtime/WorkerDispatchResult.hpp
)

# SOCKS5内部UDP地址转换的真实source owner。
target_sources(PrismProtocolSocks5 INTERFACE
    Protocols/Socks5/Detail/UdpAddress.hpp
)

# 迁移后补齐的模块公共头，按实际 owner 精确登记，供 G7 双向校验。
target_sources(PrismAccount INTERFACE
    Account/Detail/BandwidthBucket.hpp
    Account/Detail/UsageCredit.hpp
    Account/PolicyConfiguration.hpp
    Account/TransferBudget.hpp
    Account/UsageCalendar.hpp
    Account/UsageModels.hpp
    Account/UsagePersistence.hpp
    Contract/Account/PayloadBudget.hpp
)
target_sources(PrismApplication INTERFACE
    Application/Account/PublishedPolicySource.hpp
    Application/Configuration/AccountPolicyJson.hpp
    Application/OperationsConfigurationPersistence.hpp
    Application/OperationsManagementQueries.hpp
    Application/OperationsManagementQuerySupport.hpp
    Application/OperationsSnapshotQueries.hpp
    Application/Storage/CommandJournal.hpp
    Application/Storage/HistoryStore.hpp
    Application/Storage/SqliteUsagePersistence.hpp
    Application/Storage/StorageRuntime.hpp
    Application/Storage/UsageLedger.hpp
)
target_sources(PrismFoundation INTERFACE
    Foundation/Memory/BytePoolMetrics.hpp
    Foundation/Memory/MemoryAllocationSnapshot.hpp
    Foundation/Memory/ProcessMemory.hpp
    Foundation/Memory/TrackingResource.hpp
    Foundation/Storage/Sqlite.hpp
)
target_sources(PrismNet INTERFACE
    Net/Dialer/Observation.hpp
    Net/Relay/FirstTransferObserver.hpp
)
target_sources(PrismOperations INTERFACE
    Operations/HistoryModels.hpp
    Operations/ManagementModels.hpp
    Operations/QueryResult.hpp
    Operations/Routes/HistoryJson.hpp
    Operations/Routes/ManagementJson.hpp
    Operations/Routes/ManagementRoutes.hpp
)
target_sources(PrismProtocolsCommon INTERFACE
    Protocols/Common/ProviderSessionResources.hpp
    Protocols/Common/DatagramRetirementActions.hpp
)
target_sources(PrismProtocolMux INTERFACE
    Protocols/Mux/Detail/Root/RootRunFailure.hpp
    Protocols/Mux/H2Mux/Http2StreamControl.hpp
)
target_sources(PrismProtocolQuic INTERFACE
    Protocols/Quic/Detail/NativeConnectionOperationReservation.hpp
)
target_sources(PrismProtocolSocks5 INTERFACE
    Protocols/Socks5/Detail/UdpAssocFailureState.hpp
)
target_sources(PrismProtocolTuic INTERFACE
    Protocols/Tuic/DgramPacketReceiver.hpp
)
target_sources(PrismResource INTERFACE
    Resource/MemorySnapshot.hpp
    Resource/Storage/DirectoryLock.hpp
    Resource/Storage/Executor.hpp
    Resource/WorkerMemoryResourceService.hpp
)
target_sources(PrismRuntime INTERFACE
    Runtime/ListenerTrace.hpp
    Runtime/SessionRegistryAccountRetirement.hpp
    Runtime/SessionTraceModel.hpp
    Runtime/SessionTraceRing.hpp
    Runtime/Statistics/HistoryCollector.hpp
    Runtime/WorkerExecution.hpp
    Runtime/WorkerTaskSnapshotGate.hpp
)
target_sources(PrismStatistics INTERFACE
    Statistics/Analysis/Histogram.hpp
    Statistics/Analysis/HistoryCatalog.hpp
    Statistics/Analysis/HistoryModels.hpp
    Statistics/Analysis/HistorySeries.hpp
)

# React资源与当前Main使用同一build树。
find_program(PrismNodeExecutable NAMES node REQUIRED)
find_program(PrismNpmExecutable NAMES npm.cmd npm REQUIRED)
add_custom_command(
    OUTPUT "${CMAKE_BINARY_DIR}/Web/catalog.json"
    COMMAND "${PrismNpmExecutable}" --prefix "${PROJECT_SOURCE_DIR}/Web" run build -- --outDir "${CMAKE_BINARY_DIR}/Web"
    COMMAND "${PrismNodeExecutable}" "${PROJECT_SOURCE_DIR}/scripts/build_prism_web_catalog.mjs" "${CMAKE_BINARY_DIR}/Web" "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    DEPENDS
        "${PROJECT_SOURCE_DIR}/Web/index.html"
        "${PROJECT_SOURCE_DIR}/Web/package-lock.json"
        "${PROJECT_SOURCE_DIR}/Web/package.json"
        "${PROJECT_SOURCE_DIR}/Web/public/PrismMark.svg"
        "${PROJECT_SOURCE_DIR}/Web/src/Api/ConfigurationDocument.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Api/JsonDocument.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/App/AdminServices.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/App/App.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/App/AppShell.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Components/ConfirmAction.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Components/Ui.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Accounts/AccountsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Configuration/ConfigurationPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Events/EventsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Ingresses/IngressesPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Operations/OperationsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Overview/OverviewPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Sessions/SessionsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/UserGroups/UserGroupsPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/UseOperations.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Features/Workers/WorkersPage.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Main.tsx"
        "${PROJECT_SOURCE_DIR}/Web/src/Services/AdminDataSource.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Services/DemoAdminDataSource.ts"
        "${PROJECT_SOURCE_DIR}/Web/src/Styles/Theme.css"
        "${PROJECT_SOURCE_DIR}/Web/README.md"
        "${PROJECT_SOURCE_DIR}/Web/tsconfig.json"
        "${PROJECT_SOURCE_DIR}/Web/vite.config.ts"
        "${PROJECT_SOURCE_DIR}/scripts/build_prism_web_catalog.mjs"
    VERBATIM
)
add_custom_target(PrismWeb DEPENDS "${CMAKE_BINARY_DIR}/Web/catalog.json")
# Web 前端依赖单独构建；Prism 默认构建不触发 TypeScript/Vite。

# 源与依赖全部登记后运行最终门禁。
foreach(PrismTarget IN ITEMS
        PrismFoundation
        PrismAccount
        PrismLifecycle
        PrismResource
        PrismStatistics
        PrismOperations
        PrismTransport
        PrismNet
        PrismBoundary
        PrismRuntime
        PrismComposition
        PrismConfiguration
        PrismProtocolsCommon
        PrismApplication
        Prism)
    AssertPrismTargetSources(${PrismTarget})
    AssertPrismTargetIncludes(${PrismTarget})
endforeach()
AssertPrismTargetGraph()
AssertPrismStandaloneClosure(Prism)
AssertPrismDiagnoseBackendBoundary()
