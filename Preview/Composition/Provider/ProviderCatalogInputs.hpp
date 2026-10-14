/** @file ProviderCatalogInputs.hpp @brief Provider prepare 的冷、typed 输入值。 */
#pragma once

#include <Preview/Contract/Ingress/ProtocolConfiguration.hpp>
#include <Preview/Contract/Services/Authentication.hpp>
#include <Preview/Contract/Services/Datagram.hpp>
#include <Preview/Contract/Services/DatagramEgress.hpp>
#include <Preview/Contract/Services/Quic.hpp>
#include <Preview/Contract/Services/Stream.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Protocols/Http3/ServerFactory.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Preview::Composition::Provider
{
    /** @brief provider binding 的独立物理退休观察；Unknown 不能用于归还代次资源。 */
    enum class PhysicalRetirementState : std::uint8_t
    {
        Retired,
        Active,
        Unknown,
    };

    /** @brief 一个 configured protocol instance 的冷配置值。 */
    struct ConfiguredInstance final
    {
        Preview::Contract::ProtocolConfiguration Protocol;
        bool Tcp{true};
        bool Udp{false};
        Preview::Contract::AuthenticationServices Authentication;
    };

    /**
     * @brief Prepare 按值接管配置代次、同代资源计数、协议实例与配置绑定。
     * @details Generation 固定配置值；UseState 是 F RuntimeGenerationServices 唯一代次使用计数，
     *          只在 mux root 接入时 Acquire，不持有或反向引用 RuntimeSnapshot/ProviderCatalog。
     */
    struct Preparation final
    {
        Preview::Foundation::GenerationPin Generation;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        std::vector<ConfiguredInstance> Instances;
        std::vector<Preview::Contract::ProtocolBindingConfiguration> Bindings;
    };

    /** @brief 各协议 Prepared 阶段使用的 typed service 句柄。 */
    struct BindingServices final
    {
        boost::asio::any_io_executor Executor;
        Preview::Contract::DatagramServices Associations;
        std::shared_ptr<Preview::Contract::DatagramEgress> Egress;
        std::shared_ptr<Preview::Contract::DatagramSender> Sender;
        Preview::Contract::QuicBindingServices Quic;
        std::shared_ptr<Preview::Http3::ServerFactory> Http3;
        /** @brief Mux root 的实际 owning dial/traffic/idle/buffer 能力。 */
        Preview::Contract::StreamServices Streams;
    };
}
