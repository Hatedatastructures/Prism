/**
 * @file RequestCodec.hpp
 * @brief Trojan 握手 request wire 编解码
 * @details 只拥有凭据、命令、地址和尾部 CRLF 的无状态请求转换。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Trojan/AddressCodec.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>

namespace Preview::Trojan
{

    /**
     * @brief Trojan 请求编码参数
     * @details Credential 和 Target 为借用视图，调用期间必须保持有效。
     */
    struct RequestParameters
    {
        std::string_view Credential;
        Command Cmd;
        const Address &Target;
    };

    /**
     * @brief 构造完整请求头并写入复用缓冲
     * @param Params 请求装配参数
     * @param Output 输出缓冲
     * @details 输出格式为 [credential][CRLF][CMD][address][CRLF]。
     */
    template <typename Alloc>
    inline auto BuildRequest(
        const RequestParameters &Params,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (Params.Credential.size() != CredentialLen ||
            (Params.Cmd != Command::Connect &&
             Params.Cmd != Command::UdpAssociate &&
             Params.Cmd != Command::Mux))
        {
            return;
        }
        Output.reserve(CredentialLen + 2 + 1 + Params.Target.Host.size() + 2 + 2);
        Output.insert(Output.end(), Params.Credential.begin(), Params.Credential.end());
        Output.push_back('\r');
        Output.push_back('\n');
        Output.push_back(static_cast<std::uint8_t>(Params.Cmd));
        if (!EncodeAddress(Params.Target, Output))
        {
            Output.clear();
            return;
        }
        Output.push_back('\r');
        Output.push_back('\n');
    }

    /**
     * @brief 构造完整请求头
     * @param CredentialValue 56 字符凭据
     * @param Cmd 命令
     * @param Target 目标地址
     * @return 请求头字节
     */
    [[nodiscard]] inline auto BuildRequest(
        std::string_view CredentialValue,
        Command Cmd,
        const Address &Target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestParameters{CredentialValue, Cmd, Target}, Output);
        return Output;
    }

    /**
     * @brief 增量解析 Trojan 请求头
     * @param Data 输入数据
     * @param Output 输出请求头
     * @param Consumed 输出消耗字节数
     * @return 错误码；数据不足时返回 NeedMore
     */
    [[nodiscard]] inline auto ParseRequest(
        std::span<const std::uint8_t> Data,
        RequestHeader &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.size() < CredentialLen + 2)
        {
            return Error::NeedMore;
        }
        if (Data[CredentialLen] != '\r' || Data[CredentialLen + 1] != '\n')
        {
            return Error::BadMagic;
        }
        std::size_t Offset = CredentialLen + 2;
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        Output.Cmd = static_cast<Command>(Data[Offset++]);
        if (Output.Cmd != Command::Connect &&
            Output.Cmd != Command::UdpAssociate &&
            Output.Cmd != Command::Mux)
        {
            return Error::BadMessage;
        }

        std::size_t AddressConsumed = 0;
        const auto AddressError = ParseAddress(
            Data.subspan(Offset),
            Output.Target,
            AddressConsumed);
        if (AddressError != Error::None)
        {
            return AddressError;
        }
        Offset += AddressConsumed;
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        if (Data[Offset] != '\r' || Data[Offset + 1] != '\n')
        {
            return Error::BadMagic;
        }
        Consumed = Offset + 2;
        return Error::None;
    }

} // namespace Preview::Trojan
