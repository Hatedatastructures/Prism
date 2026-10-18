/**
 * @file Grpc.hpp
 * @brief Gun 标准 gRPC/HTTP2 endpoint 聚合入口。
 * @details 配置、stream accept 工厂、metadata、framing 和连接 owner
 *          分别位于职责头文件中。
 */
#pragma once

#include <Prism/Protocols/Gun/GrpcFraming.hpp>
#include <Prism/Protocols/Gun/GrpcMetadata.hpp>
#include <Prism/Protocols/Gun/GrpcStream.hpp>
#include <Prism/Protocols/Gun/GrpcTypes.hpp>
