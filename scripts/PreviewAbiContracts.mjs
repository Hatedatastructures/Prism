// 精确列出库规定的回调 ABI。路径、符号和参数数目必须同时匹配；同文件其它宽接口仍违规。
const foreignAbiContracts = new Map();
function RegisterAbi(file, symbols) {
  for (const [name, count, contract] of symbols) {
    foreignAbiContracts.set(`${file}\0${name}`, { count, contract });
  }
}
const http3Callbacks = [
  ['CbBeginHeaders', 4, 'nghttp3_callbacks.begin_headers'],
  ['CbRecvHeader', 8, 'nghttp3_callbacks.recv_header'],
  ['CbEndHeaders', 5, 'nghttp3_callbacks.end_headers'],
  ['CbRecvData', 6, 'nghttp3_callbacks.recv_data'],
  ['CbStopSending', 5, 'nghttp3_callbacks.stop_sending'],
  ['CbEndStream', 4, 'nghttp3_callbacks.end_stream'],
];
RegisterAbi('Preview/Protocols/Http3/Detail/SessionContract.hpp',
  [...http3Callbacks, ['ReadResponseBody', 7, 'nghttp3_data_reader.read_data']]);
RegisterAbi('Preview/Protocols/Http3/Detail/SessionCallbacks.hpp',
  http3Callbacks.map(([name, count, contract]) => [`Session::${name}`, count, contract]));
RegisterAbi('Preview/Protocols/Http3/Detail/SessionOutput.hpp',
  [['Session::ReadResponseBody', 7, 'nghttp3_data_reader.read_data']]);
const http3ClientCallbacks = [
  ['BeginHeaders', 4, 'nghttp3_callbacks.begin_headers'],
  ['ReceiveHeader', 8, 'nghttp3_callbacks.recv_header'],
  ['EndHeaders', 5, 'nghttp3_callbacks.end_headers'],
  ['ReceiveData', 6, 'nghttp3_callbacks.recv_data'],
  ['StopSending', 5, 'nghttp3_callbacks.stop_sending'],
  ['EndStream', 4, 'nghttp3_callbacks.end_stream'],
  ['ResetStream', 5, 'nghttp3_callbacks.reset_stream'],
  ['ReadRequestBody', 7, 'nghttp3_data_reader.read_data'],
];
RegisterAbi('Preview/Protocols/Http3/Detail/NativeClientCallbackApi.hpp', http3ClientCallbacks);
RegisterAbi('Preview/Protocols/Http3/Detail/NativeClientCallbacks.hpp',
  http3ClientCallbacks.map(([name, count, contract]) => [`NativeClientCallbacks::${name}`, count, contract]));
const quicCallbacks = [
  ['SetReadSecret', 5, 'SSL_QUIC_METHOD.set_read_secret'],
  ['SetWriteSecret', 5, 'SSL_QUIC_METHOD.set_write_secret'],
  ['AddHandshakeData', 4, 'SSL_QUIC_METHOD.add_handshake_data'],
  ['RecvCryptoData', 6, 'ngtcp2_callbacks.recv_crypto_data'],
  ['RecvStreamData', 8, 'ngtcp2_callbacks.recv_stream_data'],
  ['StreamClose', 6, 'ngtcp2_callbacks.stream_close'],
  ['RecvDatagram', 5, 'ngtcp2_callbacks.recv_datagram'],
  ['VersionNegotiation', 4, 'ngtcp2_callbacks.version_negotiation'],
  ['NewConnectionId', 5, 'ngtcp2_callbacks.get_new_connection_id'],
];
RegisterAbi('Preview/Protocols/Quic/Detail/NativeConnection.hpp', quicCallbacks);
RegisterAbi('Preview/Protocols/Quic/Detail/NativeConnectionCallbacks.hpp',
  quicCallbacks.map(([name, count, contract]) => [`NativeConnection::${name}`, count, contract]));
RegisterAbi('Preview/Application/BoundaryStartup.hpp',
  [['SelectNativeTlsAlpn', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/Integration/InteropHysteria2.cpp',
  [['SelectH3', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/integration/InteropHysteria2.cpp',
  [['SelectH3', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/Integration/InteropTrusttunnel.cpp',
  [['SelectH2', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/integration/InteropTrusttunnel.cpp',
  [['SelectH2', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/Integration/InteropXhttp.cpp',
  [['SelectH2', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/integration/InteropXhttp.cpp',
  [['SelectH2', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/Protocols/Trusttunnel/TrusttunnelHttp2TransportSupport.hpp',
  [['SelectH2', 6, 'SSL_CTX_set_alpn_select_cb']]);
RegisterAbi('tests/Preview/protocols/Trusttunnel/TrusttunnelHttp2TransportSupport.hpp',
  [['SelectH2', 6, 'SSL_CTX_set_alpn_select_cb']]);

/** 按当前文件、符号和真实参数数目返回唯一上游 ABI 契约。 */
export function GetPreviewAbiContract(File, Name, Count) {
  const Contract = foreignAbiContracts.get(`${File}\0${Name}`);
  if (Contract && Contract.count === Count) return Contract;
  return undefined;
}
