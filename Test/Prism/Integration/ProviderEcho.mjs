// 真实 listener 验收的 TCP/UDP upstream；只记录 literal bytes 和包计数，不处理代理认证。
import net from 'node:net';
import dgram from 'node:dgram';
import http from 'node:http';
const records=[];
const sockets=new Set();
const tcp=net.createServer(socket=>{
  sockets.add(socket);
  socket.on('close',()=>sockets.delete(socket));
  socket.on('data',bytes=>{const record={type:'tcp',bytes:bytes.length,hex:bytes.toString('hex')};records.push(record);process.stdout.write(JSON.stringify(record)+'\n');socket.write(bytes);});
  socket.on('error',()=>{});
});
const udp=dgram.createSocket('udp4');
udp.on('message',(bytes,peer)=>{const record={type:'udp',bytes:bytes.length,hex:bytes.toString('hex'),sourcePort:peer.port};records.push(record);process.stdout.write(JSON.stringify(record)+'\n');udp.send(bytes,peer.port,peer.address);});
const control=http.createServer((request,response)=>{
  response.setHeader('content-type','application/json');response.end(JSON.stringify(records));
  if(request.url==='/stop'){
    for(const socket of sockets)socket.destroy();
    tcp.close();udp.close();control.close();
  }
});
await Promise.all([
  new Promise(resolve=>tcp.listen(0,'127.0.0.1',resolve)),
  new Promise(resolve=>udp.bind(0,'127.0.0.1',resolve)),
  new Promise(resolve=>control.listen(0,'127.0.0.1',resolve)),
]);
process.stdout.write(JSON.stringify({tcp:tcp.address().port,udp:udp.address().port,control:control.address().port})+'\n');
