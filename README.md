# dd-node

一个用 Node.js 写的 VMess over WebSocket 节点，不需要 Docker 和 Xray。
适合跑在只支持 Node.js 的平台上，比如 Railway、各种应用托管。

只支持 FlClash 这类客户端实际用到的组合：VMess、AES-128-GCM、WebSocket 传输、TLS。

## 部署

需要 Node.js 18 以上。

```bash
git clone https://github.com/linbaoa4598/dd-node.git
cd dd-node
npm install
node server.js
```

启动后监听 `8080` 端口，WebSocket 路径是 `/c214cf6df5df`。
用环境变量修改：

```bash
PORT=8080 UUID=你的UUID WS_PATH=/你的路径 node server.js
```

前面需要一层 HTTPS 反代（Caddy、Nginx，或平台自带的域名），客户端通过 `wss://` 连接。

## 客户端参数

- 协议：VMess
- 地址：你的域名
- 端口：443
- UUID：和服务器的 `UUID` 一致
- 传输：ws
- 路径：和服务器的 `WS_PATH` 一致
- TLS：开启

## Railway

把这个仓库关联到 Railway 服务后会自动部署。Railway 用 `PORT` 环境变量指定端口，代码已经读取它。
部署完成后在服务的 Settings 里生成域名，客户端的地址和 SNI 都填这个域名。
