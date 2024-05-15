# go-secoap

`secoap` go语言实现，私有协议，一种coap协议的变种

## secoap

`secoap` 为 `sensorh.com` 私有定制的一套物联网协议，基于 `coap` 协议上的改进，可用于设备与服务器之间的通信。

设备与服务器之间的通信(**大端模式**), 数据内容由 `Header` 和 `Payload` 组成，具体协议描述如下：

```text
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver|  TKL  | T |  EID  |  ETP  |   CRC16                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Message ID                  |   Code        |   RSUM8       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Token (if any, TKL bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1 1 1 1 1 1 1 1|    Payload (if any) ...
   | (if Ver != 0) |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Ver: 0, 是没有0xFF分割位，CRC16 为小端存储（历史遗留问题），如下所示:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0|R|R|R|R|0 1|  EID  |  ETP  |    CRC16-L    |    CRC16-H    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Ver: 1, 有0xFF分割位，CRC16 为大端存储，如下所示:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 1|  TKL  | T |  EID  |  ETP  |   CRC16                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Message ID                  |   Code        |   RSUM8       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Token (if any, TKL bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1 1 1 1 1 1 1 1|    Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header

协议包由定长头(4字节或8字节)组成

- `Ver`: 2 bits，协议版本号，目前支持 0 和 1 两个版本
- `TKL`: 4 bits，可变长度Token字段(0-8字节)。长度9-15是保留，不能被发送，并且必须处理为消息格式错误。
- `T`: 2 bits，包类型

    ```text
    Confirmable (0) 可确认包，可靠的消息
    Non-confirmable (1) 非可确认包，不可靠的消息
    Acknowledgement (2) 确认包或非可确认包的回复响应
    Reset (3) 重置包，当客户端或服务器无法处理时可重置
    ```

- `EID`: 4 bits，编码ID，用于标识编码类型的不同版本
- `ETP`: 4 bits, 编码类型，用于对 Payload 内容的应用编码类型，详见编码类型列表
    | ETP | EID | Content-Type | 说明 |
    | :--- | :--- | :--- | :--- |
    | 0 | 0 | none/userdefine | 无编码, 不要设置, 字段留空, 为了兼容老设备（未设置编码类型字段），保留用户自定义协议 |
    | 1 | 0 | text/base64 | base64编码 |
    | 2 | 0 | text/plain | 纯文本字符串编码 |
    | 3 | 0 | text/hex | 字符串十六进制编码 |
    | 4 | 0 | application/octet-stream | 二进制编码 |
    | 5 | 0 | application/protobuf | Protobuf编码 |
    | 6 | 0 | application/json | JSON编码 |

- `CRC16`: 校验和，对 Payload 内容进行 CRC16/MODBUS 计算后的结果, 2 bytes， 在 Ver = 0时，采用小端存储，Ver = 1 时，采用大端存储
- `Message ID`: 2 bytes，消息ID，用于标识消息的唯一性
- `Code`: 1 byte，消息类型，用于标识消息的类型，详见消息类型列表
    | Code | 说明 |
    | :--- | :--- |
    | 1 | GET |
    | 2 | POST |
    | 3 | POST |
    | 3 | PUT |
    | 4 | DELETE |
    | - | - |
    | 0 | Empty |
    | 65 | Created |
    | 66 | Deleted |
    | 67 | Valid |
    | 68 | Changed |
    | 69 | Content |
    | 95 | Continue |
    | 128 | BadRequest |
    | 129 | Unauthorized |
    | 130 | BadOption |
    | 131 | Forbidden |
    | 132 | NotFound |
    | 133 | MethodNotAllowed |
    | 134 | NotAcceptable |
    | 136 | RequestEntityIncomplete |
    | 140 | PreconditionFailed |
    | 141 | RequestEntityTooLarge |
    | 143 | UnsupportedMediaType |
    | 157 | TooManyRequests |
    | 160 | InternalServerError |
    | 161 | NotImplemented |
    | 162 | BadGateway |
    | 163 | ServiceUnavailable |
    | 164 | GatewayTimeout |
    | 165 | ProxyingNotSupported |
    | - | - |
    | 192 | GiterlabErrnoOk |
    | 193 | GiterlabErrnoParamConfigure |
    | 194 | GiterlabErrnoFirmwareUpdate |
    | 195 | GiterlabErrnoUserCommand |
    | 220 | GiterlabErrnoEnterFlightMode |
    | 224 | GiterlabErrnoIllegalKey |
    | 225 | GiterlabErrnoDataError |
    | 226 | GiterlabErrnoDeviceNotExist |
    | 227 | GiterlabErrnoTimeExpired |
    | 228 | GiterlabErrnoNotSupportProtocolVersion |
    | 229 | GiterlabErrnoProtocolParsingErrors |
    | 230 | GiterlabErrnoRequestTimeout |
    | 231 | GiterlabErrnoOptProtocolParsingErrors |
    | 232 | GiterlabErrnoNotSupportAnalyticalMethods |
    | 233 | GiterlabErrnoNotSupportPacketType |
    | 234 | GiterlabErrnoDataDecodingError |
    | 235 | GiterlabErrnoPackageLengthError |
    | 236 | GiterlabErrnoDuoxieyunServerRequestBusy |
    | 237 | GiterlabErrnoSluanServerRequestBusy |
    | 238 | GiterlabErrnoCacheServiceErrors |
    | 239 | GiterlabErrnoTableStoreServiceErrors |
    | 240 | GiterlabErrnoDatabaseServiceErrors |
    | 241 | GiterlabErrnoNotSupportEncodingType |
    | 242 | GiterlabErrnoDeviceRepeatRegistered |
    | 243 | GiterlabErrnoDeviceSimCardUsed |
    | 244 | GiterlabErrnoDeviceSimCardIllegal |
    | 245 | GiterlabErrnoDeviceUpdateForcedFailed |

- `RSUM8`: 1 byte，反转校验和，对 `Header` 和 `Payload` 字段进行校验和计算后的结果，计算公式如下：

    ```c
        uint8_t rsum8(void *data, uint16_t len) {
            uint8_t sum  = 0;
            uint8_t *pdata = (uint8_t *)data;

            while (len--) {
                sum += ~(*pdata);
                pdata++;
            }
            return sum;
        }
    ```

- `Token`: Token字段，长度由 TKL 指定（0 到 8 bytes），Token长度为 0 时，Token字段为空
- `Options`: 可选字段，长度不定，用于扩展消息头部信息，Type-Length-Value (TLV) format, 详见 [CoAP-Option Format](https://datatracker.ietf.org/doc/html/rfc7252#section-3.1)
- `Payload`: 消息体，长度不定，用于携带消息内容

### Payload

`Payload` 为设备指定的数据格式，通过指定编码类型进行序列号后的数据。

- `内容部分：` 数据，可扩充对象数据或序列化后的对象数据
