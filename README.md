# luawebsocketnetpack
skynet+lua用来解析websocket数据帧的c库文件 ，可以正确处理分帧数据包，正确过滤超大包。

源地址在这里https://github.com/sctangqiang/skynetpatch/blob/master/lualib-src/lua-websocketnetpack.c

但是这里这个改法没有对数据分帧做处理，也就是帧头中fin=0的时候做处理，当然它限定了MAX_PACKET 实际上也是没有关系的，不过它过滤大数据包的方式就是在缓冲区一直2字节2字节的读取，直到匹配到正确的帧头，但是很有可能消息包中也有符合数据帧头的2字节的格式，然后就会给上层错误的消息数据，项目就是用的这个，然后发大包的时候经常出问题。

我对此做了一些改进，让这个文件可以处理分帧数据，等获取到一个完整的包后再进行过滤或者不过滤。
