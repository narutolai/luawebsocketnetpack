# luawebsocketnetpack
skynet+lua用来解析websocket数据帧的c库文件 ，可以正确处理分帧数据包，正确过滤超大包。

源地址在这里https://github.com/sctangqiang/skynetpatch/blob/master/lualib-src/lua-websocketnetpack.c

但是这里这个改法没有对数据分帧做处理，也就是帧头中fin=0的时候做处理，当然它限定了MAX_PACKSIZE 实际上也是没有关系的，不过它过滤大数据包的方式就是在缓冲区一直2字节2字节的读取，直到匹配到正确的帧头，这种做法有点问题，很有可能消息中间中也有符合数据帧头的2字节的格式，然后就可能会解析出错误的帧长度，然后给上层上报错误的消息数据，我们项目就是用的这个文件，然后发大包的时候就会出这些问题。

我觉得正确的过滤方式应该是这样的：先收取一个完整的消息包(即对分帧数据也要进行处理)，然后获取到包大小后再根据规则判断是否要过滤。

这里我分别提交了2个文件，两者都对分帧数据做处理，有limit后缀的文件添加了消息包大小过滤功能，对超过设定大小的包将不会传递给lua层。 弄成2个文件只是为了方便。有问题可以提issue
