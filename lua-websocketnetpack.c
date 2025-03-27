#include "skynet_malloc.h"
#include "skynet_socket.h"
#include "skynet.h"
#include <lua.h>
#include <lauxlib.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#define QUEUESIZE 1024
#define HASHSIZE 4096
#define SMALLSTRING 2048
#define HEADERSIZE 1024
#define WEBSOCKET_HEADER_LEN  2
#define WEBSOCKET_MASK_LEN    4
#define MAX_PACKSIZE (64*1024)
#define MAX_PAYLOAD_NUM_PER_MSG 10 //一个消息最大会是几个负载 10个应该是极限了 

#define TYPE_DATA 1
#define TYPE_MORE 2
#define TYPE_ERROR 3
#define TYPE_OPEN 4
#define TYPE_CLOSE 5
#define TYPE_WARNING 6

struct netpack {
	int id;
	int size;
	void * buffer;
};

struct uncomplete {
	struct netpack pack[MAX_PAYLOAD_NUM_PER_MSG]; 	//这个只是数据帧的负载 payload
	int cur_packet;
	struct uncomplete * next;
	uint8_t header[HEADERSIZE];
	int header_size;
	int read; //当前cur_pay_load的head_size
    // websocket mask
    int mask;
    int ismask;
    int hasunmask_size;
	int fin ;
	int msgsize ;
};

struct queue {
	int cap;
	int head;
	int tail;
	struct uncomplete * hash[HASHSIZE];
	struct netpack queue[QUEUESIZE];
};

static void
clear_list(struct uncomplete * uc) {
	while (uc) {
		for (int i =0; i <= uc->cur_packet; i++)
		{
			skynet_free(uc->pack[i].buffer);
		}
		void * tmp = uc;
		uc = uc->next;
		skynet_free(tmp);
	}
}

static int
lclear(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL) {
		return 0;
	}
	int i;
	for (i=0;i<HASHSIZE;i++) {
		clear_list(q->hash[i]);
		q->hash[i] = NULL;
	}
	if (q->head > q->tail) {
		q->tail += q->cap;
	}
	for (i=q->head;i<q->tail;i++) {
		struct netpack *np = &q->queue[i % q->cap];
		skynet_free(np->buffer);
	}
	q->head = q->tail = 0;

	return 0;
}

static inline int
hash_fd(int fd) {
	int a = fd >> 24;
	int b = fd >> 12;
	int c = fd;
	return (int)(((uint32_t)(a + b + c)) % HASHSIZE);
}

static struct uncomplete *
find_uncomplete(struct queue *q, int fd) {
	if (q == NULL)
		return NULL;
	int h = hash_fd(fd);
	struct uncomplete * uc = q->hash[h];
	if (uc == NULL)
		return NULL;
	int index = uc->cur_packet -1 < 0 ? 0:uc->cur_packet -1;
	if (uc->pack[index].id == fd) {
		q->hash[h] = uc->next;
		return uc;
	}
	struct uncomplete * last = uc;
	while (last->next) {
		uc = last->next;
		int index = uc->cur_packet -1 < 0 ? 0:uc->cur_packet -1;
		if (uc->pack[index].id == fd) {
			last->next = uc->next;
			return uc;
		}
		last = uc;
	}
	return NULL;
}

static struct queue *
get_queue(lua_State *L) {
	struct queue *q = lua_touserdata(L,1);
	if (q == NULL) {
		q = lua_newuserdata(L, sizeof(struct queue));
		q->cap = QUEUESIZE;
		q->head = 0;
		q->tail = 0;
		int i;
		for (i=0;i<HASHSIZE;i++) {
			q->hash[i] = NULL;
		}
		lua_replace(L, 1);
	}
	return q;
}

static void
expand_queue(lua_State *L, struct queue *q) {
	struct queue *nq = lua_newuserdata(L, sizeof(struct queue) + q->cap * sizeof(struct netpack));
	nq->cap = q->cap + QUEUESIZE;
	nq->head = 0;
	nq->tail = q->cap;
	memcpy(nq->hash, q->hash, sizeof(nq->hash));
	memset(q->hash, 0, sizeof(q->hash));
	int i;
	for (i=0;i<q->cap;i++) {
		int idx = (q->head + i) % q->cap;
		nq->queue[i] = q->queue[idx];
	}
	q->head = q->tail = 0;
	lua_replace(L,1);
}

static void
push_data(lua_State *L, int fd, void *buffer, int size, int clone) {
	if (clone) {
		void * tmp = skynet_malloc(size);
		memcpy(tmp, buffer, size);
		buffer = tmp;
	}


	struct queue *q = get_queue(L);
	struct netpack *np = &q->queue[q->tail];
	if (++q->tail >= q->cap)
		q->tail -= q->cap;
	np->id = fd;
	np->buffer = buffer;
	np->size = size;
	if (q->head == q->tail) {
		expand_queue(L, q);
	}
}

static struct uncomplete * save_uncomplete(lua_State *L, int fd) {
	struct queue *q = get_queue(L);
	int h = hash_fd(fd);
	struct uncomplete * uc = skynet_malloc(sizeof(struct uncomplete));
	memset(uc, 0, sizeof(*uc));
	uc->cur_packet = 0;
	uc->fin = 1;
	uc->next = q->hash[h];
	uc->pack[uc->cur_packet].id = fd;
	q->hash[h] = uc;

	return uc;
}

static uint64_t ntoh64(uint64_t host) {
    uint64_t ret = 0;
    uint32_t high, low;
    low = host & 0xFFFFFFFF;
    high = (host >> 32) & 0xFFFFFFFF;
    low = ntohl(low);
    high = ntohl(high);
    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}
/*
* @return -1表示包头长不够 -2表示包前两个字节无效逻辑需要扔掉
*/
static  int
read_size(uint8_t * buffer, int size, int* pack_head_length, int* mask, int * ismask, int * hasunmask_size, int*fin_) {
	
	if (size < 2) {
		return -1;
	}
	
	char fin = (buffer[0] >> 7) & 0x1;
    char is_mask = (buffer[1] >> 7) & 0x1;


	//本数据帧不是最后一个数据帧


    int offset = 0;
	int pack_size = 0;
    //0-125
    char length = buffer[1] & 0x7f;
    offset += WEBSOCKET_HEADER_LEN;
    //126
    if (length < 0x7E) {
        pack_size = length;
    }
    //Short
    else if (0x7E == length) {
		if (size < WEBSOCKET_HEADER_LEN + sizeof(short)) {
			return -1;
		}
        pack_size = ntohs(*((uint16_t *) (buffer+WEBSOCKET_HEADER_LEN)));
        //printf("read_size3 pack_size=%d sizeof(short)=%d sizeof(uint16_t)=%d\n", pack_size, sizeof(short), sizeof(uint16_t));
        offset += sizeof(short);
    }
    else {
		if (size < WEBSOCKET_HEADER_LEN + sizeof(int64_t)) {
			return -1;
		}
        pack_size = ntoh64(*((uint64_t *) (buffer+WEBSOCKET_HEADER_LEN)));
        //printf("read_size4 pack_size=%d sizeof(int64_t)=%d sizeof(uint64_t)=%d\n", pack_size, sizeof(int64_t), sizeof(uint64_t));
        offset += sizeof(int64_t);
    }
	
    if (is_mask) {
        if (offset + WEBSOCKET_MASK_LEN > size) {
            return -1;
        }

        *ismask = 1;

        char *masks = (char*)mask;
        memcpy(masks, (buffer + offset), WEBSOCKET_MASK_LEN);
        offset += WEBSOCKET_MASK_LEN;
    }
	*fin_ =1;
	if(fin == 0)
	{
		*fin_ = 0;
	}
	*pack_head_length = offset;
	return pack_size;
}

static void decode_wsmask_data(uint8_t* buffer, int size, struct uncomplete *uc)
{
        if (uc == NULL)
        {
            return;
        }

        if (! uc->ismask ) 
        {
            return;
        }

        char *masks = (char*)(&(uc->mask));
        if (size)
        {
            int i;
            for (i = 0; i < size; i++)
            {
                buffer[i] ^= masks[(i+uc->hasunmask_size) % WEBSOCKET_MASK_LEN];
            }
            uc->hasunmask_size += size;
        }
}

static int websocket_strnpos(char *haystack, uint32_t haystack_length, char *needle, uint32_t needle_length)
{
    assert(needle_length > 0);
    uint32_t i;

    for (i = 0; i < (int) (haystack_length - needle_length + 1); i++)
    {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
        {
            return i;
        }
        haystack++;
    }

    return -1;
}
/*
* @param  buffer   数据buffer
* @param  size     数据buffer的大小
* @return  -1表示解析失败， >0表示解析成功返回header的长度
*/
static int get_http_header(uint8_t* buffer, int size)
{
	int n = websocket_strnpos((char*)buffer, size, "\r\n\r\n", 4);
	if (n < 0)
	{
		return n;
	}
	
	return (n+4);
}
static int
push_more(lua_State *L, int fd, uint8_t *buffer, int size, int wsocket_handeshake) {
	struct queue *q = lua_touserdata(L,1);
	int pack_size = 0;
	int pack_head_length = 0;
    int mask = 0;
    int ismask = 0;
    int hasunmask_size = 0;
	int fin = 1;
	if (wsocket_handeshake)
	{
		//认为socket初次建立连接读取握手协议
		pack_size = get_http_header(buffer, size);			
	}
	else
	{
		//读取帧大小
		pack_size = read_size(buffer, size, &pack_head_length, &mask, &ismask, &hasunmask_size, &fin);
	}
	
	if (pack_size == -1)
	{	
		struct uncomplete * uc = find_uncomplete(q, fd);
		if (uc == NULL)
		{
			uc = save_uncomplete(L, fd);
		}
		else
		{	
			int h = hash_fd(fd);
			uc->next = q->hash[h];
			q->hash[h] = uc;	
		}
		uc->read = -1;
		uc->header_size = size;
		memset(uc->header,0, HEADERSIZE);
		memcpy(uc->header, buffer, size);
		return 1;			
	}
	buffer += pack_head_length;
	size -= pack_head_length;

	if (size < pack_size && !wsocket_handeshake) {
		struct uncomplete * uc = find_uncomplete(q, fd);
		if(uc == NULL){
			uc = save_uncomplete(L, fd);
			uc->mask = mask;
			uc->ismask = ismask;
			uc->hasunmask_size = hasunmask_size;
		}
		else //有旧的uc
		{
			int h = hash_fd(fd);
			uc->next = q->hash[h];
			q->hash[h] = uc;	
		}
		uc->read = size;
		uc->fin = fin;
		uc->pack[uc->cur_packet].size = pack_size;
		uc->pack[uc->cur_packet].buffer = skynet_malloc(pack_size);
		decode_wsmask_data(buffer, uc->read, uc);
		memcpy(uc->pack[uc->cur_packet].buffer, buffer, uc->read);
		return 1;
	}
	struct uncomplete decode_uc;
	memset(&decode_uc, 0, sizeof(decode_uc));
	decode_uc.mask = mask;
	decode_uc.ismask = ismask;
	decode_uc.hasunmask_size = hasunmask_size;
	if(size == pack_size && fin == 1)
	{
		decode_wsmask_data(buffer, pack_size, &decode_uc);
		struct uncomplete * uc = find_uncomplete(q, fd);
		if(uc == NULL){
			if(pack_size > MAX_PACKSIZE)
			{
				return 1;	
			}
			push_data(L, fd, buffer, pack_size, 1);	//再向queue中 push一条消息
			return 2;
		}
		else 
		{	
			int msg_size = uc->msgsize + pack_size;
			if(msg_size > MAX_PACKSIZE) {return 1;}
			void * result = skynet_malloc(msg_size);
			int offset  = 0;
			for(int i =0; i < uc->cur_packet; ++i){
				memcpy(result + offset, uc->pack[i].buffer, uc->pack[i].size);
				offset = offset + uc->pack[i].size;
				skynet_free(uc->pack[i].buffer);
			}
			memcpy(result + offset, buffer, size);
			push_data(L,fd, result, msg_size, 0);//不用拷贝
			skynet_free(uc);
			return 2;
		}
	}
	else if(size == pack_size && fin == 0){
			struct uncomplete * uc = find_uncomplete(q, fd);
			if(uc == NULL){
				uc = save_uncomplete(L, fd);
			}
			else
			{
				int h = hash_fd(fd);
				uc->next = q->hash[h];
				q->hash[h] = uc;	
			}
			uc->read = -1;
            uc->mask = mask;
            uc->ismask = ismask;
			uc->fin = fin;
            uc->hasunmask_size = hasunmask_size;
			uc->pack[uc->cur_packet].size = pack_size;			
			uc->pack[uc->cur_packet].buffer = skynet_malloc(pack_size);

			decode_wsmask_data(buffer, pack_size, uc);
			memcpy(uc->pack[uc->cur_packet].buffer, buffer, pack_size);
			uc->msgsize = uc->msgsize + pack_size;
			uc->cur_packet++;

			return 1;
	}
	else if(size > pack_size && fin == 1){
		decode_wsmask_data(buffer, pack_size, &decode_uc);
		struct uncomplete * uc = find_uncomplete(q, fd);
		if(uc == NULL){
			if(pack_size > MAX_PACKSIZE)
			{
				buffer += pack_size;
				size -= pack_size;
				int res = push_more(L, fd, buffer, size, wsocket_handeshake);
				return res;
			}
			else
			{
				push_data(L, fd, buffer, pack_size, 1);	//再向queue中 push一条消息
				buffer += pack_size;
				size -= pack_size;
				push_more(L, fd, buffer, size, wsocket_handeshake);
				return 2;
			}
		
		}
		else 
		{
			int msg_size = uc->msgsize + pack_size;
			if(msg_size > MAX_PACKSIZE)
			{
				skynet_free(uc);
				buffer += pack_size;
				size -= pack_size;
				int res = push_more(L, fd, buffer, size, wsocket_handeshake);
				return res;
			}
			else 
			{
				void * result = skynet_malloc(msg_size);
				int offset  = 0;
				for(int i =0; i < uc->cur_packet; ++i){
					memcpy(result + offset, uc->pack[i].buffer, uc->pack[i].size);
					offset = offset + uc->pack[i].size;
				}
				memcpy(result + offset, buffer, pack_size);
				push_data(L, fd, result, msg_size, 0);//不用拷贝

				skynet_free(uc);
				buffer += pack_size;
				size -= pack_size;
				push_more(L, fd, buffer, size, wsocket_handeshake);
				return 2;
			}
		}
	
	}
	else if(size > pack_size && fin == 0){
		struct uncomplete * uc = find_uncomplete(q, fd);
			if(uc == NULL){
				uc = save_uncomplete(L, fd);
			}
			else
			{
				int h = hash_fd(fd);
				uc->next = q->hash[h];
				q->hash[h] = uc;	
			}
			uc->read = -1;
            uc->mask = mask;
            uc->ismask = ismask;
			uc->fin = fin;
            uc->hasunmask_size = hasunmask_size;
			uc->pack[uc->cur_packet].size = pack_size;			
			uc->pack[uc->cur_packet].buffer = skynet_malloc(pack_size);
			decode_wsmask_data(buffer, pack_size, uc);
			memcpy(uc->pack[uc->cur_packet].buffer, buffer, pack_size);
			uc->msgsize = uc->msgsize + pack_size;
			uc->cur_packet++;

			buffer += pack_size;
			size -= pack_size;
			int res  = push_more(L, fd, buffer, size, wsocket_handeshake);
			return res;
	}
	return 1;
}

static void
close_uncomplete(lua_State *L, int fd) {
	struct queue *q = lua_touserdata(L,1);
	struct uncomplete * uc = find_uncomplete(q, fd);
	if (uc) {
		for(int i=0; i<=uc->cur_packet;i++)
		{
			skynet_free(uc->pack[i].buffer);
		}
		skynet_free(uc);
	}
}

int show_uc(struct uncomplete * uc)
{
	if(uc == NULL)return 0;
	for(int i=0; i<uc->cur_packet; ++i)
	{

	}
	return 0;
}

static int
filter_data_(lua_State *L, int fd, uint8_t * buffer, int size, int wsocket_handeshake) {
	struct queue *q = lua_touserdata(L,1);
	struct uncomplete * uc = find_uncomplete(q, fd);
    int pack_size = 0;
	int pack_head_length = 0;
    int mask = 0;
    int ismask = 0;
    int hasunmask_size = 0;
	int fin = 1;
	//一个uc可能是这些类型
	//1.帧长度未读出， 即read ==-1
	//2.帧长读完, 不完整的分帧 (fin=0,uc->read > 0)
	//3.帧长读完, 完整的的分帧 (fin=0,uc->read = 0) 
	//4.帧长读完, 不完整的最后帧(fin=1,uc->read > 0)
	if (uc) {
		//1.上一个uc中没有读出帧长度
		mask = uc->mask;
		ismask = uc->ismask; 
		hasunmask_size = uc->hasunmask_size;
		
		if (uc->read < 0) { 				   //1.帧长度未读出， 即read ==-1
			int index = 0;
			while (size > 0) {
				uc->header[uc->header_size] = buffer[index];
				index += 1;
				uc->header_size += 1;
				if (wsocket_handeshake) {
					pack_size = get_http_header(uc->header, uc->header_size);			
				}
				else {
					pack_size = read_size(uc->header, uc->header_size, &pack_head_length, &mask, &ismask, &hasunmask_size, &fin);
				}

				if (pack_size >= 0 || index >= size) {
					size -= index;
					buffer += index;
					break;
				} 
			}
			
			if (pack_size == -1) {			
				int h = hash_fd(fd);
				uc->next = q->hash[h];
				q->hash[h] = uc;
				return 1;			
			}
			//取得包头长度以后开始生成新包
			uc->pack[uc->cur_packet].buffer = skynet_malloc(pack_size);
			uc->pack[uc->cur_packet].size = pack_size;
			uc->mask = mask;
            uc->ismask = ismask;
            uc->hasunmask_size = hasunmask_size;
			

			//如果是握手协议则把header缓冲区的内容拷贝到缓冲区
            if (wsocket_handeshake) {
				//难道这俩会不相等吗???
				uc->read = uc->header_size < pack_size ? uc->header_size : pack_size;
				memcpy(uc->pack[uc->cur_packet].buffer, uc->header, uc->read);
				uc->fin = 1; //
            } 
            else {

            	uc->read = 0;
				uc->fin = fin;
            }
		}
		int need = uc->pack[uc->cur_packet].size - uc->read;
		if (size < need) {
           	decode_wsmask_data(buffer, size, uc);
			memcpy(uc->pack[uc->cur_packet].buffer + uc->read, buffer, size);
			uc->read += size;

			int h = hash_fd(fd);
			uc->next = q->hash[h];
			q->hash[h] = uc;
			return 1;
		}

		int hung_back = 1;
		if(uc->fin == 1 && uc->read >= 0) //4.如果是不完整的最后帧 变成完整的最后帧
		{
			decode_wsmask_data(buffer, need, uc);
			memcpy(uc->pack[uc->cur_packet].buffer + uc->read, buffer, need);
			uc->msgsize = uc->msgsize + uc->pack[uc->cur_packet].size;
			uc->cur_packet++;
	
			void * result = skynet_malloc(uc->msgsize);
			int offset  = 0;
			for(int i =0; i < uc->cur_packet; ++i){
				memcpy(result + offset, uc->pack[i].buffer, uc->pack[i].size);
				offset = offset + uc->pack[i].size;
				skynet_free(uc->pack[i].buffer);
			}
			buffer += need;
			size -= need;
			if(size > 0)
			{	
				//如果消息超过了最大帧长度
				if(uc->msgsize > MAX_PACKSIZE)
				{
					skynet_free(uc);
					int res = push_more(L,fd,buffer, size,wsocket_handeshake);
					if(res ==2)
					{
						lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
						return 2;	
					}
					return 1;
				}
				else 
				{
					push_data(L,fd,result,uc->msgsize, 0);
					skynet_free(uc);

					push_more(L,fd,buffer, size,wsocket_handeshake);
					lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
					return 2;
				}
			
			}
			else
			{	
				if(uc->msgsize > MAX_PACKSIZE) 
				{
					skynet_free(uc);
					return 1;
				}
				lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
				lua_pushinteger(L, fd);
				lua_pushlightuserdata(L, result);
				lua_pushinteger(L, uc->msgsize);
				skynet_free(uc);
				return 5;
			}
		}
		else if(uc->fin == 0 && uc->read >= 0)  // 如果是不完整分帧先把不完整的分帧 先变成完整的分帧
		{	
			//没有read过时 mask是取自原来的
			decode_wsmask_data(buffer, need, uc);
			memcpy(uc->pack[uc->cur_packet].buffer + uc->read, buffer, need);
			uc->msgsize = uc->msgsize  + uc->pack[uc->cur_packet].size;
			uc->cur_packet++;
			uc->read = -1;  //就是这个地方吧
			

			int h = hash_fd(fd);
			uc->next = q->hash[h];
			q->hash[h] = uc;
			hung_back = 0;

			buffer += need;
			size -= need;
		}
		if(hung_back == 1)
		{
			int h = hash_fd(fd);
			uc->next = q->hash[h];
			q->hash[h] = uc;
		}
		if(size > 0)
		{
			int res = push_more(L, fd, buffer, size, wsocket_handeshake);
			if(res == 2)
			{
				lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
				return 2;
			}
		}
		return 1;
	} else {
		if (wsocket_handeshake) {
			pack_size = get_http_header(buffer, size);
		}
		else {
			//读取帧大小
			pack_size = read_size(buffer, size, &pack_head_length, &mask, &ismask, &hasunmask_size, &fin);
		}

		//1.该数据帧头还未读出来
		if (pack_size == -1) {		
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = -1;
			uc->header_size += size;
			memcpy(uc->header, buffer, size);
			return 1;			
		}
		//数据帧头大小
		buffer+=pack_head_length;
		size-=pack_head_length;
		//不够一个帧
		if (size < pack_size && !wsocket_handeshake) {
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = size;
            uc->mask = mask;
            uc->ismask = ismask;
			uc->fin = fin;
            uc->hasunmask_size = hasunmask_size;
			uc->pack[uc->cur_packet].size = pack_size;			
			uc->pack[uc->cur_packet].buffer = skynet_malloc(pack_size);
			decode_wsmask_data(buffer, size, uc);
			memcpy(uc->pack[uc->cur_packet].buffer, buffer, size);
			return 1;
		}

		struct uncomplete uc;
		memset(&uc, 0, sizeof(uc));
		uc.mask = mask;
		uc.ismask = ismask;
		uc.hasunmask_size = hasunmask_size;
		
		if (size == pack_size && fin == 1) {
			if(pack_size > MAX_PACKSIZE){
				return 1;
			}
			lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
			lua_pushinteger(L, fd);
			void * result = skynet_malloc(pack_size);
			decode_wsmask_data(buffer, size, &uc);			
			memcpy(result, buffer, size);
			lua_pushlightuserdata(L, result);
			lua_pushinteger(L, size);
			return 5;
		}
		else if(size == pack_size && fin == 0)
		{
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = -1;
            uc->mask = mask;
            uc->ismask = ismask;
			uc->fin = fin;
            uc->hasunmask_size = hasunmask_size;
			uc->pack[uc->cur_packet].size = pack_size;			
			uc->pack[uc->cur_packet].buffer = skynet_malloc(pack_size);
			decode_wsmask_data(buffer, pack_size, uc);
			memcpy(uc->pack[uc->cur_packet].buffer, buffer, pack_size);
			uc->msgsize = uc->msgsize + pack_size;
			uc->cur_packet++;
			return 1;
		}
		else if(size > pack_size && fin == 1)
		{
			if(pack_size > MAX_PACKSIZE){
				buffer += pack_size;
				size -= pack_size;
				int res = push_more(L, fd, buffer, size, wsocket_handeshake);
				if (res == 2){
					lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
					return 2;
				}
				return 1;
			}
			else 
			{
				decode_wsmask_data(buffer, pack_size, &uc);
				push_data(L, fd, buffer, pack_size, 1);
				buffer += pack_size;
				size -= pack_size;
				push_more(L, fd, buffer, size, wsocket_handeshake);
				lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
				return 2;
			}
		}
		else if (size > pack_size && fin == 0)
		{
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = -1;
            uc->mask = mask;
            uc->ismask = ismask;
			uc->fin = fin;
            uc->hasunmask_size = hasunmask_size;
			uc->pack[uc->cur_packet].size = pack_size;			
			uc->pack[uc->cur_packet].buffer = skynet_malloc(pack_size);
			decode_wsmask_data(buffer, pack_size, uc);
			memcpy(uc->pack[uc->cur_packet].buffer, buffer, pack_size);
			uc->msgsize = uc->msgsize + pack_size;
			uc->cur_packet++;

			buffer += pack_size;
			size -= pack_size;
			int res = push_more(L, fd, buffer, size, wsocket_handeshake);
			if(res == 2)
			{
				lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
				return 2;
			}
			return 1;
		}
	}
	return 1;
}

static inline int
filter_data(lua_State *L, int fd, uint8_t * buffer, int size, int wsocket_handeshake) {
	int ret = filter_data_(L, fd, buffer, size, wsocket_handeshake);
	// buffer is the data of socket message, it malloc at socket_server.c : function forward_message .
	// it should be free before return,
	skynet_free(buffer);
	return ret;
}

static void
pushstring(lua_State *L, const char * msg, int size) {
	if (msg) {
		lua_pushlstring(L, msg, size);
	} else {
		lua_pushliteral(L, "");
	}
}

/*
	userdata queue
	lightuserdata msg
	integer size
	return
		userdata queue
		integer type
		integer fd
		string msg | lightuserdata/integer
 */
static int
lfilter(lua_State *L) {
	struct skynet_socket_message *message = lua_touserdata(L,2);
	int size = luaL_checkinteger(L,3);
	int wsocket_handeshake = luaL_checkinteger(L,4);
	char * buffer = message->buffer;
	if (buffer == NULL) {
		buffer = (char *)(message+1);
		size -= sizeof(*message);
	} else {
		size = -1;
	}

	lua_settop(L, 1);

	switch(message->type) {
	case SKYNET_SOCKET_TYPE_DATA:
		// ignore listen id (message->id)
		assert(size == -1);	// never padding string
		return filter_data(L, message->id, (uint8_t *)buffer, message->ud, wsocket_handeshake);
	case SKYNET_SOCKET_TYPE_CONNECT:
		// ignore listen fd connect
		return 1;
	case SKYNET_SOCKET_TYPE_CLOSE:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_CLOSE));
		lua_pushinteger(L, message->id);
		return 3;
	case SKYNET_SOCKET_TYPE_ACCEPT:
		lua_pushvalue(L, lua_upvalueindex(TYPE_OPEN));
		// ignore listen id (message->id);
		lua_pushinteger(L, message->ud);
		pushstring(L, buffer, size);
		return 4;
	case SKYNET_SOCKET_TYPE_ERROR:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_ERROR));
		lua_pushinteger(L, message->id);
		pushstring(L, buffer, size);
		return 4;
	case SKYNET_SOCKET_TYPE_WARNING:
		lua_pushvalue(L, lua_upvalueindex(TYPE_WARNING));
		lua_pushinteger(L, message->id);
		lua_pushinteger(L, message->ud);
		return 4;
	default:
		// never get here
		return 1;
	}
}

/*
	userdata queue
	return
		integer fd
		lightuserdata msg
		integer size
 */
static int
lpop(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL || q->head == q->tail)
		return 0;
	struct netpack *np = &q->queue[q->head];
	if (++q->head >= q->cap) {
		q->head = 0;
	}

	lua_pushinteger(L, np->id);
	lua_pushlightuserdata(L, np->buffer);
	lua_pushinteger(L, np->size);

	return 3;
}

/*
	string msg | lightuserdata/integer

	lightuserdata/integer
 */

static const char *
tolstring(lua_State *L, size_t *sz, int index) {
	const char * ptr;
	if (lua_isuserdata(L,index)) {
		ptr = (const char *)lua_touserdata(L,index);
		*sz = (size_t)luaL_checkinteger(L, index+1);
	} else {
		ptr = luaL_checklstring(L, index, sz);
	}
	return ptr;
}

#define FRAME_SET_FIN(BYTE) (((BYTE) & 0x01) << 7)
#define FRAME_SET_OPCODE(BYTE) ((BYTE) & 0x0F)
#define FRAME_SET_MASK(BYTE) (((BYTE) & 0x01) << 7)
#define FRAME_SET_LENGTH(X64, IDX) (unsigned char)(((X64) >> ((IDX)*8)) & 0xFF)

static int
lpack(lua_State *L) {
	size_t len;
	const char * ptr = tolstring(L, &len, 1);

	int pos = 0;
    char frame_header[16];

    frame_header[pos++] = FRAME_SET_FIN(1) | FRAME_SET_OPCODE(2);
    if (len < 126)
    {
        frame_header[pos++] = FRAME_SET_MASK(0) | FRAME_SET_LENGTH(len, 0);
    }
    else
    {
        if (len < 65536)
        {
            frame_header[pos++] = FRAME_SET_MASK(0) | 126;
        }
        else
        {
            frame_header[pos++] = FRAME_SET_MASK(0) | 127;
            frame_header[pos++] = FRAME_SET_LENGTH(len, 7);
            frame_header[pos++] = FRAME_SET_LENGTH(len, 6);
            frame_header[pos++] = FRAME_SET_LENGTH(len, 5);
            frame_header[pos++] = FRAME_SET_LENGTH(len, 4);
            frame_header[pos++] = FRAME_SET_LENGTH(len, 3);
            frame_header[pos++] = FRAME_SET_LENGTH(len, 2);
        }
        frame_header[pos++] = FRAME_SET_LENGTH(len, 1);
        frame_header[pos++] = FRAME_SET_LENGTH(len, 0);
    }
		
	uint8_t * buffer = skynet_malloc(len + pos);
	memcpy(buffer, frame_header, pos);
	memcpy(buffer+pos, ptr, len);

	lua_pushlightuserdata(L, buffer);
	lua_pushinteger(L, len + pos);

	return 2;
}

static int
ltostring(lua_State *L) {
	void * ptr = lua_touserdata(L, 1);
	int size = luaL_checkinteger(L, 2);
	if (ptr == NULL) {
		lua_pushliteral(L, "");
	} else {
		lua_pushlstring(L, (const char *)ptr, size);
		skynet_free(ptr);
	}
	return 1;
}

int
luaopen_websocketnetpack(lua_State *L) {
	luaL_checkversion(L);
    luaL_Reg l[] = {
        { "pop", lpop },
        { "pack", lpack },
        { "clear", lclear },
        { "tostring", ltostring },
        { NULL, NULL },
    };
    luaL_newlib(L,l);

    // the order is same with macros : TYPE_* (defined top)
    lua_pushliteral(L, "data");
    lua_pushliteral(L, "more");
    lua_pushliteral(L, "error");
    lua_pushliteral(L, "open");
    lua_pushliteral(L, "close");
    lua_pushliteral(L, "warning");
    lua_pushcclosure(L, lfilter, 6);
    lua_setfield(L, -2, "filter");
    return 1;
}	
