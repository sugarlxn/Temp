#ifndef __UDP_H__
#define __UDP_H__

#include "common.h"

int udp_process(struct rte_mbuf *pstUdpMbuf);
int udp_out(struct rte_mempool *mbuf_pool);

/*udp控制块是在应用层创建socket的同时生成的，主要包含一个发送队列和接收队列，线程同步变量等*/
// udp control block
struct localhost 
{	
	//fd文件描述符
	int fd;

	//unsigned int status; //
	uint32_t localip; // ip --> mac
	unsigned char localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;

	unsigned char protocol;

	struct rte_ring *sndbuf; //udp控制块发送队列
	struct rte_ring *rcvbuf; //udp控制块接收队列

	struct localhost *prev; //双向链表 前项指针
	struct localhost *next; //双向链表 后项指针

	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

/*传输块作为协议栈向UDP应用通信的数据封装，DPDK协议栈在收到网卡发送的数据后
，按照传输块的结构来封装数据，并发送到UDP控制块中的接收队列
*/
//udp 传输块
struct offload 
{ 
	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport; 

	int protocol;

	unsigned char *data;
	uint16_t length;
	
}; 

#endif