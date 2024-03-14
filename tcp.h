#ifndef __TCP_H__
#define __TCP_H__

#include "common.h"

int tcp_process(struct rte_mbuf *pstTcpMbuf);
int tcp_out(struct rte_mempool *pstMbufPool);
//send window management packet
// int window_link_pushback(struct tcp_window *window, struct tcp_fragment *fragment);
// int window_link_popfront(struct tcp_window *window, struct rte_tcp_hdr *pstTcphdr);
int tcp_window_handle(uint32_t time);

// 11种tcp连接状态
typedef enum _ENUM_TCP_STATUS 
{
	TCP_STATUS_CLOSED = 0,
	TCP_STATUS_LISTEN,
	TCP_STATUS_SYN_RCVD,
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,

	TCP_STATUS_FIN_WAIT_1,
	TCP_STATUS_FIN_WAIT_2,
	TCP_STATUS_CLOSING,
	TCP_STATUS_TIME_WAIT,

	TCP_STATUS_CLOSE_WAIT,
	TCP_STATUS_LAST_ACK

}TCP_STATUS;

// tcb control block tcp连接控制块 存储方向规定 server <==tcp_stream== client
//tcb stream 使用双向链表数据结构存储
struct tcp_stream 
{ 
	int fd; //文件描述符

	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	
	uint8_t protocol;
	
	uint16_t sport;
	uint32_t sip;

	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum
	//11种状态
	TCP_STATUS status;

	struct rte_ring *sndbuf; //send buff
	struct rte_ring *rcvbuf; //recd buff
	struct rte_ring *windbuf; //window_management_buffer
	//双向链表指针
	struct tcp_stream *prev;
	struct tcp_stream *next;
	//信号量
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	//滑动窗口控制块
	struct tcp_window * window;
};


//TODO 将半连接链表和全连接链表分别管理，目前都存储在tcp_table中
struct tcp_table 
{
	int count;
	//struct tcp_stream *listener_set;	// 半连接链表
#if ENABLE_SINGLE_EPOLL 
	struct eventpoll *ep; // single epoll
#endif
	struct tcp_stream *tcb_set;  //全连接链表
};
//tcp报文
struct tcp_fragment 
{ 
	uint16_t sport;  
	uint16_t dport;  
	uint32_t seqnum;  
	uint32_t acknum;  
	uint8_t  hdrlen_off;  
	uint8_t  tcp_flags; 
	uint16_t windows;   
	uint16_t cksum;     
	uint16_t tcp_urp;  

	int optlen;
	uint32_t option[D_TCP_OPTION_LENGTH];

	unsigned char *data;
	uint32_t length;
};

//滑动窗口
struct tcp_window 
{
	uint32_t window_size;//窗口大小
	uint32_t window_used;//已使用窗口大小
	uint32_t timeout;//超时时间,表示窗口内首个报文的超时时间 毫秒级
	//两个指针，分别指向窗口的首部和尾部，滑动窗口使用链表实现
	struct tcp_packet_node* head;//表示窗口的首部，#2的第一个tcp_packet_node,窗口内已发送但未收到ack的报文
	struct tcp_packet_node* tail;//表示窗口的尾部，窗口内最后一个tcp报文

};
//滑动窗口中tcp报文单向链表节点
struct tcp_packet_node 
{
	struct tcp_fragment *fragment;
	struct tcp_packet_node *next;
};

#endif
