#include "tcp.h"

//创建tcp连接条目 创建一条stream 通过四元组建立
static struct tcp_stream * tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{ 
    char acBufname[32] = {0}; //buffer name 
    unsigned int uiSeed;
    struct tcp_stream *pstStream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
	if (pstStream == NULL){ 
        return NULL;
	}

	
	printf("tcp_stream_create!\n");

    pstStream->sip = sip;
    pstStream->dip = dip;
    pstStream->sport = sport;
    pstStream->dport = dport;
    pstStream->protocol = IPPROTO_TCP;
    pstStream->fd = -1; //表示该连接未被使用 unused
    pstStream->status = TCP_STATUS_LISTEN;

	//dpdk ring 要求ringbuffer的名字是唯一的
	//创建sndbuf rcvbuf windbuf
    sprintf(acBufname, "sndbuf%x%d", sip, sport);
	pstStream->sndbuf = rte_ring_create(acBufname, D_RING_SIZE, rte_socket_id(), 0);
	sprintf(acBufname, "rcvbuf%x%d", sip, sport);
	pstStream->rcvbuf = rte_ring_create(acBufname, D_RING_SIZE, rte_socket_id(), 0);
	//windbuf
	sprintf(acBufname, "windbuf%x%d", sip, sport);
	pstStream->windbuf = rte_ring_create(acBufname, D_RING_SIZE, rte_socket_id(), 0);


    // seq num
	uiSeed = time(NULL);
	pstStream->snd_nxt = rand_r(&uiSeed) % D_TCP_MAX_SEQ;
	rte_memcpy(pstStream->localmac, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
	
	//条件信号量与互斥信号量初始化
	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&pstStream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&pstStream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	//发送窗口初始化
	pstStream->window = (struct tcp_window *)rte_malloc("tcp_window", sizeof(struct tcp_window), 0);
	if (pstStream->window == NULL)
	{
		printf("tcp_stream_create window malloc failed\n");
		rte_ring_free(pstStream->sndbuf);
		rte_ring_free(pstStream->rcvbuf);
		rte_free(pstStream);
		return NULL;
	}
	pstStream->window->window_size = D_TCP_INITIAL_WINDOW;
	pstStream->window->window_used = 0;
	pstStream->window->head = NULL;
	pstStream->window->tail = NULL;

    return pstStream;
}

//tcp协议发送ack包 数据部分为空
static int ng_tcp_send_ackpkt(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL){
		return -1;
	}
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
	// printf("tcp_send_ackpkt: %d, %d\n", pstStream->rcv_nxt, pstStream->snd_nxt);
	
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG;
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

	return 0;
}

//tcp协议发送FIN+ACK包 数据部分为空
static int ng_tcp_send_fin_ackpkt(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL){
		return -1;
	}
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
	// printf("tcp_send_ackpkt: %d, %d\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
	
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG;
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

	return 0;
}

//tcp协议状态迁移 listen->syn-revd
static int tcp_handle_listen(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, 
                                struct rte_ipv4_hdr *pstIphdr) 
{
    if (pstTcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  
    {
        if (pstStream->status == TCP_STATUS_LISTEN)
        {
			//创建tcp stream 新建一条连接，并插入到tcp建联表中
            struct tcp_stream *pstSyn = tcp_stream_create(pstIphdr->src_addr, pstIphdr->dst_addr, 
                                                            pstTcphdr->src_port, pstTcphdr->dst_port);
			LL_ADD(pstSyn, g_pstTcpTbl->tcb_set);
			//发送SYN+ACK
            struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
			if (pstFragment == NULL) 
                return -1;
			memset(pstFragment, 0, sizeof(struct tcp_fragment));

            pstFragment->sport = pstTcphdr->dst_port;
			pstFragment->dport = pstTcphdr->src_port;

            struct in_addr addr;
			addr.s_addr = pstSyn->sip;
			// printf("tcp ---> src: %s:%d ", inet_ntoa(addr), ntohs(pstTcphdr->src_port));

			addr.s_addr = pstSyn->dip;
			// printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(pstTcphdr->dst_port));

            pstFragment->seqnum = pstSyn->snd_nxt;
			pstFragment->acknum = ntohl(pstTcphdr->sent_seq) + 1;
			pstSyn->rcv_nxt = pstFragment->acknum;
			
			pstFragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			pstFragment->windows = D_TCP_INITIAL_WINDOW;
			pstFragment->hdrlen_off = 0x50; //网络字节 低位在前 高位在后(大端存储)
			
			pstFragment->data = NULL;
			pstFragment->length = 0;

			rte_ring_mp_enqueue(pstSyn->sndbuf, pstFragment);
			
			pstSyn->status = TCP_STATUS_SYN_RCVD;
        }
    }

    return 0;
}

static int tcp_handle_syn_rcvd(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr)
{
	if (pstTcphdr->tcp_flags & RTE_TCP_ACK_FLAG) 
	{
		if (pstStream->status == TCP_STATUS_SYN_RCVD) 
		{
			uint32_t acknum = ntohl(pstTcphdr->recv_ack);
			if (acknum == pstStream->snd_nxt + 1) 
			{
				printf("ack response success!\n");
			}
			else
			{
				printf("ack response error! \n");
			}

			pstStream->status = TCP_STATUS_ESTABLISHED;

			// accept 查找tcp stream对应的listen fd 
			struct tcp_stream *pstListener = tcp_stream_search(0, 0, 0, pstStream->dport);
			if (pstListener == NULL) 
			{
				rte_exit(EXIT_FAILURE, "tcp_stream_search pstlistener failed\n");
			}

			//唤醒accept中的等待
			pthread_mutex_lock(&pstListener->mutex);
			pthread_cond_signal(&pstListener->cond);   // 唤醒accept中的等待
			pthread_mutex_unlock(&pstListener->mutex);

#if ENABLE_SINGLE_EPOLL
			//轮询回调函数调用
			struct tcp_table *table = tcpInstance();
			epoll_event_callback(table->ep, pstListener->fd, EPOLLIN);
#endif
		}
	}

	return 0;
}

static int tcp_handle_syn_sent(struct tcp_stream * pstTcpStream, struct rte_tcp_hdr * pstTcpHdr){
	if(pstTcpHdr->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)){
		if(pstTcpStream->status == TCP_STATUS_SYN_SENT){

			uint32_t acknum = ntohl(pstTcpHdr->recv_ack);
			if(acknum == pstTcpStream->snd_nxt + 1){
				printf("ack response success!\n");
			}
			else{
				printf("ack response error! \n");
			}

			pstTcpStream->snd_nxt = ntohl(pstTcpHdr->recv_ack);
			pstTcpStream->rcv_nxt = ntohl(pstTcpHdr->sent_seq) + 1;
			//发送ack
			ng_tcp_send_ackpkt(pstTcpStream, pstTcpHdr);

			pstTcpStream->status = TCP_STATUS_ESTABLISHED;

			//唤醒connect中的等待
			pthread_mutex_lock(&pstTcpStream->mutex);
			pthread_cond_signal(&pstTcpStream->cond);   // 唤醒connect中的等待
			pthread_mutex_unlock(&pstTcpStream->mutex);
		}
	}
	return 0;

}

static int ng_tcp_enqueue_recvbuffer(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int iTcplen) 
{
	struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstFragment == NULL) 
		return -1;

	memset(pstFragment, 0, sizeof(struct tcp_fragment));
	pstFragment->dport = ntohs(pstTcphdr->dst_port);
	pstFragment->sport = ntohs(pstTcphdr->src_port);

	// data_off：前4位表示包头到数据域起始位置之间的大小
	// 每一位表示4Byte，最大表示为 15*4Byte 大小
	uint8_t hdrlen = pstTcphdr->data_off >> 4;   
	int payloadlen = iTcplen - hdrlen * 4; // 数据域长度
#if ENABLE_DEBUG
	if (pstTcphdr->tcp_flags & RTE_TCP_FIN_FLAG) 
		printf("iTcplen = %d\n", iTcplen);
	printf("payloadlen = %d\n", payloadlen);
#endif

	if(payloadlen > 0)
	{
		uint8_t *payload = (uint8_t*)pstTcphdr + hdrlen * 4;

		pstFragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
		if (pstFragment->data == NULL) 
		{
			rte_free(pstFragment);
			return -1;
		}

		memset(pstFragment->data, 0, payloadlen + 1);
		rte_memcpy(pstFragment->data, payload, payloadlen);
		pstFragment->length = payloadlen;
	}
	else if(payloadlen == 0)
	{
		pstFragment->length = 0;
		pstFragment->data = NULL;
	}

	rte_ring_mp_enqueue(pstStream->rcvbuf, pstFragment);

	pthread_mutex_lock(&pstStream->mutex);
	pthread_cond_signal(&pstStream->cond); //唤醒nrecv函数中请求rcvbuf的等待
	pthread_mutex_unlock(&pstStream->mutex);

	return 0;
}


static int tcp_handle_established(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int iTcplen) 
{
	if (pstTcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  // 异常：收到对端的SYN重传包
	{
		// printf("RTE_TCP_SYN_FLAG\n");
	} 
	if(pstTcphdr->tcp_flags & RTE_TCP_PSH_FLAG )  // 收到对端的数据包，TCP数据域不为0
	{
		// printf("RTE_TCP_PSH_FLAG\n");
		ng_tcp_enqueue_recvbuffer(pstStream, pstTcphdr, iTcplen);
		
#if ENABLE_SINGLE_EPOLL
		//调用epoll回调函数
		struct tcp_table * table = tcpInstance();
		epoll_event_callback(table->ep, pstStream->fd, EPOLLIN);
#endif

		uint8_t hdrlen = pstTcphdr->data_off >> 4;
		int payloadlen = iTcplen - hdrlen * 4;
		
		//更新rcv_nxt snd_nxt 
		pstStream->rcv_nxt = pstStream->rcv_nxt + payloadlen;
		pstStream->snd_nxt = ntohl(pstTcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(pstStream, pstTcphdr);
	}
	
	if(pstTcphdr->tcp_flags & RTE_TCP_ACK_FLAG)  //收到对端的ACK包，ACK有效标志
	{
		// printf("RTE_TCP_ACK_FLAG\n");

#if ENABLE_WINDOW_MANAGE
		//TODO 窗口管理释放窗口头部数据包
		int ret = window_link_popfront(pstStream->window, pstTcphdr);

#endif


	}
	if (pstTcphdr->tcp_flags & RTE_TCP_FIN_FLAG)  // 对端关闭连接
	{
		// printf("RTE_TCP_FIN_FLAG\n");
		pstStream->status = TCP_STATUS_CLOSE_WAIT;

		ng_tcp_enqueue_recvbuffer(pstStream, pstTcphdr, pstTcphdr->data_off >> 4);

#if ENABLE_SINGLE_EPOLL
		//回调函数
		struct tcp_table *table = tcpInstance();
		epoll_event_callback(table->ep, pstStream->fd, EPOLLIN);

#endif
		// send ack ptk
		pstStream->rcv_nxt = (pstStream->rcv_nxt + 1);
		pstStream->snd_nxt = ntohl(pstTcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(pstStream, pstTcphdr);
		
	}

	return 0;
}

static int tcp_hadle_fin_wait_1(struct tcp_stream * pstTcpStream,struct rte_tcp_hdr * pstTcpHdr){
	if(pstTcpHdr->tcp_flags & RTE_TCP_ACK_FLAG){
		if(pstTcpStream->status == TCP_STATUS_FIN_WAIT_1){
			//状态变为FIN_WAIT_2
			pstTcpStream->status = TCP_STATUS_FIN_WAIT_2;
		}
	}
	return 0;
}


static int tcp_hadle_fin_wait_2(struct tcp_stream * pstTcpStream,struct rte_tcp_hdr * pstTcpHdr)
{
	if(pstTcpHdr->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG)){
		if(pstTcpStream->status == TCP_STATUS_FIN_WAIT_2){
			
			//发送ACK
			pstTcpStream->rcv_nxt = pstTcpStream->rcv_nxt+1; 
			pstTcpStream->snd_nxt = pstTcpStream->snd_nxt+1;
			int ret = ng_tcp_send_ackpkt(pstTcpStream, pstTcpHdr);
			// printf("ret=%d\n",ret);
			
			//FIXME 等待2MSL


			pstTcpStream->status = TCP_STATUS_CLOSING;
			//唤醒nclose_tcp_client中的等待
			pthread_mutex_lock(&pstTcpStream->mutex);
			pthread_cond_signal(&pstTcpStream->cond);
			pthread_mutex_unlock(&pstTcpStream->mutex);

			// //释放资源 
			// //BUG 报错Segmentation fault
			// LL_REMOVE(pstTcpStream, g_pstTcpTbl->tcb_set);
			// rte_ring_free(pstTcpStream->sndbuf);
			// rte_ring_free(pstTcpStream->rcvbuf);
			// rte_free(pstTcpStream);
			// printf("tcp_handle_fin_wait_2 stream_client close\n");
		}
	}
	return 0;
}

//TODO被动关闭 tcp close wait -(关闭，发送FIN)-> last ack -(收到ack)-> closed
static int tcp_handle_close_wait(struct tcp_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) //收到重复FIN包
	{ 
		if (stream->status == TCP_STATUS_CLOSE_WAIT) 
		{	
			
		}
	}
	
	return 0;
}

static int tcp_handle_last_ack(struct tcp_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) 
	{
		if (stream->status == TCP_STATUS_LAST_ACK) 
		{
			stream->status = TCP_STATUS_CLOSED;
			printf("tcp_handle_last_ack stream close\n");
			
			LL_REMOVE(stream, g_pstTcpTbl->tcb_set);
			//释放资源
			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);
			rte_free(stream->window);
			rte_free(stream);
		}
	}

	return 0;
}

int tcp_process(struct rte_mbuf *pstTcpMbuf) 
{
    struct rte_ipv4_hdr *pstIpHdr;
    struct rte_tcp_hdr *pstTcpHdr;
    struct tcp_stream *pstTcpStream;
    unsigned short usOldTcpCkSum;
    unsigned short usNewTcpCkSum;

    pstIpHdr = rte_pktmbuf_mtod_offset(pstTcpMbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    pstTcpHdr = (struct rte_tcp_hdr *)(pstIpHdr + 1);

    // 校验和
    usOldTcpCkSum = pstTcpHdr->cksum;
    pstTcpHdr->cksum = 0;
    usNewTcpCkSum = rte_ipv4_udptcp_cksum(pstIpHdr, pstTcpHdr);
    if (usOldTcpCkSum != usNewTcpCkSum) 
    { 
		printf("cksum: %x, tcp cksum: %x\n", usOldTcpCkSum, usNewTcpCkSum);
		rte_pktmbuf_free(pstTcpMbuf);
		return -1;
	}

	// 搜索涵盖了半连接队列和全连接队列
	// 搜索的stream，根据status状态调用对应处理函数
    pstTcpStream = tcp_stream_search(pstIpHdr->src_addr, pstIpHdr->dst_addr, 
        pstTcpHdr->src_port, pstTcpHdr->dst_port);
    if (pstTcpStream == NULL) 
    { 
        // puts("no tcb create!");
		rte_pktmbuf_free(pstTcpMbuf);
		return -2;
	}

    switch(pstTcpStream->status)
    {
        case TCP_STATUS_CLOSED: //client 
			break;
			
		case TCP_STATUS_LISTEN: // server
			tcp_handle_listen(pstTcpStream, pstTcpHdr, pstIpHdr);
			break;

		case TCP_STATUS_SYN_RCVD: // server
			tcp_handle_syn_rcvd(pstTcpStream, pstTcpHdr);
			break;

		case TCP_STATUS_SYN_SENT: // client
			tcp_handle_syn_sent(pstTcpStream, pstTcpHdr);
			break;

		case TCP_STATUS_ESTABLISHED:  // server | client
		{ 
			int tcplen = ntohs(pstIpHdr->total_length) - sizeof(struct rte_ipv4_hdr);
			tcp_handle_established(pstTcpStream, pstTcpHdr, tcplen);
			// printf("tcplen = %d\n", tcplen);
			break;
		}
		case TCP_STATUS_FIN_WAIT_1: //  ~client
			// printf("tcp_handle_fin_wait_1\n");
			tcp_hadle_fin_wait_1(pstTcpStream, pstTcpHdr);
			break;
			
		case TCP_STATUS_FIN_WAIT_2: // ~client
			// printf("tcp_handle_fin_wait_2\n");
			tcp_hadle_fin_wait_2(pstTcpStream, pstTcpHdr);
			break;
			
		case TCP_STATUS_CLOSING: // ~client
			break;
			
		case TCP_STATUS_TIME_WAIT: // ~client
			break;

		case TCP_STATUS_CLOSE_WAIT: // ~server
			//收到重复FIN包
			tcp_handle_close_wait(pstTcpStream, pstTcpHdr);
			break;
			
		case TCP_STATUS_LAST_ACK:  // ~server
			tcp_handle_last_ack(pstTcpStream, pstTcpHdr);
			break;
    }
	//释放mbuf
	rte_pktmbuf_free(pstTcpMbuf);
    return 0;
}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment, unsigned int total_len) 
{
	struct rte_ether_hdr *pstEth;
	struct rte_ipv4_hdr *pstIp;
	struct rte_tcp_hdr *pstTcp;

	// 1 ethhdr
	pstEth = (struct rte_ether_hdr *)msg;
	rte_memcpy(pstEth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(pstEth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	pstEth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	
	// 2 iphdr 
	pstIp = (struct rte_ipv4_hdr *)(pstEth + 1);
	pstIp->version_ihl = 0x45;
	pstIp->type_of_service = 0;
	pstIp->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	pstIp->packet_id = 0;
	pstIp->fragment_offset = 0;
	pstIp->time_to_live = 64; // ttl = 64
	pstIp->next_proto_id = IPPROTO_TCP;
	pstIp->src_addr = sip;
	pstIp->dst_addr = dip;
	pstIp->hdr_checksum = 0;
	pstIp->hdr_checksum = rte_ipv4_cksum(pstIp);

	// 3 tcphdr 
	pstTcp = (struct rte_tcp_hdr *)(pstIp + 1);
	pstTcp->src_port = fragment->sport;
	pstTcp->dst_port = fragment->dport;
	pstTcp->sent_seq = htonl(fragment->seqnum);
	pstTcp->recv_ack = htonl(fragment->acknum);
	pstTcp->data_off = fragment->hdrlen_off;
	pstTcp->rx_win = fragment->windows;
	pstTcp->tcp_urp = fragment->tcp_urp;
	pstTcp->tcp_flags = fragment->tcp_flags;
	if (fragment->data != NULL) 
	{
		uint8_t *payload = (uint8_t*)(pstTcp + 1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}
	pstTcp->cksum = 0;
	pstTcp->cksum = rte_ipv4_udptcp_cksum(pstIp, pstTcp);

	return 0;
}


static struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment) 
{
	unsigned int uiTotalLen;
	struct rte_mbuf *pstMbuf;
    unsigned char *pucPktData;

	uiTotalLen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t) + fragment->length;  
	
	pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	
	pstMbuf->pkt_len = uiTotalLen;
    pstMbuf->data_len = uiTotalLen;
    pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char*);

	ng_encode_tcp_apppkt(pucPktData, sip, dip, srcmac, dstmac, fragment, uiTotalLen);

	return pstMbuf;
}

int tcp_out(struct rte_mempool *pstMbufPool) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_stream *pstStream = NULL;
	for(pstStream = pstTable->tcb_set; pstStream != NULL; pstStream = pstStream->next)
	{
		if(pstStream->sndbuf == NULL){ //此时是一个半连接 listener fd 没有sndbuf 和 recvbuf
			continue;
		}

		struct tcp_fragment *pstFragment = NULL;		
		int iSendCnt = rte_ring_mc_dequeue(pstStream->sndbuf, (void**)&pstFragment);
		if (iSendCnt < 0){ 
			continue;
		}

		// struct in_addr addr;
		// addr.s_addr = pstStream->sip;

		// printf("tcp_out ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(pstFragment->dport));

		
		uint8_t *dstmac = ng_get_dst_macaddr(pstStream->sip); //这里的源ip指的是对端ip 

		if (dstmac == NULL)  // 先广播发个arp包确定对端mac地址 
		{
			printf("ng_send_arp\n");
			struct rte_mbuf *pstArpbuf = ng_send_arp(pstMbufPool, RTE_ARP_OP_REQUEST, g_aucDefaultArpMac, 
				pstStream->dip, pstStream->sip);

			struct St_InOut_Ring * pst_ringbuf = g_pstRingIns;
			rte_ring_mp_enqueue_burst(pst_ringbuf->pstOutRing, (void **)&pstArpbuf, 1, NULL);

			rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);  // 将取出的数据再次放入队列
		} 
		else 
		{
			
			struct rte_mbuf *pstTcpBuf = ng_tcp_pkt(pstMbufPool, pstStream->dip, pstStream->sip, 
												pstStream->localmac, dstmac, pstFragment);

			struct St_InOut_Ring * pst_ringbuf = g_pstRingIns;
			rte_ring_mp_enqueue_burst(pst_ringbuf->pstOutRing, (void **)&pstTcpBuf, 1, NULL);

			/*solution 1 sigal tcp stream 的send buff*/
#if ENABLE_WINDOW_MANAGE
			//here is the window management aera

#else
			if (pstFragment->data != NULL){
				rte_free(pstFragment->data);
			}
			
			rte_free(pstFragment);
#endif

		}
	}

    return 0;
}

#if ENABLE_WINDOW_MANAGE
//TODO tcp接收窗口管理函数-popfront
int window_link_popfront(struct tcp_window *window, struct rte_tcp_hdr *pstTcphdr){
	//检查window节点是否存在tcphdr 的 acknum
	if(window->head == NULL){ //若窗口为空则返回
		return -1;
	}
	struct tcp_window *tcpwindow = window;
	struct tcp_packet_node* packet_node =NULL;
	while(tcpwindow->head != NULL){
		packet_node=tcpwindow->head;
		uint32_t mysequce =packet_node->fragment->seqnum + packet_node->fragment->length;
		if(mysequce < ntohl(pstTcphdr->recv_ack)){
			//释放数据包
			tcpwindow->window_used -= packet_node->fragment->length;

			if(tcpwindow->head == tcpwindow->tail){ //表示只有一个节点，窗口只有一个节点
				tcpwindow->head = NULL;
				tcpwindow->tail = NULL;
			}else{
				tcpwindow->head = tcpwindow->head->next;	
			}

			if(packet_node->fragment->data != NULL){
				rte_free(packet_node->fragment->data);
			}
			rte_free(packet_node->fragment);
			rte_free(packet_node);
		}else{
			break;
		}
	}
	return 0;
}

//TODO tcp接收窗口管理函数-pushback
int window_link_pushback(struct tcp_window *window, struct tcp_fragment *fragment){
	//创建窗口节点
	struct tcp_packet_node* packet_node = (struct tcp_packet_node*)rte_malloc("tcp_packet_node", sizeof(struct tcp_packet_node), 0);
	if (packet_node == NULL){
		return -1;
	}
	memset(packet_node, 0, sizeof(struct tcp_packet_node));
	packet_node->fragment = fragment;
	packet_node->next = NULL;

	//单链表插入 insert 尾插法
	//此时单链表为空
	if(window->head == NULL && window->tail == NULL){
		window->head = packet_node;
		window->tail = packet_node;
	}
	else{ //此时单链表不为空
		window->tail->next = packet_node;
		window->tail = packet_node;
	}
	return 0;
}

//重传机制实现
int tcp_retransmission(struct tcp_stream *pstStream){
	//判断超时时间大小
	if(pstStream->window->timeout > D_TCP_RETRANSMISSION_TIMEOUT){
		//重传n帧
		int n = 5;
		struct tcp_window * tcpwindow = pstStream->window;
		struct tcp_packet_node* packet_node = tcpwindow->head;
		for(;packet_node!=NULL;packet_node=packet_node->next){
			struct tcp_fragment *fragment = packet_node->fragment;
			//发送数据包
			rte_ring_mp_enqueue(pstStream->sndbuf, fragment);
			n--;
			if(n <= 0){
				break;
			}
		}
		//重置超时时间
		pstStream->window->timeout = 0;
	}
	return 0;
}

//TODO tcp 发送窗口管理函数 使用定时器轮询调用
int tcp_window_handle(uint32_t time){
	
	//获取tcp stream set
	struct tcp_table *pstTable = tcpInstance();	
	struct tcp_stream *pstStream = NULL;
	//遍历每个tcp stream
	for (pstStream = pstTable->tcb_set;pstStream != NULL; pstStream = pstStream->next){
		//一个半连接 listener fd 没有sndbuf 和 recvbuf
		if(pstStream->sndbuf == NULL){
			continue;
		}

		//超时时间管理
		if (pstStream->window == NULL)
		{
			continue;
		}
#if ENABLE_DEBUG
		printf("window_used:%d\n",pstStream->window->window_used);
#endif
		if(pstStream->window->window_used > 0){
			//定时器时间自增
			pstStream->window->timeout += time;
		}else{
			//重置超时时间
			pstStream->window->timeout = 0;
		}

		//重传机制
		tcp_retransmission(pstStream);
		//FIXME 窗口管理	
		while(pstStream->window->window_used < pstStream->window->window_size){
			//从windbuf中取出数据de_queue
			struct tcp_fragment *pstFragment = NULL;
			int iSendCnt = rte_ring_mc_dequeue(pstStream->windbuf, (void**)&pstFragment);
			if (iSendCnt < 0){
				break;
			}
			//查看pststream中的可用窗口大小
			uint32_t window_size_invalid = pstStream->window->window_size - pstStream->window->window_used;
			//如果pststream中的可用窗口大小大于pstfragment的大小
			if(window_size_invalid > pstFragment->length){
				//发送数据包
				rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
				//更新pststream中的窗口大小
				pstStream->window->window_used += pstFragment->length;
				//将pkt压入window_link的尾部
				int rte = window_link_pushback(pstStream->window, pstFragment);
			}
			else{
				//如果pststream中的可用窗口大小小于pstfragment的大小
				//将pstfragment重新放入windbuf
				rte_ring_mp_enqueue(pstStream->windbuf, pstFragment);
			}
		}
	}
	

	return 0;
}

#endif	
