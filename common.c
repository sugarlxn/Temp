#include "common.h"
#include "udp.h"
#include "tcp.h"


void dbg_print(char *info, unsigned char *dat, int dat_len)
{
    int i;

    printf("\n%s:%d\n", info, dat_len);
    for (i = 0; i < dat_len; i++)
    {
        if (i && (i % 16 == 0))
            printf("\n");
        printf("%02x ", dat[i]);
    }
    printf("\n");
}

struct tcp_table *tcpInstance(void) 
{
	if (g_pstTcpTbl == NULL) 
    {
		g_pstTcpTbl = rte_malloc("tcp_table", sizeof(struct tcp_table), 0);
		memset(g_pstTcpTbl, 0, sizeof(struct tcp_table));
	}
	return g_pstTcpTbl;
}

// TODO:分割establish和listen为两个函数
struct tcp_stream * tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_stream *iter = NULL;

	for (iter = pstTable->tcb_set; iter != NULL; iter = iter->next) // established
    {  
		if (iter->sip == sip && iter->dip == dip && 
			    iter->sport == sport && iter->dport == dport) 
        {
			return iter;
		}

	}

	for (iter = pstTable->tcb_set; iter != NULL; iter = iter->next) 
    {
		if (iter->dport == dport && iter->status == TCP_STATUS_LISTEN)  // listen
        { 
			return iter;
		}
	}

	return NULL;
}

// 从全连接队列中取 未使用的stream条目 fd=-1
static struct tcp_stream *get_accept_tcb(uint16_t dport) 
{
	struct tcp_stream *apt;
	for (apt = g_pstTcpTbl->tcb_set; apt != NULL; apt = apt->next) 
    {
		if (dport == apt->dport && apt->fd == -1) // fd = -1 表示该链接未使用 unused
        {
			return apt;
		}
	}

	return NULL;
}

int get_fd_frombitmap(void) 
{
	int fd = D_DEFAULT_FD_NUM;
	for (; fd < D_MAX_FD_COUNT; fd ++) 
    {
		if ((g_ucFdTable[fd/8] & (0x1 << (fd % 8))) == 0) 
        {
			g_ucFdTable[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}

	return -1;
}

int set_fd_frombitmap(int fd) 
{
	if (fd >= D_MAX_FD_COUNT) 
        return -1;

	g_ucFdTable[fd/8] &= ~(0x1 << (fd % 8));

	return 0;
}

struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, unsigned char proto) 
{
	struct localhost *pstHost = NULL;

	for (pstHost = g_pstHost; pstHost != NULL; pstHost = pstHost->next) 
    {
		if (dip == pstHost->localip && port == pstHost->localport && proto == pstHost->protocol) 
			return pstHost;
	}

	return NULL;
}

// TODO: 改成三个接口：udp get localhost, tcp get tcp_stream, tcp get listener
// udp 和 tcp 的get hostinfo from fd 都使用这个函数，并且时间复杂度为O(2n)
void* get_hostinfo_fromfd(int iSockFd) 
{
	struct localhost *pstHost = NULL;
	struct tcp_stream *pstStream = NULL;

	for (pstHost = g_pstHost; pstHost != NULL; pstHost = g_pstHost->next) //UDP
    {
		if (iSockFd == pstHost->fd) 
			return pstHost;
	}

	for (pstStream = g_pstTcpTbl->tcb_set; pstStream != NULL; pstStream = pstStream->next) { //TCP
		if (iSockFd == pstStream->fd) {
			return pstStream;
		}
	}


#if ENABLE_SINGLE_EPOLL

	struct eventpoll *ep = g_pstTcpTbl->ep; //TCP epoll
	if (ep != NULL) 
    {
		if (ep->fd == iSockFd) 
        {
			return ep;
		}
	}

#endif
	
	return NULL;
}

static struct arp_table *arp_table_instance(void) 
{
	if (g_pstArpTbl == NULL) 
    {
		g_pstArpTbl = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (g_pstArpTbl == NULL) 
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		
		memset(g_pstArpTbl, 0, sizeof(struct arp_table));

		pthread_spin_init(&g_pstArpTbl->spinlock, PTHREAD_PROCESS_SHARED);
	}

	return g_pstArpTbl;
}

unsigned char* ng_get_dst_macaddr(uint32_t dip) 
{
	struct arp_entry *pstIter;
	struct arp_table *pstTbl = arp_table_instance();

	int count = pstTbl->count;
	
	for (pstIter = pstTbl->entries; count-- > 0 && pstIter != NULL; pstIter = pstIter->next) 
    {
		if (dip == pstIter->ip) 
			return pstIter->hwaddr;
	}

	return NULL;
}

int ng_arp_entry_insert(uint32_t ip, unsigned char *mac)
{
    struct arp_table *pstTbl = arp_table_instance();
    struct arp_entry *pstEntry = NULL;
    unsigned char *pstHwaddr = NULL;

    pstHwaddr = ng_get_dst_macaddr(ip);
    if(pstHwaddr == NULL)
    {
        pstEntry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
		if (pstEntry) 
        {
			memset(pstEntry, 0, sizeof(struct arp_entry));

			pstEntry->ip = ip;
			rte_memcpy(pstEntry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
			pstEntry->type = 0;

			pthread_spin_lock(&pstTbl->spinlock);
			LL_ADD(pstEntry, pstTbl->entries);
			pstTbl->count ++;
			pthread_spin_unlock(&pstTbl->spinlock);
		}
        return 1;
    }

    return 0;
}

static int ng_encode_arp_pkt(unsigned char *msg, uint16_t opcode, unsigned char *dst_mac, 
    uint32_t sip, uint32_t dip) 
{
    struct rte_ether_hdr *pstEth = NULL;
    struct rte_arp_hdr *pstArp = NULL;
    unsigned char aucMac[RTE_ETHER_ADDR_LEN] = {0x0};

    // eth
    pstEth = (struct rte_ether_hdr*)msg;
    rte_memcpy(pstEth->s_addr.addr_bytes, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
    if (!strncmp((const char *)dst_mac, (const char *)g_aucDefaultArpMac, RTE_ETHER_ADDR_LEN)) 
    {
		rte_memcpy(pstEth->d_addr.addr_bytes, aucMac, RTE_ETHER_ADDR_LEN);
	} 
    else
    {
		rte_memcpy(pstEth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
    pstEth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // arp
    pstArp = (struct rte_arp_hdr *)(pstEth + 1);
    pstArp->arp_hardware = htons(1);                    // 硬件类型：1 以太网
    pstArp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);  // 协议类型：0x0800 IP地址
    pstArp->arp_hlen = RTE_ETHER_ADDR_LEN;              // 硬件地址长度：6
    pstArp->arp_plen = sizeof(uint32_t);                // 协议地址长度：4
    pstArp->arp_opcode = htons(opcode);                 // OP

    rte_memcpy(pstArp->arp_data.arp_sha.addr_bytes, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(pstArp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	pstArp->arp_data.arp_sip = sip;
	pstArp->arp_data.arp_tip = dip;
	
	return 0;
}

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, unsigned char *dst_mac, 
                                uint32_t sip, uint32_t dip) 
{
	const unsigned int uiTotalLen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    unsigned char *pucPktData;

	struct rte_mbuf *pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");

	pstMbuf->pkt_len = uiTotalLen;
	pstMbuf->data_len = uiTotalLen;

	pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char *);
	ng_encode_arp_pkt(pucPktData, opcode, dst_mac, sip, dip);

	return pstMbuf;
}


/*socket函数主要实现获取fd，创建控制块tcb*/
int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol)
{
    int iFd;
    struct localhost *pstHost;
    pthread_cond_t pctCond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t pmtMutex = PTHREAD_MUTEX_INITIALIZER;

    iFd = get_fd_frombitmap();
    if(type == SOCK_DGRAM) // udp
    {
        pstHost = rte_malloc("localhost", sizeof(struct localhost), 0);
        if(pstHost == NULL)
        {
            printf("[%s][%d]: rte_malloc fail!\n", __FUNCTION__, __LINE__);
            return -1;
        }

        memset(pstHost, 0x00, sizeof(struct localhost));
        pstHost->fd = iFd;
        pstHost->protocol = IPPROTO_UDP;
        pstHost->rcvbuf = rte_ring_create("recv buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (pstHost->rcvbuf == NULL) 
        {
            printf("[%s][%d]: rte_ring_create fail!\n", __FUNCTION__, __LINE__);
			rte_free(pstHost);
			return -1;
		}
        pstHost->sndbuf = rte_ring_create("send buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (pstHost->sndbuf == NULL) 
        {
            printf("[%s][%d]: rte_ring_create fail!\n", __FUNCTION__, __LINE__);
            rte_ring_free(pstHost->rcvbuf);
			rte_free(pstHost);
			return -1;
		}

		rte_memcpy(&pstHost->cond, &pctCond, sizeof(pthread_cond_t));

		rte_memcpy(&pstHost->mutex, &pmtMutex, sizeof(pthread_mutex_t));

		LL_ADD(pstHost, g_pstHost);
    }
    else if(type == SOCK_STREAM) // tcp
    {
        struct tcp_stream *pstStream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
		if (pstStream == NULL) 
			return -1;
		
		memset(pstStream, 0, sizeof(struct tcp_stream));
        pstStream->fd = iFd;
        pstStream->protocol = IPPROTO_TCP;
		pstStream->next = pstStream->prev = NULL;

        pstStream->rcvbuf = rte_ring_create("tcp recv buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (pstStream->rcvbuf == NULL) 
        {
			rte_free(pstStream);
			return -1;
		}
		pstStream->sndbuf = rte_ring_create("tcp send buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (pstStream->sndbuf == NULL) 
        {
			rte_ring_free(pstStream->rcvbuf);
			rte_free(pstStream);
			return -1;
		}

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&pstStream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&pstStream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        g_pstTcpTbl = tcpInstance();
		LL_ADD(pstStream, g_pstTcpTbl->tcb_set);           // TODO :hash 可以优化为哈希方式
    }

    return iFd;
}

/*bind函数的任务是将IP和端口信息绑定到socket函数创建的控制块结构中*/
//FIXME 如何判断sockfd 是udp还是tcp，本函数方法不太完美
int nbind(int sockfd, const struct sockaddr *addr, __attribute__((unused))  socklen_t addrlen)
{
    void *info = NULL;

    info = get_hostinfo_fromfd(sockfd);
    if(info == NULL) 
        return -1;

    struct localhost *pstHostInfo = (struct localhost *)info;
    if(pstHostInfo->protocol == IPPROTO_UDP)
    {
        const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)addr;
		pstHostInfo->localport = pstAddr->sin_port;
		rte_memcpy(&pstHostInfo->localip, &pstAddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(pstHostInfo->localmac, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
    }
    else if(pstHostInfo->protocol == IPPROTO_TCP)
    {
        struct tcp_stream* pstStream = (struct tcp_stream*)pstHostInfo;

        const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)addr;
		pstStream->dport = pstAddr->sin_port;
		rte_memcpy(&pstStream->dip, &pstAddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(pstStream->localmac, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
		//bind之后初始状态为 closed
		pstStream->status = TCP_STATUS_CLOSED;
    }

    return 0;
}

int nlisten(int sockfd, __attribute__((unused)) int backlog)
{
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
	if (pstStream->protocol == IPPROTO_TCP) 
    {
		pstStream->status = TCP_STATUS_LISTEN;
	}

    return 0;
}

//接收tcp stream链接：在全连接队列里面找到一个未使用的stream条目，然后为其分配一个唯一的fd文件描述符
int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen)
{
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL){ 
        return -1;
	}

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if (pstStream->protocol == IPPROTO_TCP) 
    {
        struct tcp_stream *pstAccept = NULL;

		//在全连接队列里面查找一个未使用的stream条目
        pthread_mutex_lock(&pstStream->mutex);
        while((pstAccept = get_accept_tcb(pstStream->dport)) == NULL)
        {
            pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
        }
        pthread_mutex_unlock(&pstStream->mutex);

		//为stream 分配一个唯一的fd 文件描述符
        pstAccept->fd = get_fd_frombitmap();

		//设置源ip和端口
        struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = pstAccept->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &pstAccept->sip, sizeof(uint32_t));

		return pstAccept->fd;
    }

    return -1;
}
/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.
   */
//连接函数 srcaddr 为本地地址，dstaddr 为远程地址
//FIXME 传统的网络协议栈自动分配srcaddr ip 以及port 待完善， 不需要用户指定
int nconnect(int sockfd, const struct sockaddr *dstaddr, const struct sockaddr *srcaddr, __attribute__((unused)) socklen_t addrlen)
{
	void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
		return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
	if(pstStream->protocol == IPPROTO_TCP)
	{
		//设置tcp stream 
		struct sockaddr_in *pstAddr = (struct sockaddr_in *)dstaddr;
		pstStream->sport = pstAddr->sin_port;
		rte_memcpy(&pstStream->sip, &pstAddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(pstStream->localmac, &g_stCpuMac, RTE_ETHER_ADDR_LEN);

		struct sockaddr_in *pstSrcAddr = (struct sockaddr_in *)srcaddr;
		pstStream->dport = pstSrcAddr->sin_port;
		rte_memcpy(&pstStream->dip, &pstSrcAddr->sin_addr.s_addr, sizeof(uint32_t));

		//发送SYN
		struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
		if (pstFragment == NULL){
			return -1;
		}
		memset(pstFragment, 0, sizeof(struct tcp_fragment));
		pstFragment->dport = pstStream->sport;
		pstFragment->sport = pstStream->dport;

		struct in_addr addr;
		addr.s_addr = pstStream->sip;
		printf("nconnect ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(pstStream->sport));

		pstFragment->acknum = 0;
		pstFragment->seqnum = 0;
		pstFragment->tcp_flags = RTE_TCP_SYN_FLAG;
		pstFragment->windows = D_TCP_INITIAL_WINDOW;
		pstFragment->hdrlen_off = 0x50;
		pstFragment->data = NULL;
		pstFragment->length = 0;

		//发送SYN包 
		rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);

		pstStream->status = TCP_STATUS_SYN_SENT;

		//等待连接建立
		pthread_mutex_lock(&pstStream->mutex);
		while (pstStream->status != TCP_STATUS_ESTABLISHED) 
		{
			pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
		}
		pthread_mutex_unlock(&pstStream->mutex);
	}

	return 0;
}

ssize_t nsend(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags)
{
    unsigned int uiLength = 0;
	//根据fd获取hostinfo
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;
	
	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if(pstStream->protocol == IPPROTO_TCP)
    {
        struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
		if (pstFragment == NULL) 
        {
			return -2;
		}

		memset(pstFragment, 0, sizeof(struct tcp_fragment));
        pstFragment->dport = pstStream->sport;
		pstFragment->sport = pstStream->dport;
		pstFragment->acknum = pstStream->rcv_nxt;
		pstFragment->seqnum = pstStream->snd_nxt;
		pstFragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		pstFragment->windows = D_TCP_INITIAL_WINDOW;
		pstFragment->hdrlen_off = 0x50;

        pstFragment->data = rte_malloc("unsigned char *", len+1, 0);
		if (pstFragment->data == NULL) 
        {
			rte_free(pstFragment);
			return -1;
		}
		memset(pstFragment->data, 0, len+1); 

		rte_memcpy(pstFragment->data, buf, len);
		
		pstFragment->length = len;
		uiLength = pstFragment->length;

#if ENABLE_WINDOW_MANAGE
		//添加滑动窗口机制, 将网络数据包--> windbuf 中
		int ret = rte_ring_mp_enqueue(pstStream->windbuf, pstFragment);
#else
		//此处代码是未添加滑动窗口机制
		int ret = rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
		/*FIXME 当ring size不够空间存放pstFragment时，函数返回-105，此时需要等待tcp_out将数据发送出去，然后再次调用rte_ring_mp_enqueue
				可以使用信号量cond和mutex来实现
		*/
#endif
		if(ret < 0){
			printf("rte_ring_mp_enqueue fail! ret = %d\n", ret);
		}
    }

    return uiLength;
}

/*Read len bytes into buf form socket fd
  returns the numbers read or -1 for error.
*/
ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags)
{
    ssize_t length = 0;
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL){
        return -1;
	}

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if(pstStream->protocol == IPPROTO_TCP)
    {
        struct tcp_fragment *pstFragment = NULL;
        int iRcvNum = 0;

        // 等待recvbuf中有数据
        pthread_mutex_lock(&pstStream->mutex);
		while ((iRcvNum = rte_ring_mc_dequeue(pstStream->rcvbuf, (void **)&pstFragment)) < 0) 
        {
			pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
		}
		pthread_mutex_unlock(&pstStream->mutex);

        if (pstFragment->length > len) 
        {
			//取出len长度的数据
            rte_memcpy(buf, pstFragment->data, len);
			//剩下的数据往前移动
			uint32_t i = 0;
			for(i = 0; i < pstFragment->length - len; i ++) 
            {
				pstFragment->data[i] = pstFragment->data[len + i];
			}
			pstFragment->length = pstFragment->length - len;
			//此时的length应该是len
			length = len;
			//数据未取完，存回rcvbuf
			rte_ring_mp_enqueue(pstStream->rcvbuf, pstFragment);
        }
        else if(pstFragment->length == 0)
        {
            rte_free(pstFragment);
			return 0;
        }
        else
        {
            rte_memcpy(buf, pstFragment->data, pstFragment->length);
			length = pstFragment->length;

			rte_free(pstFragment->data);
			pstFragment->data = NULL;

			rte_free(pstFragment);
        }
    }

    return length;
}

/*目前实现的recvfrom函数为阻塞式的，使用条件变量+互斥量等待接收队列中的数据到来*/
ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen)
{
    struct localhost *pstHostInfo = NULL;
    struct offload *pstOffLoad = NULL;
    struct sockaddr_in *pstAddr = NULL;
	unsigned char *pucPtr = NULL;
    int iLen = 0;
    int iRet = -1;
	
	//TODO 可以使用hash_table优化
    pstHostInfo = (struct localhost *)get_hostinfo_fromfd(sockfd);
    if(pstHostInfo == NULL) 
        return -1;
    
    pthread_mutex_lock(&pstHostInfo->mutex);
    while((iRet = rte_ring_mc_dequeue(pstHostInfo->rcvbuf, (void**)&pstOffLoad)) < 0)
    {
        pthread_cond_wait(&pstHostInfo->cond, &pstHostInfo->mutex);
    }
    pthread_mutex_unlock(&pstHostInfo->mutex);

    pstAddr = (struct sockaddr_in *)src_addr;
    pstAddr->sin_port = pstOffLoad->sport;
    rte_memcpy(&pstAddr->sin_addr.s_addr, &pstOffLoad->sip, sizeof(uint32_t));

    if(len < pstOffLoad->length)
    {
        rte_memcpy(buf, pstOffLoad->data, len);

        pucPtr = rte_malloc("unsigned char *", pstOffLoad->length - len, 0);
		rte_memcpy(pucPtr, pstOffLoad->data + len, pstOffLoad->length - len);

		pstOffLoad->length -= len;
		rte_free(pstOffLoad->data);
		pstOffLoad->data = pucPtr;
		
		rte_ring_mp_enqueue(pstHostInfo->rcvbuf, pstOffLoad);

		return len;
    }

    iLen = pstOffLoad->length;
    rte_memcpy(buf, pstOffLoad->data, pstOffLoad->length);
    
    rte_free(pstOffLoad->data);
    rte_free(pstOffLoad);
    
    return iLen;
}   
/*sendto函数式是将待发送数据封装成传输块，放入发送队列中，交由协议栈发送至网卡*/
ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen)
{
    struct localhost *pstHostInfo = NULL;
    struct offload *pstOffLoad = NULL;
    const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)dest_addr;

    pstHostInfo = (struct localhost *)get_hostinfo_fromfd(sockfd);
    if(pstHostInfo == NULL) 
        return -1;

    pstOffLoad = rte_malloc("offload", sizeof(struct offload), 0);
	if (pstOffLoad == NULL) 
        return -1;

    pstOffLoad->dip = pstAddr->sin_addr.s_addr;
	pstOffLoad->dport = pstAddr->sin_port;
	pstOffLoad->sip = pstHostInfo->localip;
	pstOffLoad->sport = pstHostInfo->localport;
	pstOffLoad->length = len;

    
#if ENABLE_DEBUG
    struct in_addr addr;
	addr.s_addr = pstOffLoad->dip;
	printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(pstOffLoad->dport));
#endif
    
    
    pstOffLoad->data = rte_malloc("unsigned char *", len, 0);
	if (pstOffLoad->data == NULL) {
		rte_free(pstOffLoad);
		return -1;
	}

	rte_memcpy(pstOffLoad->data, buf, len);

	// puts("rte_ring_mp_enqueue before !");
	rte_ring_mp_enqueue(pstHostInfo->sndbuf, pstOffLoad);
	// puts("rte_ring_mp_enqueue after !");

	return len;
}

/*close函数则是将创建的控制块进行释放*/
int nclose(int fd)
{
    void *info = NULL;

    info = (struct localhost *)get_hostinfo_fromfd(fd);
    if(info == NULL) 
        return -1;

    struct localhost *pstHostInfo = (struct localhost *)info;
    if(pstHostInfo->protocol == IPPROTO_UDP) //udp
    {
        LL_REMOVE(pstHostInfo, g_pstHost);

        if (pstHostInfo->rcvbuf)
			rte_ring_free(pstHostInfo->rcvbuf);
		if (pstHostInfo->sndbuf) 
			rte_ring_free(pstHostInfo->sndbuf);

		rte_free(pstHostInfo);
		//重置fd bitmap 为0
		set_fd_frombitmap(fd);
    }
    else if(pstHostInfo->protocol == IPPROTO_TCP) //tcp
    {
        struct tcp_stream *pstStream = (struct tcp_stream*)info;
        if (pstStream->status != TCP_STATUS_LISTEN) //tcp 
        {
            struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
			if (pstFragment == NULL) 
                return -1;

            memset(pstFragment, 0x00, sizeof(struct tcp_fragment));
            pstFragment->data = NULL;
			pstFragment->length = 0;
			pstFragment->sport = pstStream->dport;
			pstFragment->dport = pstStream->sport;

			pstFragment->seqnum = pstStream->snd_nxt;
			pstFragment->acknum = pstStream->rcv_nxt;

			pstFragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;// 发送 FIN+ACK
			pstFragment->windows = D_TCP_INITIAL_WINDOW;
			pstFragment->hdrlen_off = 0x50;

            rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
			pstStream->status = TCP_STATUS_LAST_ACK;

            set_fd_frombitmap(fd);
        }
        else //nsocket对应，由nsocket创建的stream不带sendbuf 和 recvbuf server端的listen
        {
            LL_REMOVE(pstStream, g_pstTcpTbl->tcb_set);	
			rte_free(pstStream);
        }
    }

    return 0;
}

//关闭tcp client
int nclose_tcp_client(int fd)
{
    void *info = NULL;

    info = (struct localhost *)get_hostinfo_fromfd(fd);
    if(info == NULL) 
        return -1;

    struct localhost *pstHostInfo = (struct localhost *)info;
    if(pstHostInfo->protocol == IPPROTO_UDP) //udp
    {
        LL_REMOVE(pstHostInfo, g_pstHost);

        if (pstHostInfo->rcvbuf)
			rte_ring_free(pstHostInfo->rcvbuf);
		if (pstHostInfo->sndbuf) 
			rte_ring_free(pstHostInfo->sndbuf);

		rte_free(pstHostInfo);
		//重置fd bitmap 为0
		set_fd_frombitmap(fd);
    }
    else if(pstHostInfo->protocol == IPPROTO_TCP) //tcp
    {
        struct tcp_stream *pstStream = (struct tcp_stream*)info;
         //tcp established
        
		struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
		if (pstFragment == NULL) 
			return -1;

		memset(pstFragment, 0x00, sizeof(struct tcp_fragment));
		pstFragment->data = NULL;
		pstFragment->length = 0;
		pstFragment->sport = pstStream->dport;
		pstFragment->dport = pstStream->sport;

		pstFragment->seqnum = pstStream->snd_nxt;
		pstFragment->acknum = pstStream->rcv_nxt;

		pstFragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;// 发送 FIN+ACK
		pstFragment->windows = D_TCP_INITIAL_WINDOW;
		pstFragment->hdrlen_off = 0x50;

		rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
		pstStream->status = TCP_STATUS_FIN_WAIT_1;


		//等待关闭
		pthread_mutex_lock(&pstStream->mutex);
		while (pstStream->status != TCP_STATUS_CLOSED)
		{
			pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
		}
		pthread_mutex_unlock(&pstStream->mutex);
		
		set_fd_frombitmap(fd);
    }

    return 0;
}

#if ENABLE_SINGLE_EPOLL

//epoll回调函数，将fd添加到准备队列
int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event)
{
	struct epitem tmp;
	tmp.sockfd = sockid;
	struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
	if (!epi) 
	{
		printf("rbtree not exist\n");
		return -1;
	}
	if (epi->rdy) 
	{
		epi->event.events |= event;
		return 1;
	} 
#if ENABLE_DEBUG
	printf("epoll_event_callback --> %d\n", epi->sockfd);
#endif
	
	pthread_spin_lock(&ep->lock);
	epi->rdy = 1;
	LIST_INSERT_HEAD(&ep->rdlist, epi, rdlink);
	ep->rdnum ++;
	pthread_spin_unlock(&ep->lock);

	pthread_mutex_lock(&ep->cdmtx);

	pthread_cond_signal(&ep->cond);
	pthread_mutex_unlock(&ep->cdmtx);
	return 0;
}
//对event poll进行初始化 并且将其添加到tcp_table中
int nepoll_create(int size)
{
	//size必须大于0
    if (size <= 0) return -1;
    // epfd --> struct eventpoll 一一对应
	int epfd = get_fd_frombitmap(); //tcp, udp 获取文件描述符
	
	struct eventpoll *ep = (struct eventpoll*)rte_malloc("eventpoll", sizeof(struct eventpoll), 0);
	if (!ep) 
    {
		set_fd_frombitmap(epfd);
		return -1;
	}

	g_pstTcpTbl->ep = ep;
	
	ep->fd = epfd;
	ep->rbcnt = 0;
	//初始化红黑树
	RB_INIT(&ep->rbr);
	LIST_INIT(&ep->rdlist);

	if (pthread_mutex_init(&ep->mtx, NULL)) 
    {
		rte_free(ep);
		set_fd_frombitmap(epfd);
		
		return -2;
	}

	if (pthread_mutex_init(&ep->cdmtx, NULL))
    {
		pthread_mutex_destroy(&ep->mtx);
		rte_free(ep);
		set_fd_frombitmap(epfd);
		return -2;
	}

	if (pthread_cond_init(&ep->cond, NULL)) 
    {
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		rte_free(ep);
		set_fd_frombitmap(epfd);
		return -2;
	}

	if (pthread_spin_init(&ep->lock, PTHREAD_PROCESS_SHARED)) 
    {
		pthread_cond_destroy(&ep->cond);
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		rte_free(ep);

		set_fd_frombitmap(epfd);
		return -2;
	}

	return epfd;
}

int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event)	
{
    struct eventpoll *ep = (struct eventpoll*)get_hostinfo_fromfd(epfd);
	if (!ep || (!event && op != EPOLL_CTL_DEL)) 
    {
		errno = -EINVAL;
		return -1;
	}

    if (op == EPOLL_CTL_ADD) 
    {
        pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) 
        {
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}

		epi = (struct epitem*)rte_malloc("epitem", sizeof(struct epitem), 0);
		if (!epi) 
        {
			pthread_mutex_unlock(&ep->mtx);
			rte_errno = -ENOMEM;
			return -1;
		}
		
		epi->sockfd = sockid;
		memcpy(&epi->event, event, sizeof(struct epoll_event));

		epi = RB_INSERT(_epoll_rb_socket, &ep->rbr, epi);

		ep->rbcnt ++;
		
		pthread_mutex_unlock(&ep->mtx);
    }
    else if(op == EPOLL_CTL_DEL)
    {
        pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (!epi) 
        {	
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}
		
		epi = RB_REMOVE(_epoll_rb_socket, &ep->rbr, epi);
		if (!epi)
        {
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}

		ep->rbcnt --;
		rte_free(epi);
		
		pthread_mutex_unlock(&ep->mtx);
    }
    else if (op == EPOLL_CTL_MOD) 
    {
		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) 
        {
			epi->event.events = event->events;
			epi->event.events |= EPOLLERR | EPOLLHUP;
		} 
        else 
        {
			rte_errno = -ENOENT;
			return -1;
		}
    }

    return 0;
}

int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    struct eventpoll *ep = (struct eventpoll*)get_hostinfo_fromfd(epfd);;
	if (!ep || !events || maxevents <= 0) 
    {
		rte_errno = -EINVAL;
		return -1;
	}

	if (pthread_mutex_lock(&ep->cdmtx)) 
    {
		if (rte_errno == EDEADLK) 
        	printf("epoll lock blocked\n");
	}
	
	while (ep->rdnum == 0 && timeout != 0) 
    {
		ep->waiting = 1;
		if (timeout > 0) 
        {
			struct timespec deadline;

			clock_gettime(CLOCK_REALTIME, &deadline);
			if (timeout >= 1000) 
            {
				int sec;
				sec = timeout / 1000;
				deadline.tv_sec += sec;
				timeout -= sec * 1000;
			}

			deadline.tv_nsec += timeout * 1000000;

			if (deadline.tv_nsec >= 1000000000) 
            {
				deadline.tv_sec++;
				deadline.tv_nsec -= 1000000000;
			}

			int ret = pthread_cond_timedwait(&ep->cond, &ep->cdmtx, &deadline);
			if (ret && ret != ETIMEDOUT) 
            {
				printf("pthread_cond_timewait\n");
				
				pthread_mutex_unlock(&ep->cdmtx);
				
				return -1;
			}
			timeout = 0;
		} 
        else if (timeout < 0) 
        {
			int ret = pthread_cond_wait(&ep->cond, &ep->cdmtx);
			if (ret) 
            {
				printf("pthread_cond_wait\n");
				pthread_mutex_unlock(&ep->cdmtx);

				return -1;
			}
		}
		ep->waiting = 0; 
	}

	pthread_mutex_unlock(&ep->cdmtx);

	pthread_spin_lock(&ep->lock);
	int cnt = 0;
	int num = (ep->rdnum > maxevents ? maxevents : ep->rdnum);
	int i = 0;
	
	while (num != 0 && !LIST_EMPTY(&ep->rdlist))  // EPOLLET
    { 
		struct epitem *epi = LIST_FIRST(&ep->rdlist);
		LIST_REMOVE(epi, rdlink);
		epi->rdy = 0;

		memcpy(&events[i++], &epi->event, sizeof(struct epoll_event));
		
		num --;
		cnt ++;
		ep->rdnum --;
	}
	pthread_spin_unlock(&ep->lock);

	return cnt;
}


#endif