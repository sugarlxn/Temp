#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "common.h"
#include "tcp.h"
#include "udp.h"

struct rte_ether_addr g_stCpuMac;
struct rte_kni *g_pstKni;                    // todo：后续将全局变量统一初始化，不再使用getInstance()
struct St_InOut_Ring *g_pstRingIns = NULL;   // todo：后续将全局变量统一初始化，不再使用getInstance()
struct localhost *g_pstHost = NULL;          // todo：后续将全局变量统一初始化，不再使用getInstance()
struct arp_table *g_pstArpTbl = NULL;        // todo：后续将全局变量统一初始化，不再使用getInstance()
struct tcp_table *g_pstTcpTbl = NULL;		 // todo：后续将全局变量统一初始化，不再使用getInstance()
static uint64_t tcp_pkt_count = 0; // tcp包计数 用于计算PPS
static uint64_t udp_pkt_count = 0; // udp包计数 用于计算PPS

#if ENABLE_DEBUG
static FILE *file_ptr= NULL; //数据采集文件
#endif

unsigned char g_aucDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

unsigned char g_ucFdTable[D_MAX_FD_COUNT] = {0};

static struct St_InOut_Ring *ringInstance(void) 
{
	if (g_pstRingIns == NULL) 
    {
		g_pstRingIns = rte_malloc("in/out ring", sizeof(struct St_InOut_Ring), 0);
		memset(g_pstRingIns, 0, sizeof(struct St_InOut_Ring));
	}

	return g_pstRingIns;
}

void ng_init_port(struct rte_mempool *pstMbufPoolPub)
{
    unsigned int uiPortsNum;
    const int iRxQueueNum = 1;
	const int iTxQueueNum = 1;
    int iRet;
    struct rte_eth_dev_info stDevInfo;
    struct rte_eth_txconf stTxConf;
    struct rte_eth_conf stPortConf =    // 端口配置信息
    {
        .rxmode = {.max_rx_pkt_len = 1518 }   // RTE_ETHER_MAX_LEN = 1518
    };
    
    uiPortsNum = rte_eth_dev_count_avail(); 
	if (uiPortsNum == 0) 
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");

	rte_eth_dev_info_get(D_PORT_ID, &stDevInfo); 
	
    // 配置以太网设备
	rte_eth_dev_configure(D_PORT_ID, iRxQueueNum, iTxQueueNum, &stPortConf);

    iRet = rte_eth_rx_queue_setup(D_PORT_ID, 0 , 1024, rte_eth_dev_socket_id(D_PORT_ID), NULL, pstMbufPoolPub);
	if(iRet < 0) 
	    rte_exit(EXIT_FAILURE, "Could not setup RX queue!\n");

	stTxConf = stDevInfo.default_txconf;
	stTxConf.offloads = stPortConf.txmode.offloads;
    iRet = rte_eth_tx_queue_setup(D_PORT_ID, 0 , 1024, rte_eth_dev_socket_id(D_PORT_ID), &stTxConf);
	if (iRet < 0) 
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");

	if (rte_eth_dev_start(D_PORT_ID) < 0 )
		rte_exit(EXIT_FAILURE, "Could not start\n");
    
    rte_eth_promiscuous_enable(D_PORT_ID);
}

//ifconfig veth0 up/down 响应函数
static int ng_config_network_if(uint16_t port_id, unsigned char if_up) {
	//判断port_id是否有效
	if (!rte_eth_dev_is_valid_port(port_id)) {
		return -EINVAL;
	}

	int ret = 0;
	if (if_up) {

		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);

	} else {

		rte_eth_dev_stop(port_id);

	}

	if (ret < 0) {
		printf("Failed to start port : %d\n", port_id);
	}

	return 0;
}

static struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool) {

	struct rte_kni *kni_hanlder = NULL; //kni句柄
	
	struct rte_kni_conf conf; //config配置信息
	memset(&conf, 0, sizeof(conf));

	//设置kni配置信息 snprintf:格式化输出到字符串 为创建的kni接口命名 如vEth0
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", D_PORT_ID);
	conf.group_id = D_PORT_ID;
	conf.mbuf_size = D_MAX_PACKET_SIZE;
	rte_eth_macaddr_get(D_PORT_ID, (struct rte_ether_addr *)conf.mac_addr);
	//mtu maximum transmission unit 最大传输单元,网卡设备的最大传输单元
	rte_eth_dev_get_mtu(D_PORT_ID, &conf.mtu);

	// print_ethaddr("ng_alloc_kni: ", (struct ether_addr *)conf.mac_addr);

	/*
	//获取网卡设备信息接口示例
	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(D_PORT_ID, &dev_info);
	*/


	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));

	ops.port_id = D_PORT_ID;
	ops.config_network_if = ng_config_network_if;
	
	kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);	
	if (!kni_hanlder) {
		rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", D_PORT_ID);
	}
	
	return kni_hanlder;
}
//网络数据包处理
static int pkt_process(void *arg)
{
    struct rte_mempool *pstMbufPool;
    int iRxNum;
	int i;
	struct rte_ether_hdr *pstEthHdr;
    struct rte_ipv4_hdr *pstIpHdr;
	struct rte_udp_hdr *pstUdpHdr;
	struct rte_tcp_hdr *pstTcpHdr;

    pstMbufPool = (struct rte_mempool *)arg;
    while(1)
    {	
		//从in ring队列中取出数据包
		struct rte_mbuf *pstMbuf[32];
        iRxNum = rte_ring_mc_dequeue_burst(g_pstRingIns->pstInRing, (void**)pstMbuf, D_BURST_SIZE, NULL);
        
		
        if(iRxNum <= 0){
			continue;
		}
        
        for(i = 0; i < iRxNum; ++i)
        {
            pstEthHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ether_hdr *, 0);
            if (pstEthHdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))   //IPv4: 0800 
            {
                pstIpHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                
				// 维护一个arp表
				ng_arp_entry_insert(pstIpHdr->src_addr, pstEthHdr->s_addr.addr_bytes);
                if(pstIpHdr->next_proto_id == IPPROTO_UDP ) // udp 
                {	
					pstUdpHdr =(struct rte_udp_hdr*)(pstIpHdr + 1);
					// printf("udp_process dst_port:%d\n", ntohs(pstUdpHdr->dst_port));
					//FIXME 端口过滤 当有多个udp服务端时，将会有多个 udp localport 端口
					if(pstUdpHdr->dst_port == htons(8889)){
						// udp process
						// printf("udp_process---\n");
						udp_process(pstMbuf[i]);
					}else{
						//返回到kni接口，走内核协议栈
						rte_kni_tx_burst(g_pstKni, pstMbuf, iRxNum);
						// printf("udp --> rte_kni_handle_request\n");
					}
				}
                else if(pstIpHdr->next_proto_id == IPPROTO_TCP)  // tcp
                {
					pstTcpHdr = (struct rte_tcp_hdr *)(pstIpHdr + 1);
					//FIXME 端口过滤 当有多个TCP服务端时，将会有多个TCP dport 端口
					if(pstTcpHdr->dst_port == htons(9999)){
						// printf("tcp_process ---\n");
						tcp_process(pstMbuf[i]);
					}else{
						//返回到kni接口，走内核协议栈
						rte_kni_tx_burst(g_pstKni, pstMbuf, iRxNum);
						// printf("tcp --> rte_kni_handle_request\n");
					}
				}
				else
				{
					//返回到kni接口，走内核协议栈
					rte_kni_tx_burst(g_pstKni, pstMbuf, iRxNum);
					// printf("tcp/udp --> rte_kni_handle_request\n");
				}
            }
			else 
			{
				// ifconfig vEth0 192.168.181.169 up
				//返回到kni接口，走内核协议栈
				rte_kni_tx_burst(g_pstKni, pstMbuf, iRxNum);
				// printf("ip --> rte_kni_handle_request\n");
			}   
        }
		//处理kni handle请求
		rte_kni_handle_request(g_pstKni);

		//窗口管理
#if ENABLE_WINDOW_MANAGE
		tcp_window_handle(NULL);
#endif


    }
    return 0;
}

int pkg_out(void *arg){
	struct rte_mempool *pstMbufPool;
	pstMbufPool = (struct rte_mempool *)arg;
	while(1){
		udp_out(pstMbufPool);
		tcp_out(pstMbufPool);
	}
	return 0;
}


//NOTE UDP服务器入口程序
int udp_server_entry(__attribute__((unused))  void *arg) 
{           
    int iConnfd;
	struct sockaddr_in stLocalAddr, stClientAddr; 
	socklen_t uiAddrLen = sizeof(stClientAddr);
	char acBuf[D_UDP_BUFFER_SIZE] = {0};

	iConnfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (iConnfd == -1) 
	{
		printf("nsocket failed\n");
		return -1;
	} 

	memset(&stLocalAddr, 0, sizeof(struct sockaddr_in));

	stLocalAddr.sin_port = htons(8889);
	stLocalAddr.sin_family = AF_INET;
	stLocalAddr.sin_addr.s_addr = inet_addr("10.0.0.1"); 
	// stLocalAddr.sin_addr.s_addr = htonl(INADDR_ANY); 

	
	nbind(iConnfd, (struct sockaddr*)&stLocalAddr, sizeof(stLocalAddr));

	while (1) 
	{
		if (nrecvfrom(iConnfd, acBuf, D_UDP_BUFFER_SIZE, 0, 
			(struct sockaddr*)&stClientAddr, &uiAddrLen) < 0) 
		{
			continue;
		} 
		else 
		{
			// printf("recv from %s:%d, data:%s\n", inet_ntoa(stClientAddr.sin_addr), 
			// 	ntohs(stClientAddr.sin_port), acBuf);
			nsendto(iConnfd, acBuf, strlen(acBuf), 0, 
				(struct sockaddr*)&stClientAddr, sizeof(stClientAddr));
			++udp_pkt_count;
		}
	}

	nclose(iConnfd);

    return 0;
}

#define BUFFER_SIZE	1024

#if ENABLE_SINGLE_EPOLL 
//NOTE TCP 服务器入口 epoll轮询 单线程轮询
int tcp_server_entry(__attribute__((unused))  void *arg)
{
	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) 
	{
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

	nlisten(listenfd, 10);

	//创建epoll 并添加进入tcp-table中的ep链表中 epoll事件根节点
	int epfd = nepoll_create(1);
	struct epoll_event ev, events[1024];
	ev.data.fd = listenfd;
	ev.events |= EPOLLIN;
	nepoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);


	char buff[BUFFER_SIZE] = {'\0'};
	while(1)
	{
		int nready = nepoll_wait(epfd, events, 1024, 5);
		if(nready < 0){
			continue;
		}

		for(int i = 0; i < nready; ++i)
		{
			int fd = events[i].data.fd;
			if(listenfd == fd)
			{
				struct sockaddr_in client;
				socklen_t len = sizeof(client);
				int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

				struct epoll_event ev;
				ev.events = EPOLLIN;
				ev.data.fd = connfd;
				nepoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
			}
			else
			{
				int n = nrecv(fd, buff, BUFFER_SIZE, 0); //block
				if (n > 0) 
				{
					// printf(" epoll tcp server --> recv: %s\n", buff);
					//业务代码
					nsend(fd, buff, n, 0);
					++tcp_pkt_count;
				} 
				else 
				{
					// printf("recv length <= 0 close stream: %s\n", strerror(errno));
					nepoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
					nclose(fd);
				} 
			}
		}
	}

	return 0;
}

#else
//NOTE tcp服务器入口程序
int tcp_server_entry(__attribute__((unused))  void *arg)  
{
	int listenfd;
	int iRet = -1;
	struct sockaddr_in servaddr;
	
	listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) 
	{
		printf("[%s][%d] nsocket error!\n", __FUNCTION__, __LINE__);
		return -1;
	}

	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	// servaddr.sin_addr.s_addr = inet_addr("172.31.196.226"); 
	servaddr.sin_port = htons(9999);
	iRet = nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if(iRet < 0)
	{
		printf("nbind error!\n");
		return -1;
	}

	nlisten(listenfd, 10);

	while (1) 
	{
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

		char buff[D_TCP_BUFFER_SIZE] = {0};
		while (1) 
		{
			int n = nrecv(connfd, buff, D_TCP_BUFFER_SIZE, 0); //block 阻塞的方式
			printf("nrecv n = %d\n", n);
			if (n > 0) //n>0 接收成功
			{
				printf("tcp server recv: %s\n", buff);
				// nsend(connfd, "hello", 5, 0);
				nsend(connfd, buff, n, 0);
			} 
			else if (n == 0) //n=0 连接断开
			{
				printf("nclose()\n");
				nclose(connfd);
				break;
			} 
			else //n<0 非阻塞方式
			{
				continue;
			}
		}

	}
	
	nclose(listenfd);

    return 0;
}

#endif

//tcp client entry
int tcp_client_entry(__attribute__((unused))  void *arg)
{
	int sockfd;
	struct sockaddr_in server_addr; // 服务器端地址
	struct sockaddr_in client_addr; // 客户端地址

	//创建socket套接字
	if ((sockfd = nsocket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket create failed");
		exit(1);
	}
	server_addr.sin_family = AF_INET; //网络层IP协议IPV4
	server_addr.sin_port = htons(8888); //服务器端口
	server_addr.sin_addr.s_addr = inet_addr("172.28.48.1"); //服务器IP地址
	bzero(&(server_addr.sin_zero), 8); //保留的8字节清零

	client_addr.sin_family = AF_INET; //网络层IP协议IPV4
	client_addr.sin_port = htons(23570); //客户端端口
	client_addr.sin_addr.s_addr = inet_addr("172.28.60.246"); //客户端IP地址
	bzero(&(client_addr.sin_zero), 8); //保留的8字节清零

	//链接服务器
	if (nconnect(sockfd, (struct sockaddr *)&server_addr, (struct sockaddr*)&client_addr , sizeof(struct sockaddr)) < 0)
	{
		perror("connect failed");
		exit(1);
	}
	printf("connect success\n");

	char recvbuf[D_TCP_BUFFER_SIZE]={0};
	int index =0;
	//发送数据
	while (1)
	{
		
		nsend(sockfd, "hello", 5, 0);
		nrecv(sockfd, recvbuf, D_TCP_BUFFER_SIZE, 0);
		printf("recv data is %s\n", recvbuf);
		if (index==3)
		{
			break;
		}
		index++;
		

		// if (nsend(sockfd, sendbuf, data_len, 0) < 0)
		// {
		// 	perror("send failed");
		// 	exit(1);
		// }
	}
	//FIXME 关闭socket
	nclose_tcp_client(sockfd);
	while (1)
	{
		/* code */
	}
	
	return 0;
}

//定时器回调函数timer0_cb 自动重装载
static void timer0_cb(__attribute__((unused)) struct rte_timer *timer, __attribute__((unused)) void *arg)
{
#if ENABLE_DEBUG
	static unsigned counter = 0;
	unsigned lcore_id = rte_lcore_id();
	printf("%s() on lcore %u, count:%d\n", __func__, lcore_id, counter++);
#endif

#if ENABLE_WINDOW_MANAGE
	//获取当前定时器时间
	uint32_t time = 100;
	//TODO超时重传管理
	struct tcp_table *pst_tcp_table = tcpInstance();
	struct tcp_stream *pst_stream = pst_tcp_table->tcb_set;
	//int tcp_retransmission(struct tcp_stream *pstStream, int time);
	while (pst_stream != NULL){
		tcp_retransmission(pst_stream, time);
		pst_stream = pst_stream->next;		
	} 

#endif



	/* this timer is automatically reloaded until we decide to
	 * stop it, when counter reaches 20. */
	// if ((counter ++) == 20){
	// 	rte_timer_stop(timer);
	// }
}

//定时器回调函数timer1_cb 仅触发一次
static void timer1_cb(__rte_unused struct rte_timer* timer, __rte_unused void* arg){
	unsigned lcore_id = rte_lcore_id();
	// uint64_t hz;

#if ENABLE_COLLECT
	if(file_ptr != NULL){
		//将counter 写入文件fd
		fprintf(file_ptr, "udp_pps,%d,tcp_pps,%d,\n", udp_pkt_count, tcp_pkt_count);
	
	}
#endif
	printf("%s() on lcore %u, udp_pkt_PPS=%d pkt per second, tcp_pkt_PPS=%d pkt per second.\n", __func__, lcore_id, udp_pkt_count, tcp_pkt_count);
	udp_pkt_count = 0;
	tcp_pkt_count = 0;

	// /* reload it on another lcore */
	// hz = rte_get_timer_hz();
	// lcore_id = rte_get_next_lcore(lcore_id, 0, 1);
	// rte_timer_reset(timer, hz, SINGLE, lcore_id, timer1_cb, NULL);
}


static __attribute__((noreturn)) int
lcore_mainloop(__attribute__((unused)) void *arg)
{
	uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
	unsigned lcore_id;

	lcore_id = rte_lcore_id();
	printf("Starting mainloop on core %u\n", lcore_id);

	while (1) {
		/*
		 * Call the timer handler on each core: as we don't
		 * need a very precise timer, so only call
		 * rte_timer_manage() every ~10ms (at 2Ghz). In a real
		 * application, this will enhance performances as
		 * reading the HPET timer is not efficient.
		 */
		//rte_rdtsc函数返回自开机后，cpu的周期数
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
}

void SIGNAI_INT_HANDLER(int signo)
{
	if(signo == SIGINT)
	{
		printf("catch SIGINT, closing.....\n");
#if ENABLE_COLLECT
		if(file_ptr != NULL)
		{
			fclose(file_ptr);
		}
#endif
	}
	exit(0);
}

//NOTE 主函数main
int main(int argc, char *argv[]) 
{
    struct rte_mempool *pstMbufPoolPub;
    struct St_InOut_Ring *pstRing;
    struct rte_mbuf *pstRecvMbuf[32] = {NULL};
    struct rte_mbuf *pstSendMbuf[32] = {NULL};
    int iRxNum;
    int iTotalNum;
    int iOffset;
    int iTxNum;

    unsigned int uiCoreId;

	//注册信号处理函数
	signal(SIGINT, SIGNAI_INT_HANDLER);

	//DPDK环境初始化
    if(rte_eal_init(argc, argv) < 0){
	    rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}	

    pstMbufPoolPub = rte_pktmbuf_pool_create("MBUF_POOL_PUB", D_NUM_MBUFS, 0, 0, 
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if(pstMbufPoolPub == NULL)
	{
		printf("rte_errno = %x, errmsg = %s\n", rte_errno, rte_strerror(rte_errno));
		return -1;
	}

	//初始化kni kernel network interface 内核网络接口
    if (-1 == rte_kni_init(D_PORT_ID)) 
        rte_exit(EXIT_FAILURE, "kni init failed\n");
    
	//初始化dpdk端口
	ng_init_port(pstMbufPoolPub);
	//分配kni内存池
	g_pstKni = ng_alloc_kni(pstMbufPoolPub);

    rte_eth_macaddr_get(D_PORT_ID, &g_stCpuMac);

#if ENABLE_COLLECT
	//打开数据采集文件
	//获取当前时间
	time_t t = time(0);
	//转换为字符串 添加到文件名中
	char filename[64];
	strftime(filename, sizeof(filename), "%Y-%m-%d %H:%M:%S", localtime(&t));
	//字符串拼接tmp + .txt
	char dir[64] = "./data/";
	char path[128]={'\0'};
	sprintf(path, "%s%s%s", dir, filename, ".txt");
	printf("data_will write into filename : %s\n", path);
	file_ptr = fopen(path, "a+");
	if (file_ptr == NULL)
	{
		printf("open file failed\n");
		return -1;
	}
#endif	

	//配置rte_timer定时器
	rte_timer_subsystem_init();
	struct rte_timer timer0;
	struct rte_timer timer1;
	rte_timer_init(&timer0);
	rte_timer_init(&timer1);
	uint64_t hz = rte_get_timer_hz();


	/*
	* PERIODICAL : 定时器触发完了之后自动加载
	* SINGLE : 定时器仅触发一次
	*/
	//两个定时器都在主循环中触发
	uiCoreId = rte_lcore_id();

    pstRing = ringInstance();
	if(pstRing == NULL){
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
	}

	//设置IN、OUT队列，将网卡的收发数据包存入队列
    pstRing->pstInRing = rte_ring_create("in ring", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    pstRing->pstOutRing = rte_ring_create("out ring", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	
	///*DPDK具有cpu亲和性的特点，可以为每个线程绑定单独的cpu核心*/
	///*这里设置了三个线程，分别用于网卡数据包分发、UDP应用层业务服务、TCP应用层业务服务*/
    
	//NOTE 启动数据包处理线程 pkt_process协议栈解析部分
    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	rte_eal_remote_launch(pkt_process, pstMbufPoolPub, uiCoreId);

	//NOTE 启动UDP服务器线程
    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	rte_eal_remote_launch(udp_server_entry, pstMbufPoolPub, uiCoreId);
	//NOTE 启动TCP服务器线程
    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    rte_eal_remote_launch(tcp_server_entry, pstMbufPoolPub, uiCoreId);

	//NOTE 启动pkg_out线程
	uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	rte_eal_remote_launch(pkg_out, pstMbufPoolPub, uiCoreId);

	// NOTE 启动TCP客户端线程
	// uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	// rte_eal_remote_launch(tcp_client_entry, pstMbufPoolPub, uiCoreId);

	//hz为定时器一秒的tick总数，所以hz的tick总数,时间为 100ms
	uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	rte_timer_reset(&timer0, hz/10, PERIODICAL, uiCoreId, timer0_cb, pstMbufPoolPub);
	rte_eal_remote_launch(lcore_mainloop, NULL, uiCoreId);
	uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	rte_timer_reset(&timer1, hz, PERIODICAL, uiCoreId, timer1_cb, pstMbufPoolPub);
	rte_eal_remote_launch(lcore_mainloop, NULL, uiCoreId);

	/* call lcore_mainloop() on every slave lcore */
	/*RTE_LCORE_FOREACH_SLAVE只会历遍所有的slave核，不包括master核*/
	// uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	// RTE_LCORE_FOREACH_SLAVE(uiCoreId) {
	// 	rte_eal_remote_launch(lcore_mainloop, NULL, uiCoreId);
	// }



	/*主线程负责将网卡的数据放入in ring队列，将要发送的网卡数据从out ring队列拿出发送*/
    while (1) 
    {
        // rx
        iRxNum = rte_eth_rx_burst(D_PORT_ID, 0, pstRecvMbuf, D_BURST_SIZE);
        if(iRxNum > 0){
            rte_ring_sp_enqueue_burst(pstRing->pstInRing, (void**)pstRecvMbuf, iRxNum, NULL);
		}
        // tx
        iTotalNum = rte_ring_sc_dequeue_burst(pstRing->pstOutRing, (void**)pstSendMbuf, D_BURST_SIZE, NULL);
		if(iTotalNum > 0)
		{
			iOffset = 0;
			while(iOffset < iTotalNum)
			{
				iTxNum = rte_eth_tx_burst(D_PORT_ID, 0, &pstSendMbuf[iOffset], iTotalNum - iOffset);
				if(iTxNum > 0){
					iOffset += iTxNum;
				}
			}
		}

		//定时器管理
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;
		//rte_rdtsc函数返回自开机后，cpu的周期数
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
			// printf("rte_timer_manage\n");
			// printf("diff_tsc = %lu\n", diff_tsc);
		}

    }

	return 0;

}   
