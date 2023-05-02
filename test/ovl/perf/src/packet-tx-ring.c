// Example asynchronous packet socket reading with PACKET_TX_RING
// From http://codemonkeytips.blogspot.com/2011/07/asynchronous-packet-socket-writing-with.html

#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DEBUG

# define INADDR_VM201	((in_addr_t) 0xc0a801c9) /* Inet 192.168.1.201.  */

typedef struct {
	int block_nr;
	int block_sz;
	int frame_nr;
	int frame_sz;
	int packet_sz;
	int port;
	char ifname[IFNAMSIZ];
	char dest[INET6_ADDRSTRLEN];
} packet_tx_ring_opts;
static packet_tx_ring_opts options;

static volatile int wait = 1;
static volatile int stop = 0;

/// The number of frames in the ring
//  This number is not set in stone. Nor are block_size, block_nr or frame_size
#define DEF_PKT_LEN			100
#define DEF_BLOCK_NR		256
#define DEF_BLOCK_SZ		(getpagesize() << 2)
#define DEF_FRAME_SZ		(TPACKET_ALIGNMENT << 7)

/// (unimportant) macro for loud failure
#define RETURN_ERROR(lvl, msg...) \
	do {                    \
		fprintf(stderr, msg); \
		return lvl;            \
	} while(0);

static struct sockaddr_ll txring_daddr;

/* function: ip_checksum_add
 * adds data to a checksum
 * current - the current checksum (or 0 to start a new checksum)
 * data        - the data to add to the checksum
 * len         - length of data
 */
uint32_t
ip_checksum_add(uint32_t current, const void *data, int len)
{
	uint32_t checksum = current;
	int left = len;
	const uint16_t *data_16 = data;
	while(left > 1) {
		checksum += *data_16;
		data_16++;
		left -= 2;
	}
	if(left) {
		checksum += *(uint8_t *)data_16;
	}
	return checksum;
}

/* function: ip_checksum_fold
 * folds a 32-bit partial checksum into 16 bits
 * temp_sum - sum from ip_checksum_add
 * returns: the folded checksum in network byte order
 */
uint16_t
ip_checksum_fold(uint32_t temp_sum)
{
	while(temp_sum > 0xffff)
		temp_sum = (temp_sum >> 16) + (temp_sum & 0xFFFF);
	return temp_sum;
}

/* function: ip_checksum_finish
 * folds and closes the checksum
 * temp_sum - sum from ip_checksum_add
 * returns: a header checksum value in network byte order
 */
uint16_t
ip_checksum_finish(uint32_t temp_sum)
{
  return ~ip_checksum_fold(temp_sum);
}

/* function: ip_checksum
 * combined ip_checksum_add and ip_checksum_finish
 * data - data to checksum
 * len  - length of data
 */
uint16_t
ip_checksum(const void *data, int len)
{
  uint32_t temp_sum;
  temp_sum = ip_checksum_add(0, data,len);
  return ip_checksum_finish(temp_sum);
}

/// create a linklayer destination address
//  @param ringdev is a link layer device name, such as "eth0"
static int
init_ring_daddr(int fd, const char *ringdev)
{
	struct ifreq ifreq;

	// get device index
	strcpy(ifreq.ifr_name, ringdev);
	if (ioctl(fd, SIOCGIFINDEX, &ifreq))
		RETURN_ERROR(-1, "Error getting ifindex: %s", strerror(errno));

	txring_daddr.sll_family    = AF_PACKET;
	txring_daddr.sll_protocol  = htons(ETH_P_IP);
	txring_daddr.sll_ifindex   = ifreq.ifr_ifindex;
	txring_daddr.sll_halen = 0;

	return 0;
}

/// Initialize a packet socket ring buffer
//  @param ringtype is one of PACKET_RX_RING or PACKET_TX_RING
static char *
init_packetsock_ring(int fd, int ringtype)
{
	struct tpacket_req tp;
	char *ring;

	// tell kernel to export data through mmap()ped ring
	tp.tp_block_size = options.block_sz;
	tp.tp_block_nr = options.block_nr;
	tp.tp_frame_size = options.frame_sz;
	tp.tp_frame_nr = options.frame_nr;
	if (setsockopt(fd, SOL_PACKET, ringtype, (void*) &tp, sizeof(tp)))
		RETURN_ERROR(NULL, "setsockopt() ring error: %s\n", strerror(errno));

#ifdef TPACKET_V2
	val = TPACKET_V1;
	setsockopt(fd, SOL_PACKET, PACKET_HDRLEN, &val, sizeof(val));
#endif

	// open ring
	ring = mmap(0, tp.tp_block_size * tp.tp_block_nr,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!ring || ring == MAP_FAILED) {
		RETURN_ERROR(NULL, "mmap() failed with err: %s\n", strerror(errno));
	}
		

	if (init_ring_daddr(fd, options.ifname))
		return NULL;

	int sock_wmem = options.block_nr * options.block_sz;
	int sock_wmem_cur;
	socklen_t read_len = sizeof(sock_wmem_cur);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, 
		       &sock_wmem_cur, &read_len) < 0)
		RETURN_ERROR(NULL,
			     "getsockopt(SO_SNDBUF) failed with err: %s\n",
			     strerror(errno));

	if (sock_wmem_cur < sock_wmem)
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
			       &sock_wmem, sizeof(sock_wmem)) < 0)
			RETURN_ERROR(NULL,
				     "setsockopt(SO_SNDBUF) failed with err: %s\n",
				     strerror(errno));

	return ring;
}

/// Create a packet socket. If param ring is not NULL, the buffer is mapped
//  @param ring will, if set, point to the mapped ring on return
//  @return the socket fd
static int
init_packetsock(char **ring, int ringtype)
{
	int fd;

	// open packet socket
	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0)
		RETURN_ERROR(-1, "Root priliveges are required\nsocket() rx. \n");

	if (ring) {
		*ring = init_packetsock_ring(fd, ringtype);
		if (!*ring) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

static int
exit_packetsock(int fd, char *ring)
{
	if (munmap(ring, options.frame_nr * options.frame_sz))
		RETURN_ERROR(1, "munmap err: %s\n", strerror(errno));

	if (close(fd))
		RETURN_ERROR(1, "close err: %s\n", strerror(errno));

	return 0;
}

static int
stats_packetsock(int fd)
{
	int err;
	socklen_t len;
	struct tpacket_stats stats;

	len = sizeof(stats);
	err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
	if (err < 0) {
		RETURN_ERROR(-1, "Error getting packet stats: %s", strerror(errno));
	}

	fprintf(stderr, "\nSent %u packets, %u dropped\n", stats.tp_packets, stats.tp_drops);
	return 0;
}

static int
create_packet(int fd, char *off, uint16_t pktlen)
{
	static uint16_t id = 0; 
	struct ifreq ifr;
	struct iphdr *iph = (struct iphdr*)off;

	/* Get the MAC address of the interface to send on */
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, options.ifname, (IFNAMSIZ - 1));
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
	  RETURN_ERROR(-1, "Get IP address failed with err: %s", strerror(errno));

	if (getrandom(off, pktlen, 0) != pktlen)
		RETURN_ERROR(-1, "Random payload generation failed\n");

	iph->ihl = 0x5;
	iph->version = 0x4;
	iph->tos = 0x00;
	iph->id = htons(id++);
	iph->protocol = IPPROTO_UDP;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->tot_len = htons((uint16_t)pktlen - sizeof(struct ethhdr));

	iph->saddr = inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr)));
	iph->daddr = inet_addr(options.dest);
	iph->check = 0;
	iph->check = ip_checksum(off, sizeof(struct iphdr));

	struct udphdr *uh = (struct udphdr *)(off + sizeof(struct iphdr));
	uh->source = htons(options.port);
	uh->dest = htons(options.port);
	uh->len = htons((uint16_t)pktlen - sizeof(struct iphdr) - sizeof(struct ethhdr));
	uh->check = 0;

	return 0;
}

/// transmit a packet using packet ring
//  NOTE: for high rate processing try to batch system calls, 
//        by writing multiple packets to the ring before calling send()
//
//  @param pkt is a packet from the network layer up (e.g., IP)
//  @return 0 on success, -1 on failure
static int
process_tx(int fd, char *ring, int pktlen)
{
	static int ring_offset = 0;
	struct tpacket_hdr *header;
	struct pollfd pollset;
	char *off;
	int ret;
	time_t timer;
	char buffer[26];
	struct tm* tm_info;

	timer = time(NULL);
	tm_info = localtime(&timer);
	strftime(buffer, 26, "%H:%M:%S", tm_info);

	// fetch a frame
	header = (void *) ring + (ring_offset * options.frame_sz);
#ifdef DEBUG_FULL
	fprintf(stderr, "%s: Fetch frame: header: %p, ring: %p, ring_offset: %d, pagesize: 0x%x\n",
		buffer, header, ring, ring_offset, getpagesize());
#endif
	while (header->tp_status != TP_STATUS_AVAILABLE) {
#ifdef DEBUG
		fprintf(stderr, "Before poll: header: %p, ring offset: %d\n",
			header, ring_offset);
#endif
		// if none available: wait on more data
		pollset.fd = fd;
		pollset.events = POLLOUT;
		pollset.revents = 0;
		ret = poll(&pollset, 1, 1000 /* don't hang */);
		if (ret < 0) {
			if (errno != EINTR) {
				RETURN_ERROR(-1, "Poll err: %s\n", strerror(errno));
			}
			return 0;
		}
#ifdef DEBUG
		fprintf(stderr, "After poll: header: %p, ring offset: %d\n",
			header, ring_offset);
#endif
	}

	// fill data
	off = ((void *) header) + (TPACKET_HDRLEN - sizeof(struct sockaddr_ll));
	if ((ret = create_packet(fd, off, pktlen)))
		return ret;

	// fill header
	header->tp_len = pktlen;
	header->tp_status = TP_STATUS_SEND_REQUEST;

	// increase consumer ring pointer
	ring_offset = (ring_offset + 1) & (options.frame_nr - 1);

	// notify kernel
	if (sendto(fd, NULL, 0, 0, (void *) &txring_daddr, sizeof(txring_daddr)) < 0) {
		RETURN_ERROR(-1, "send err: %s\n", strerror(errno));
	}

	return 0;
}

static void
ring_align() {
#ifdef DEBUG
	fprintf(stderr, "packet-tx-ring parameters (before align):\n"
			"\tblock_nr: %d\n"
			"\tblock_sz: %d\n"
			"\tframe_nr: %d\n"
			"\tframe_sz: %d\n"
			"\tpacket_sz: %d\n",
			options.block_nr, options.block_sz,
			options.frame_nr, options.frame_sz,
			options.packet_sz);
#endif
    /*
     * The frame allocation in the ring block holds the full layer 2 frame 
     * (headers + data) and some meta data, so it must hold TPACKET2_HDRLEN
     * (which is 52 bytes) aligned with TPACKET_ALIGN() (which increases it
     * from 52 to 64 bytes) + the minimum Ethernet layer 2 frame size (which
     * is 64 bytes).
     * Ensure the frame size within each block supports this minimum size:
     */
    if (options.block_sz < (options.packet_sz + TPACKET_ALIGN(TPACKET2_HDRLEN)))
	options.block_sz = (options.packet_sz + TPACKET_ALIGN(TPACKET2_HDRLEN));

    // In TPACKET v2 each block must hold exactly a multple of two frames:
    if (options.block_sz < options.frame_sz)
	options.block_sz = options.frame_sz;

    // Block size must be an integer multiple of pages
    if ((options.block_sz < (uint32_t)getpagesize()) ||
	(options.block_sz % (uint32_t)getpagesize() != 0)) {
	uint32_t base = (options.block_sz / (uint32_t)getpagesize()) + 1;
	options.block_sz = (base * (uint32_t)getpagesize());
	base = (options.block_sz/options.frame_sz) + 1;
	options.frame_sz = options.block_sz/base;
    }

	/* Always calculate number of frames based on input */
	options.frame_nr = (options.block_sz/options.frame_sz) * options.block_nr;

#ifdef DEBUG
	fprintf(stderr, "packet-tx-ring parameters (after align):\n"
			"\tblock_nr: %d\n"
			"\tblock_sz: %d\n"
			"\tframe_nr: %d\n"
			"\tframe_sz: %d\n"
			"\tpacket_sz: %d\n",
			options.block_nr, options.block_sz,
			options.frame_nr, options.frame_sz,
			options.packet_sz);
#endif
}

static void print_usage ()
{
	fprintf(stderr,"packet-tx-ring;\n"
			"\t-b\tNumber of blocks in ring buffer (for PACKET_MMAP). Default is %" PRId32 ".\n"
			"\t-B\tBlock size in multiples of the pagesize. Default is 1.\n"
			"\t-f\tNumber of frames in a block. Default is %" PRId32 ".\n"
			"\t-i\tInterface name to send packets. No default, mandatory parameter.\n"
			"\t-d\tDestination IP address to send packets. No default, mandatory parameter.\n"
			"\t-s\tAllocation size in bytes for each frame per block (for PACKET_MMAP).\n"
			"\t\tThis includes meta data. Default is %" PRId32 " bytes.\n"
			"\t-h\tPrint this help.\n",
			DEF_BLOCK_SZ,
			DEF_BLOCK_NR,
			DEF_PKT_LEN);
}

static int parse_args(int argc, char **argv)
{
	int c;

	memset(&options, 0, sizeof(options));
	options.block_sz = DEF_BLOCK_SZ;
	options.block_nr = DEF_BLOCK_NR;
	options.frame_sz = DEF_FRAME_SZ;
	options.packet_sz = DEF_PKT_LEN;
	options.port = 12345;
	opterr = 0;

	while ((c = getopt (argc, argv, "b:B:f:i:d:p:s:h")) != -1)
		switch (c) {
		case 'h':
			print_usage();
			goto err;
		case 'b':
			options.block_nr = atoi(optarg);
			break;
		case 'B':
			options.block_sz = atoi(optarg) * getpagesize();
			break;
		case 'f':
			options.frame_sz = atoi(optarg);
			break;
		case 's':
			options.packet_sz = atoi(optarg);
			break;
		case 'i':
			strncpy(options.ifname, optarg, IFNAMSIZ);
			break;
		case 'd':
			strncpy(options.dest, optarg, INET6_ADDRSTRLEN);
			break;
		case 'p':
			options.port = atoi(optarg);
			break;
		case '?':
			if (optopt == 'i' || optopt == 'd' || optopt == 'p' ||
				optopt == 's' || optopt == 'b' || optopt == 'f')
				fprintf (stderr, "-%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,
						"Unknown option character `\\x%x'.\n",
						optopt);
			print_usage();
			goto err;
		default:
			goto err;
		}
	
	if (strlen(options.ifname) == 0) {
		fprintf(stderr, "-i <interface name> is mandatory!\n");
		goto err;
	} else if (strlen(options.dest) == 0) {
		fprintf(stderr, "-d <destination IP address> is mandatory!\n");
		goto err;
	} else {
		inet_addr(options.dest);
	}

	ring_align();
	return 0;

err:
	return -1;
}

void
sig_handler(int dummy)
{
	fprintf(stderr, "Ctrl+C called, exiting app\n");
  stop = 1;
}

void
alarm_handler(int signum)
{
	wait = 0;
	alarm(1);
}
 
/// Example application that opens a packet socket with rx_ring
int
main(int argc, char **argv)
{
	char *ring;
	int fd;

	signal(SIGINT, sig_handler);
	signal(SIGALRM, alarm_handler);
	alarm(1);

	if (parse_args(argc, argv) < 0)
		return 1;

	fd = init_packetsock(&ring, PACKET_TX_RING);
	if (fd < 0)
		return 1;

	while(!stop) {
		if (!wait) {
			process_tx(fd, ring, options.packet_sz);
			wait = 1;
		} else {
			usleep(100 * 1000);
		}
	}

	if (stats_packetsock(fd))
		return 1;

	if (exit_packetsock(fd, ring))
		return 1;

	printf("OK\n");
	return 0;
}


