
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

unsigned char * cmp[100];

void dump(unsigned char*buf, int size){
	int i;
	
	for(i=0;i<size;i++){
		if(i%16==0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){			
		printf("payload_len=%d ", ret);
		dump(data, ret);	
	}
	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	
	int i, ip_protocol, ip_hsize, tcp_hsize;
	struct libnet_ipv4_hdr* iphdr;
	struct libnet_tcp_hdr* tcphdr;
	unsigned char* buf;

	nfq_get_payload(nfa, &buf);

	iphdr = (struct libnet_ipv4_hdr*)buf;

	ip_protocol = iphdr->ip_p;
	ip_hsize = iphdr->ip_hl*4;

	if(ip_protocol == 0x6)
	{
		tcphdr = (struct libnet_tcp_hdr*)(buf + ip_hsize);
		tcp_hsize = tcphdr->th_off*4;
		buf = buf + ip_hsize + tcp_hsize;
		
		if(strstr(buf, "GET") || strstr(buf, "POST") || strstr(buf, "HEAD") || strstr(buf, "PUT") || strstr(buf, "DELETE") || strstr(buf, "OPTIONS") != NULL)
		{
			if(strstr(buf, "Host: ") != NULL)
			{				
				buf = strstr(buf,"Host: ");				
				
				printf("\nTHIS IS DATA\n");
				i=0;	
				while(1)
				{				
					if(buf[i] == 0x0d)
					 break;	
					if(i%16 == 0)
						printf("\n");				
					printf("%02x ", buf[i]);
					i++;					
				}	
				
				for(i=0;i<100;i++)
					if(strstr(buf, cmp[i]) != NULL)
					{					
						printf("DROP THE PAGE\n");	
						return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					}

					else
					  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			}
			
			else
			  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}	
		
		else
		  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			
	}
	
	else
	{
	  printf("entering callback\n");
	  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	int i,len;
	char buf[4096] __attribute__ ((aligned));
	
	
	for(i=0;i<3;i++)		// i == # of filtering page
	{
		len = strlen(argv[i+1]);
		//printf("%d\n",len);		
		
		if(len > 0)
		{
			cmp[i] = argv[i+1];
			printf("%s\n", cmp[i]);
		}

		else if(len == 0)
			break;
	}


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
