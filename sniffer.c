#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>

#include <stdio.h> //For standard things
#include <stdlib.h> //malloc
#include <string.h> //strlen

#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/tcp.h>  //Provides declarations for tcp header
#include <netinet/ip.h>   //Provides declarations for ip header
#include <netinet/if_ether.h>  //For ETH_P_ALL

#include <net/ethernet.h>  //For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>

#include <net/ethernet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>

#define __FAVOR_BSD           // Use BSD format of tcp header
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void PrintData(unsigned char*,int);
void PrintActualPayload(unsigned char*,int);
bool crc(void*, int, uint8_t[]);

int count = 0;

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,i,j;

char physical[20][20];
char logical[20][20];
char spare[20][20];

// Allocate memory for an array of chars.
char *allocate_strmem (int len) {
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (char *) malloc (len * sizeof (char));
    
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } 
    else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t *allocate_ustrmem (int len) {
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } 
    else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

int main() {
	int saddr_size,data_size;
	struct sockaddr saddr;

	char *interface;
	struct ifreq ifr;
	int sd;
	uint8_t *machine;	//,*dst=buffer;
	machine = allocate_ustrmem(6);	

	interface = allocate_strmem (40);
	
	// Interface to send packet through.
  	strcpy (interface, "eno1");

	
  	// Submit request for a socket descriptor to look up interface.
  	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}


	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	close (sd);
	
  	// Copy source MAC address.
	memcpy (machine, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	
	//free(&ifr);
    //free(interface);

	unsigned char *buffer = (unsigned char *) malloc(65536);//Its Big!

	printf("Starting...\n");
		
	sd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	//setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+1);
	
	if(sd < 0) {
		//Print the error with proper message
    	perror("Socket Error");
    	return 1;
	}
	    
	saddr_size = sizeof saddr;
	while(data_size = recvfrom(sd,buffer,65536,0,&saddr,(socklen_t*)&saddr_size)) {
        //saddr_size = sizeof saddr;
        //Receive a packet
    	if(data_size<0) {
    		printf("Recvfrom error , failed to get packets\n");
        		return 1;
    	}
    
        printf("%d\n",data_size);
    
    	if(crc(buffer,data_size,machine)) {
    		logfile=fopen("log.txt","w");
            if(logfile==NULL) {
		    	printf("Unable to create log.txt file.");
			}
			
    		//Now process the packet
			ProcessPacket(buffer,data_size);
			break;
    	}
    	else
    		//printf("Error detected in Ethernet frame\nCannot process data\n");
    	  ;
	}


	close(sd);
	//free(machine);
	printf("Finished\n");
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size) {
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
        if (iph->protocol == 6) { //Check the TCP Protocol and do accordingly...
            print_tcp_packet(buffer,size);
        }
}

void print_ethernet_header(unsigned char* Buffer, int Size) {
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    
    fprintf(logfile,"\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile,"   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
    fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4], eth->h_source[5] );
    fprintf(logfile, "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size) {
    print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;
        
    struct iphdr *iph=(struct iphdr *)(Buffer+sizeof(struct ethhdr));
    iphdrlen =iph->ihl*4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile, "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile ,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile ,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile ,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile, "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size) {
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)( Buffer + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
            
    int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
   
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
        
    print_ip_header(Buffer,Size);
        
    fprintf(logfile, "\n");
    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile, "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile, "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile, "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile, "\n");
    fprintf(logfile, "                        DATA Dump                         ");
    fprintf(logfile, "\n");
        
    fprintf(logfile, "IP Header\n");
    PrintData(Buffer,iphdrlen);
        
    fprintf(logfile, "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
        
    fprintf(logfile, "Data Payload\n");
    PrintActualPayload(Buffer + header_size , Size - header_size );
    
    fprintf(logfile, "CRC Code\n");
    PrintData(Buffer + Size - 1 , sizeof(uint8_t) );
                        
    fprintf(logfile, "\n###########################################################");
}


void PrintData(unsigned char* data , int Size) {
   
    int i , j, l=16;
    for(i=0 ; i < Size ; i++) {
        if(i!=0&&i%l==0) { //if one line of hex printing is complete...
            fprintf(logfile,"        ");
            for(j=i-l;j<i;j++) {
                if(data[j]>=32&&data[j]<=128){
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                    //if(j!=0)
                    	//printf("%c",(unsigned char)data[j]);
                }
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        }
        
        if(i%16==0) fprintf(logfile,"  ");
            fprintf(logfile,"%02X",(unsigned int)data[i]);
                
        if(i==Size-1) {//print the last spaces
            for(j=0;j<l-1-i%l;j++) {
                fprintf(logfile,"  "); //extra spaces
            }
            
            fprintf(logfile,"        ");
            
            for(j=i-i%l;j<=i;j++) {
                if(data[j]>=32&&data[j]<=128) {
                    fprintf(logfile,"%c",(unsigned char)data[j]);
                    //printf("%c",(unsigned char)data[j]);
                }
                else {
                    fprintf(logfile,".");
                }
            }
            
            fprintf(logfile,"\n");
        }
    }
    printf("\n");
}


void PrintActualPayload(unsigned char* data , int Size) {
    int flag = 0;
    
    char *ip;
    sprintf (ip, "255.255.255.255");
    int ip_len = strlen (ip);
    
    for(j = 0; j < ip_len; j++)
         fprintf(logfile, "%c", (unsigned char)ip[j]);
    fprintf(logfile, "\n");
    
    strcpy(physical[0], "00-14-22-01-23-45");
	strcpy(physical[1], "00-04-DC-01-23-45");
	strcpy(physical[2], "00-03-BD-01-76-42");
	strcpy(physical[3], "00-30-BD-01-23-45");
	strcpy(physical[4], "00-14-22-05-64-45");
	
	strcpy(logical[0], "130.57.64.11");
	strcpy(logical[1], "130.57.64.12");
	strcpy(logical[2], "130.57.64.13");
	strcpy(logical[3], "130.57.65.15");
	strcpy(logical[4], "130.57.65.16");

	strcpy(spare[0], "130.57.66.12");
	strcpy(spare[1], "130.57.67.14");
	strcpy(spare[2], "130.57.68.15");
	strcpy(spare[3], "130.57.66.13");

    for(int i = 0; i < 5; i ++) {
        if(strncmp(physical[i], data, 16) == 0) {
            flag = 1;
            fprintf(logfile, "\nSuccess MAC found\n");
            
            for(int j = 0; j < 12; j++) {  
               fprintf(logfile, "%c", logical[i][j]);
            }
        }
    }
  fprintf(logfile, "\n");

    if(!flag) {
        fprintf(logfile, "\nNew Address Allocated\n");
        for(int j = 0; j < 12; j ++) {
            fprintf(logfile, "%c", spare[0][j]);
            count++;
        }
        fprintf(logfile,"\n");
    } 
    
    int i , j, l=64;
    for(i=0 ; i < Size ; i++) {
        if(i!=0&&i%l==0) { //if one line of hex printing is complete...
        
            fprintf(logfile,"        ");
            
            for(j=i-l;j<i;j++) {
                if(data[j]>=32&&data[j]<=128){
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                }
                else fprintf(logfile,"."); //otherwise print a dot
            }
            
            fprintf(logfile,"\n");
        }        
        
        if(i==Size-1) {//print the last spaces
            for(j=0;j<l-1-i%l;j++) {
                fprintf(logfile,"  "); //extra spaces
            }
            
            fprintf(logfile,"        ");
            
            for(j=i-i%l;j<=i;j++) {
                if(data[j]>=32&&data[j]<=128) {
                    fprintf(logfile,"%c",(unsigned char)data[j]);
                    //printf("%c",(unsigned char)data[j]);
                }
                else {
                    fprintf(logfile,".");
                }
            }
            
            fprintf(logfile,"\n");
        }
    }
    printf("\n");
}

int errorMAC(void* buffer, int size, uint8_t machine[]) {
/*	char *interface;
	struct ifreq ifr;
	int sd;
	uint8_t i,machine[6],*dst=buffer;
	//machine = (uint8_t)allocate_ustrmem(6);	

	// Interface to send packet through.
  	strcpy (interface, "eno1");

  	// Submit request for a socket descriptor to look up interface.
  	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    		perror ("socket() failed to get socket descriptor for using ioctl() ");
    		exit (EXIT_FAILURE);
	}


	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	close (sd);
  
  	// Copy source MAC address.
	memcpy (machine, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

*/

	uint8_t i,*dst=buffer;
	//src+=6;
	for(i=0;i<6;i++){
		printf("%d %d\n",machine[i],dst[i]);
		//src[i]=(uint8_t)buffer[i];
		//dst[i]=(uint8_t)buffer[i+6];	
		if(machine[i]!=dst[i]){
			//printf("Wrong packet recieved..\n");
			return 1;
		}
	}
	//for(i=0;i<6;i++)
	//	printf("%d %d\n",src[i],dst[i]);
	return 0;
}

bool crc(void* buffer, int size, uint8_t machine[]) {
	if(errorMAC(buffer,size,machine))
		return 0;
	
	uint8_t *data=buffer;
	
	uint8_t g=7,m=data[0];
	//m=m^g;
	int i,k,j=128,z;
	
	
	for(i=1;i<size;i++) {
		j=128;
		for(k=0;k<8;k++) {
			uint8_t z=m/128;	//to extract MSB of m
			m*=2;			
			m+=((data[i]/j)%2);	//to extract 1 bit of the next byte (to create a virtual flow of bits)
				
			if(z)			//to check if XOR operation is to be performed
				m=m^g;
				
				
			j/=2;			//needed to continue the 'flow of bits'
		}
	}
	
	if(m){
		printf("Error detected through CRC encoding\nCannot process\n");
		return 0;
	}
	return 1;
}

