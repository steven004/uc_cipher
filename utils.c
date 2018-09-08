#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#include <stdio.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>


#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include <sys/utsname.h> 

unsigned int veax;
unsigned int vebx;
unsigned int vedx;
unsigned int vecx;


//执行CPUID指令
void cpuid(unsigned int veax1)
{
    asm("cpuid"
        :"=a"(veax),
        "=b"(vebx),
        "=c"(vecx),
        "=d"(vedx)
        :"a"(veax));
}
//做移位操作，把寄存器中的值以“%d”形式输出
void LM(unsigned int var,uint32_t *vx)
{
  int i;
  for(i=0;i<3;i++)
  {
      var=(var>>i);
      vx[i]=var;
  }
}
 
void get_cpuid (char *id)
{
    uint32_t ax[3],cx[3],dx[3];
    cpuid(0);
    LM(veax,ax);
    cpuid(3);
    LM(vecx,cx);
    LM(vedx,dx);
    sprintf(id,"%u%u%u%u%u%u%u%u%u",ax[0],ax[1],ax[2],cx[0],cx[1],cx[2],dx[0],dx[1],dx[2]);
}

int get_mac(char* mac)
{
    int sockfd;
    struct ifreq tmp;
    char mac_addr[30];

    struct ifaddrs *ifaddr, *ifa;
    int family, n;
    char ifa_name[20] = {0};

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
       if (ifa->ifa_addr == NULL)
           continue;

       family = ifa->ifa_addr->sa_family;


       if ((family == AF_INET) && (strcmp(ifa->ifa_name, "lo") != 0)) {
           strcpy(ifa_name, ifa->ifa_name);
           break;
       }

    }

    freeifaddrs(ifaddr);


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if( sockfd < 0)
    {
        perror("create socket fail\n");
        return -1;
    }

    memset(&tmp,0,sizeof(struct ifreq));
    strncpy(tmp.ifr_name, ifa_name, sizeof(tmp.ifr_name)-1);
    if( (ioctl(sockfd,SIOCGIFHWADDR,&tmp)) < 0 )
    {
        printf("mac ioctl error\n");
        return -1;
    }

    sprintf(mac_addr, "%02x%02x%02x%02x%02x%02x",
            (unsigned char)tmp.ifr_hwaddr.sa_data[0],
            (unsigned char)tmp.ifr_hwaddr.sa_data[1],
            (unsigned char)tmp.ifr_hwaddr.sa_data[2],
            (unsigned char)tmp.ifr_hwaddr.sa_data[3],
            (unsigned char)tmp.ifr_hwaddr.sa_data[4],
            (unsigned char)tmp.ifr_hwaddr.sa_data[5]
            );
    close(sockfd);
    memcpy(mac,mac_addr,strlen(mac_addr));

    return 0;
}


/* 
int main(void)
{
        char cpuid[100];
        char mac[100];
        getcpuid(cpuid);
        printf("cpuid is %s\n",cpuid);

        get_mac(mac);
        printf("mac is %s\n", mac);

        struct utsname  u;
        if (uname(&u) != -1) {
                printf("获取当前内核的名称和信息如下\n"
                           "sysname:%s\n"
                           "nodename:%s\n"
                           "release:%s\n"
                           "version:%s\n"
                           "machine:%s\n"
                           , u.sysname, u.nodename, u.release, u.version, u.machine);
        }


        return 0;
}
*/
