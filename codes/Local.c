#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//数据结构
struct DNS_Head
{
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
};

struct DNS_Query
{
    unsigned char *qname;
    unsigned short qtype;
    unsigned short qclass;
};

struct DNS_RR
{
    unsigned char *rname;
    unsigned short rtype;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short datalen;
    unsigned char *rdata;
};
//DNS服务器ip
unsigned char ip[64];
//包缓存
unsigned char tcpsendpacket[1024];
unsigned char tcprecvpacket[1024];
unsigned char udpsendpacket[1024];
unsigned char udprecvpacket[1024];
int tcpsendpos,tcprecvpos, udpsendpos, udprecvpos;
//rr缓存
struct DNS_RR rrdb[4];
int rrnum;
unsigned char db[1024];
unsigned char* dbptr;
//函数表
void formdomain(unsigned char*);
void gethead(unsigned char*, int*, struct DNS_Head*);
void getquery(unsigned char*, int*, struct DNS_Query*);
void getrr(unsigned char*, int*, struct DNS_RR*);
void setstdhead(unsigned char*, int*);
void setreshead(unsigned char*, int*, int id);
void setaquery(unsigned char*, int*, unsigned char*);
void setrr(unsigned char*, int*, struct DNS_RR);

int main()
{
    //初始化socket
    int tcpServerSocket, tcpClientSocket;
    struct sockaddr_in tcpServerAddr, tcpClientAddr;
    int tcpaddrlen;

    int udpSocket;
    struct sockaddr_in udpRemoteAddr;
    int udpaddrlen;

    tcpServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);

    tcpServerAddr.sin_family = AF_INET;
    tcpServerAddr.sin_port = htons(53);
    tcpServerAddr.sin_addr.s_addr = inet_addr("127.0.0.2");
    udpRemoteAddr.sin_family = AF_INET;
    udpRemoteAddr.sin_port = htons(53);

    if (bind(tcpServerSocket, (struct sockaddr*)&tcpServerAddr, sizeof(struct sockaddr)) < 0)
    {
        printf("server binds failed\n");
        exit(0);
    }
    listen(tcpServerSocket, 4);
    tcpaddrlen = sizeof(struct sockaddr_in);
    udpaddrlen = sizeof(struct sockaddr_in);

    tcpClientSocket = accept(tcpServerSocket, (struct sockaddr*)&tcpClientAddr, &tcpaddrlen);
    //开始计时
    clock();
    //初始化缓存
    rrnum = 0;
    dbptr = db;

    while (1)
    {
        //初始化DNS服务器ip
        strcpy(ip, "127.0.0.3");
        udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
        //接受报文
        recv(tcpClientSocket, tcprecvpacket, sizeof(tcprecvpacket), 0);
        printf("server recv packet from client\n");

        struct DNS_Head head;
        struct DNS_Query query;
        struct DNS_RR rr;
        //解析报文
        tcprecvpos = 2;
        gethead(tcprecvpacket, &tcprecvpos, &head);
        getquery(tcprecvpacket, &tcprecvpos, &query);
        //查询缓存
        int i;
        for (i = 0; i < rrnum; ++i)
        {
            if (strcmp(rrdb[i].rname, query.qname) == 0 && rrdb[i].rtype == query.qtype)
            {
                printf("using cache\n");
                tcpsendpos = 2;
                setreshead(tcpsendpacket, &tcpsendpos, head.id);
                setrr(tcpsendpacket, &tcpsendpos, rrdb[i]);
                *(unsigned short*)tcpsendpacket = htons(tcpsendpos - 2);
                send(tcpClientSocket, tcpsendpacket, tcpsendpos, 0);
                printf("server send packet to client\n");
                i = rrnum + 1;
                break;
            }
        }
        if (i == rrnum + 1)
            continue;
        //生成查询报文
        for (i = 2; i < sizeof(tcprecvpacket); ++i)
        {
            udpsendpacket[i - 2] = tcprecvpacket[i];
        }
        udpsendpos = tcprecvpos - 2;

        while (1)
        {
            int flag = 0;
            //发送报文
            sendto(udpSocket, udpsendpacket, udpsendpos, 0, (struct sockaddr*)&udpRemoteAddr, sizeof(struct sockaddr));
            printf("server send packet to %s\n", ip);
            //接受报文
            recvfrom(udpSocket, udprecvpacket, sizeof(udprecvpacket), 0, (struct sockaddr*)&udpRemoteAddr, &udpaddrlen);
            printf("server recv packet from %s\n", ip);
            //解析报文
            udprecvpos = 0;
            gethead(udprecvpacket, &udprecvpos, &head);
            getrr(udprecvpacket, &udprecvpos, &rr);

            switch (head.tag)
            {
            case (unsigned short)0x8000://回答是结果
                for (i = 2; i < sizeof(udprecvpacket); ++i)
                {
                    tcpsendpacket[i] = udprecvpacket[i - 2];
                }
                tcpsendpos = udprecvpos + 2;
                *(unsigned short*)tcpsendpacket = htons(tcpsendpos - 2);

                if (rr.rtype == 1 || rr.rtype == 2)//A或者NS类型的查询
                {
                    flag = 1;
                    break;
                }
                else if (rr.rtype == 5)//CNAME类型的查询
                {
                    struct DNS_Head h1;
                    struct DNS_Query q1;
                    udpsendpos = 0;
                    gethead(udpsendpacket, &udpsendpos, &h1);
                    getquery(udpsendpacket, &udpsendpos, &q1);

                    if (q1.qtype == 5)//发送的查询是CNAME
                    {
                        flag = 1;
                        break;
                    }
                    else if (q1.qtype == 1)//发送的查询是A 进行第二次查询
                    {
                        //生成查询报文
                        unsigned char domain[64];
                        strcpy(domain, rr.rdata);
                        formdomain(domain);

                        udpsendpos = 0;
                        setstdhead(udpsendpacket, &udpsendpos);
                        setaquery(udpsendpacket, &udpsendpos, domain);
                        //初始化DNS服务器地址
                        strcpy(ip, "127.0.0.3");
                        udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                        //查询
                        while (1)
                        {
                            sendto(udpSocket, udpsendpacket, udpsendpos, 0, (struct sockaddr*)&udpRemoteAddr, sizeof(struct sockaddr));
                            printf("server send packet to %s\n", ip);
                            recvfrom(udpSocket, udprecvpacket, sizeof(udprecvpacket), 0, (struct sockaddr*)&udpRemoteAddr, &udpaddrlen);
                            printf("server recv packet from %s\n", ip);


                            struct DNS_Head h2;
                            struct DNS_RR r2;
                            udprecvpos = 0;
                            gethead(udprecvpacket, &udprecvpos, &h2);
                            getrr(udprecvpacket, &udprecvpos, &r2);

                            if (r2.rtype == 2)
                            {
                                strcpy(ip, r2.rdata);
                                udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                            }
                            else if (r2.rtype == 1)
                            {
                                for (i = 2; i < sizeof(udprecvpacket); ++i)
                                {
                                    tcpsendpacket[i] = udprecvpacket[i - 2];
                                }
                                tcpsendpos = udprecvpos + 2;
                                *(unsigned short*)tcpsendpacket = htons(tcpsendpos - 2);
                                flag = 1;
                                break;
                            }
                        }
                        break;
                    }
                }
                else if (rr.rtype == 15)//MX类型的查询 进行第二次查询
                {
                    //生成查询报文
                    unsigned char domain[64];
                    strcpy(domain, rr.rdata);
                    formdomain(domain);

                    udpsendpos = 0;
                    setstdhead(udpsendpacket, &udpsendpos);
                    setaquery(udpsendpacket, &udpsendpos, domain);
                    //初始化DNS服务器ip
                    strcpy(ip, "127.0.0.3");
                    udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                    //查询
                    while (1)
                    {
                        sendto(udpSocket, udpsendpacket, udpsendpos, 0, (struct sockaddr*)&udpRemoteAddr, sizeof(struct sockaddr));
                        printf("server send packet to %s\n", ip);

                        recvfrom(udpSocket, udprecvpacket, sizeof(udprecvpacket), 0, (struct sockaddr*)&udpRemoteAddr, &udpaddrlen);
                        printf("server recv packet from %s\n", ip);

                        struct DNS_Head h2;
                        struct DNS_RR r2;
                        udprecvpos = 0;
                        gethead(udprecvpacket, &udprecvpos, &h2);
                        getrr(udprecvpacket, &udprecvpos, &r2);

                        if (r2.rtype == 2)
                        {
                            strcpy(ip, r2.rdata);
                            udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                        }
                        else if (r2.rtype == 1)
                        {
                            *(unsigned short*)(tcpsendpacket + 12) = htons(1);
                            setrr(tcpsendpacket, &tcpsendpos, r2);
                            *(unsigned short*)tcpsendpacket = htons(tcpsendpos - 2);
                            flag = 1;
                            break;
                        }
                    }
                    break;
                }
                break;
            case (unsigned short)0x8400://回答是另一个DNS服务器
                if (rr.rtype == 2)//NS
                {
                    //设置新的ip地址
                    strcpy(ip, rr.rdata);
                    udpRemoteAddr.sin_addr.s_addr = inet_addr(ip);
                }
                break;
            }
            if (flag == 1)
                break;
        }

        send(tcpClientSocket, tcpsendpacket, tcpsendpos, 0);
        printf("server send packet to client\n");

        rrnum = rrnum % 4;
        tcpsendpos = 2;
        gethead(tcpsendpacket, &tcpsendpos, &head);
        getrr(tcpsendpacket, &tcpsendpos, &rrdb[rrnum]);
        if (rrdb[rrnum].rtype != 15)
        {
            strcpy(dbptr, rrdb[rrnum].rname);
            rrdb[rrnum].rname = dbptr;
            dbptr += strlen(dbptr) + 1;
            strcpy(dbptr, rrdb[rrnum].rdata);
            rrdb[rrnum].rdata = dbptr;
            dbptr += strlen(dbptr) + 1;
            rrnum++;
        }
        //打印cache
        printf("cache:\n");
	for (i = 0; i < rrnum; ++i)
        {
            printf("%s %s\n", rrdb[i].rname, rrdb[i].rdata);
        }
    }
}

void formdomain(unsigned char* domain)
{
    unsigned char dotdomain[64];
    int i = 0;
    while (domain[i] != '\0')
    {
        dotdomain[i] = domain[i];
        ++i;
    }
    dotdomain[i] = '\0';

    int counter;
    unsigned char* flag;
    unsigned char* ptr = dotdomain;
    while (1)
    {
        counter = 0;
        flag = domain++;
        while (1)
        {
            if (*ptr == '.' || *ptr == '\0')
                break;
            *domain++ = *ptr++;
            counter++;
        }
        *flag = (unsigned char)counter;
        if (*ptr == '\0')
        {
            *domain = '\0';
            break;
        }
        ptr++;
    }
}

void gethead(unsigned char* packet, int* packetlen, struct DNS_Head* head)
{
    packet += *packetlen;

    *head = *(struct DNS_Head*)packet;

    head->id = ntohs(head->id);
    head->tag = ntohs(head->tag);
    head->queryNum = ntohs(head->queryNum);
    head->answerNum = ntohs(head->answerNum);
    head->authorNum = ntohs(head->authorNum);
    head->addNum = ntohs(head->addNum);

    *packetlen += 12;
}

void getquery(unsigned char* packet, int* packetlen, struct DNS_Query* query)
{
    packet += *packetlen;

    query->qname = packet;
    *packetlen += strlen(packet) + 1;
    packet += strlen(packet) + 1;

    query->qtype = ntohs(*(unsigned short*)packet);
    packet += 2;
    query->qclass = ntohs(*(unsigned short*)packet);

    *packetlen += 4;
}

void getrr(unsigned char* packet, int* packetlen, struct DNS_RR* rr)
{
    packet += *packetlen;

    rr->rname = packet;
    *packetlen += strlen(packet) + 1;
    packet += strlen(packet) + 1;

    rr->rtype = ntohs(*(unsigned short*)packet);
    packet += 2;
    rr->rclass = ntohs(*(unsigned short*)packet);
    packet += 2;
    rr->ttl += ntohl(*(unsigned int*)packet);
    packet += 4;
    rr->datalen = ntohs(*(unsigned short*)packet) - 1;
    packet += 2;
    packet++;
    rr->rdata = packet;
    
    *packetlen += rr->datalen + 10 + 1;
}

void setstdhead(unsigned char* packet, int* packetlen)
{
    packet += *packetlen;

    struct DNS_Head head;

    head.id = htons((unsigned short)clock());
    head.tag = htons((unsigned short)0x0000);
    head.queryNum = htons((unsigned short)1);
    head.answerNum = htons((unsigned short)0);
    head.authorNum = htons((unsigned short)0);
    head.addNum = htons((unsigned short)0);

    unsigned char* ptr = (unsigned char*)&head;
    int i;
    for (i = 0; i < 12; ++i)
    {
        *packet++ = *ptr++;
    }

    *packetlen += 12;
}

void setreshead(unsigned char* packet, int* packetlen, int id)
{
    packet += *packetlen;

    struct DNS_Head head;

    head.id = htons((unsigned short)id);
    head.tag = htons((unsigned short)0x8000);
    head.queryNum = htons((unsigned short)0);
    head.answerNum = htons((unsigned short)1);
    head.authorNum = htons((unsigned short)0);
    head.addNum = htons((unsigned short)0);

    unsigned char* ptr = (unsigned char*)&head;
    int i;
    for (i = 0; i < 12; ++i)
    {
        *packet++ = *ptr++;
    }

    *packetlen += 12;
}

void setaquery(unsigned char* packet, int* packetlen, unsigned char* domain)
{
    struct DNS_Query query;

    query.qname = domain;
    query.qtype = htons(1);
    query.qclass = htons(1);

    packet += *packetlen;

    int i;
    unsigned char* ptr = query.qname;
    for (i = 0; i < strlen((char*)query.qname) + 1; ++i)
    {
        *packet++ = *ptr++;
    }
    *packetlen += strlen((char*)query.qname) + 1;

    *(unsigned short*)packet = query.qtype;
    packet += 2;
    *(unsigned short*)packet = query.qclass;

    *packetlen += 4;
}

void setrr(unsigned char* packet, int* packetlen, struct DNS_RR rr)
{
    packet += *packetlen;

    int i;
    unsigned char* ptr = rr.rname;
    for (i = 0; i < strlen(rr.rname) + 1; ++i)
    {
        *packet++ = *ptr++;
    }
    *packetlen += strlen(rr.rname) + 1;

    *(unsigned short*)packet = htons(rr.rtype);
    packet += 2;
    *(unsigned short*)packet = htons(rr.rclass);
    packet += 2;
    *(unsigned int*)packet = htonl(rr.ttl);
    packet += 4;
    *(unsigned short*)packet = htons(rr.datalen + 1);
    packet += 2;
    *packet++ = 0x68;
    ptr = rr.rdata;
    for (i = 0; i < rr.datalen; ++i)
    {
        *packet++ = *ptr++;
    }
    *packetlen += rr.datalen + 10 + 1;
}











