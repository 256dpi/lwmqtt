#include "config.h"
#include "Socket.h"

#include <string.h>
#include <iostream>

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

Socket::Socket()
{
    Init();
}

Socket::Socket(const char *host, int port, int keepalive) {
    Init(host, port, keepalive);
}
        
void Socket::Init(const char *host, int port, int keepalive, bool blocking, int sock)
{
    BLog("Socket::Init");
    mState = Unconnected;
    mHost = host;
    mPort = port;
    mKeepAlive = keepalive;
    mBlocking = blocking;
    mSock = sock;
}

void Socket::Print()
{
    std::cout << "mState      " << mState << std::endl;
    std::cout << "mHost       " << mHost << std::endl;
    std::cout << "mPort       " << mPort << std::endl;
    std::cout << "mKeepAlive  " << mKeepAlive << std::endl;
    std::cout << "mBlocking   " << mBlocking << std::endl;
    std::cout << "mSock       " << mSock << std::endl;
}

void Socket::Close()
{
    if (mSock != INVALID_SOCKET) {
        close(mSock);
    }
    SetState(Unconnected);

}

bool Socket::ForceNonBlocking(int sock)
{
    bool retVal = true;
    int opt;
    /* Set non-blocking */
    opt = fcntl(sock, F_GETFL, 0);
    if(opt == -1){
        BLog("Error: return -1");
        retVal = false;
    }
    if(fcntl(sock, F_SETFL, opt | O_NONBLOCK) == -1) {
        BLog("Error: fcntl failed");
        retVal = false;
    }
    return retVal;
}

int Socket::Connect()
{
    struct addrinfo hints;
    struct addrinfo *ainfo, *curainfo;
    int s;
    int retVal = 0;

    BTraceIn
    mSock = INVALID_SOCKET;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    BLog("mHost: %s", mHost.c_str());
    s = getaddrinfo(mHost.c_str(), nullptr, &hints, &ainfo);
    if (s) {
        BLog("Erreur: getaddrinfo return ");
        errno = s;
        retVal = 1;  // TODO:Benoit  Changer les messages d'erreurs
    }
    else {
        for( curainfo = ainfo; curainfo != nullptr; curainfo = curainfo->ai_next)
        {
            mSock = socket(curainfo->ai_family, curainfo->ai_socktype, curainfo->ai_protocol);
            if(mSock == INVALID_SOCKET) 
            {
                BLog("Connection failed INVALID_SOCKET");
                continue;
            }

            if (!mBlocking){
                if( !ForceNonBlocking(mSock) ) {
                    mSock = INVALID_SOCKET;
                }
            }
            if (mSock != INVALID_SOCKET) {
                retVal = connect(mSock, curainfo->ai_addr, curainfo->ai_addrlen);
                        
                if(retVal == 0 || errno == EINPROGRESS || errno == EWOULDBLOCK){
                    if(retVal < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK)){
                        retVal = 2;  //TODO: Benoit  Changer les messages d'erreurs
                    }

                    if(mBlocking){
                        /* Set non-blocking */
                        if( ForceNonBlocking(mSock) ) {
                            break;
                        }
                    }
                    else {
                        break;
                    }

                }
            }
            mSock = INVALID_SOCKET;
            close(mSock);
        }
        if( mSock != INVALID_SOCKET)
            SetState(Connected);
    }
    BTraceOut;
    return retVal;
}
