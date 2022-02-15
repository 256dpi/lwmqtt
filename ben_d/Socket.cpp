#include "config.h"
#include "Socket.h"

#include <cstring>
#include <iostream>

#include <errno.h>
#include <fcntl.h>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#if AP
#include <aruba/util/grouplog_cloudconnect.h>
#else
#include <config.h>
#endif

Socket::Socket()
{
    Init();
}

Socket::Socket(const char *host, int port) {
    Init(host, port);
}
        
void Socket::Init(const char *host, int port)
{
    Close();
    if (host != nullptr)
        mHost = host;
    else
        mHost = "";
    mPort = port;
}

void Socket::Close()
{
    if (mSock != INVALID_SOCKET) {
        close(mSock);
    }
    mSock = INVALID_SOCKET;
    SetState(Unconnected);
}

bool Socket::SetSocketBlockingMode(BlockingMode_E mode )
{
    int opt;
    /* Set non-blocking */
    opt = fcntl(mSock, F_GETFL, 0);
    if(opt != -1){
        if (mode == BlockingMode )
            opt = fcntl(mSock, F_SETFL, opt & ~O_NONBLOCK);
        else
            opt = fcntl(mSock, F_SETFL, opt | O_NONBLOCK);
    }
    return opt==-1 ? false : true;
}

bool Socket::ForceBlocking()
{
    return SetSocketBlockingMode(BlockingMode_E::BlockingMode);
}

bool Socket::ForceNonBlocking()
{
    return SetSocketBlockingMode(BlockingMode_E::NonBlockingMode);
}

/*
    Connect socket to mHost:mPort
    Will force socket to blocking mode during the connection then set socket to non-blocking.
    Return: 
    Success, connection established,
    Err_InAddrInfo, error when initialising getaddrinfo struct.
    Err_ConnectionFailed, error cannot connect to mHost.
    Err_InvalidSocket, invalid socket.
*/
Socket::Msg Socket::Connect()
{
    struct addrinfo hints;
    struct addrinfo *ainfo, *curainfo;
    int result;
    Socket::Msg retVal = Success;


    Close();

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    result = getaddrinfo(mHost.c_str(), nullptr, &hints, &ainfo);
    if (result != 0) {
        GLERROR_MQTTCLIENT("Error: getaddrinfo return errno %d", result);
        retVal = Err_InAddrInfo;
    }
    else {
        for( curainfo = ainfo; curainfo != nullptr; curainfo = curainfo->ai_next) {
            mSock = socket(curainfo->ai_family, curainfo->ai_socktype, curainfo->ai_protocol);
            if(mSock == INVALID_SOCKET) {
                continue;
            }
            if(curainfo->ai_family == AF_INET){
                ((struct sockaddr_in *)curainfo->ai_addr)->sin_port = htons(mPort);
            } else if(curainfo->ai_family == AF_INET6){
                ((struct sockaddr_in6 *)curainfo->ai_addr)->sin6_port = htons(mPort);
            }else{
                close(mSock);
                mSock = INVALID_SOCKET;
                continue;
            }

            if( !ForceBlocking() ) {
                mSock = INVALID_SOCKET;
            }
            if (mSock != INVALID_SOCKET) {
                result = connect(mSock, curainfo->ai_addr, curainfo->ai_addrlen);
                        
                if(result == 0 || errno == EINPROGRESS || errno == EWOULDBLOCK){
                    if(result < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK)){
                        retVal = Err_ConnectFailed;
                    }
                    /* Set non-blocking */
                    if( ForceNonBlocking() ) {
                        break;
                    }
                }
            }
            Close();
        }
    }
    if( mSock != INVALID_SOCKET)
    {
        SetState(Connected);
        retVal = Err_InvalidSocket;
    }        
    return retVal;
}

//#define UTest
#ifdef UTest
int main(int argc, char* argv[])
{
    Socket mSock("iot.isb.arubanetworks.com", 443);
    for (int i=0; i<1; i++){
        std::cout << (mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected") << std::endl;
        mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected";
        Socket::Msg msg = mSock.Connect();
        std::cout << "Connect returns " << msg << std::endl;
        std::cout << (mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected") << std::endl;
        std::cout << "Socket number is " << mSock.GetSocket() << std::endl;
        mSock.Close();
    }
}
#endif // #ifdef UTest