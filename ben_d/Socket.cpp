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

const int Socket::KeepAliveDefaultValue = 60;

Socket::Socket()
{
    Init();
}

Socket::Socket(const char *host, int port, int keepalive) {
    Init(host, port, keepalive);
}
        
void Socket::Init(const char *host, int port, int keepalive, bool blocking, int sock)
{
    mState = Unconnected;
    if (host != nullptr)
        mHost = host;
    else
        mHost = "";
    mPort = port;
    mKeepAlive = keepalive;
    mSock = sock;
    mBlocking = blocking;
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
    mSock = INVALID_SOCKET;
    SetState(Unconnected);

}

bool Socket::SetSocketBlockingMode(int sock, BlockingMode_E mode )
{
    int opt;
    /* Set non-blocking */
    opt = fcntl(sock, F_GETFL, 0);
    if(opt != -1){
        if (mode == BlockingMode )
            opt = fcntl(sock, F_SETFL, opt & ~O_NONBLOCK);
        else
            opt = fcntl(sock, F_SETFL, opt | O_NONBLOCK);
    }
    return opt==-1 ? false : true;
}
/*
bool Socket::ForceBlocking(int sock)
{
    return SetSocketBlockingMode(sock, BlockingMode_E::BlockingMode);
}
*/
bool Socket::ForceNonBlocking(int sock)
{
    return SetSocketBlockingMode(sock, BlockingMode_E::NonBlockingMode);
}

int Socket::Connect()
{
    struct addrinfo hints;
    struct addrinfo *ainfo, *curainfo;
    int s, retVal = 0;


    Close();
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    BLog("mHost: %s", mHost.c_str());
    s = getaddrinfo(mHost.c_str(), nullptr, &hints, &ainfo);
    if (s != 0) {
        BLog("Erreur: getaddrinfo return ");
        errno = s;
        retVal = 1;  // TODO:Benoit  Changer les messages d'erreurs
    }
    else {
        for( curainfo = ainfo; curainfo != nullptr; curainfo = curainfo->ai_next) {
            mSock = socket(curainfo->ai_family, curainfo->ai_socktype, curainfo->ai_protocol);
            if(mSock == INVALID_SOCKET) {
                BLog("Connection failed INVALID_SOCKET");
                continue;
            }
            if(curainfo->ai_family == AF_INET){
                ((struct sockaddr_in *)curainfo->ai_addr)->sin_port = htons(mPort);
                BLog("AF_INET");
            } else if(curainfo->ai_family == AF_INET6){
                ((struct sockaddr_in6 *)curainfo->ai_addr)->sin6_port = htons(mPort);
                BLog("AF_INET6");
            }else{
                BLog("else COMPAT_CLOSE");
                close(mSock);
                mSock = INVALID_SOCKET;
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
                    //  TODO:Benoit Que faire ici, on dirait qu'il devrait y avoir un else ou autre chose. retVal == 2 on fait quoi, si ForceNonBlocking ne fonctionne pas ???
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
            Close();
        }
    }
    if( mSock != INVALID_SOCKET)
        SetState(Connected);
    BTraceOut;
    return retVal;
}

#ifdef UTest
int main(int argc, char* argv[])
{
    Socket mSock("iot.isb.arubanetworks.com", 443);
    for (int i=0; i<1; i++){
        std::cout << (mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected") << std::endl;
        mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected";
        mSock.Connect();
        std::cout << (mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected") << std::endl;
        std::cout << "Socket number is " << mSock.GetSocket() << std::endl;
        mSock.Print();
        mSock.Close();
    }
}
#endif // #ifdef UTest