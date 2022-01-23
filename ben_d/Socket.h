#ifndef __Socket_h__
#define __Socket_h__

#include <string>



/**
 * @brief Create and manage Socket
 * 
 */

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

class Socket 
{
    public:
        static const int KeepAliveDefaultValue;

        enum State {
            Unconnected,
            Connected
        };
        Socket();
        Socket(const char *host, int port, int keepalive = KeepAliveDefaultValue);
        void Init(const char *host = nullptr, int port = 0, int keepalive = KeepAliveDefaultValue, bool blocking = true, int sock = INVALID_SOCKET);
        State GetState();
        void SetState(State state) { mState = state;}
        bool IsConnected() {return (mState == Connected) ? true : false;}
        int Connect();
        void Close();
        void Print();
        int GetSocket() {return mSock;}

    private:
        std::string mHost;
        std::string mAddress;
        uint mKeepAlive;
        int mPort;
        bool mBlocking;
        int mSock;
        State mState;

        bool ForceNonBlocking(int sock);

};

#endif // #ifndef __Socket_h__

