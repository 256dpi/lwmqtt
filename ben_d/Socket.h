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
    enum State
    {
        Unconnected = 0,
        Connected
    };
    enum Msg
    {
        Success = 0,
        Err_InAddrInfo,
        Err_ConnectFailed,
        Err_InvalidSocket
    };
    Socket();
    Socket(const char *host, int port);
    void Init(const char *host = nullptr, int port = 0);
    State GetState() { return mState; };
    void SetState(State state) { mState = state; }
    bool IsConnected() { return (mState == Connected) ? true : false; }
    Msg Connect();
    void Close();
    void Print();
    int GetSocket() { return mSock; }
    bool ForceBlocking();
    bool ForceNonBlocking();

private:
    std::string mHost;
    std::string mAddress;
    int mPort;
    int mSock;
    State mState;
    enum BlockingMode_E
    {
        BlockingMode = 0,
        NonBlockingMode
    };
    bool SetSocketBlockingMode(BlockingMode_E mode);
};

#endif // #ifndef __Socket_h__
