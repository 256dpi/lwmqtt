#ifndef __config_h__
#define __config_h__

// Donne une erreur dans si on utilise la première ligne, la deuxième ligne donne un "Warning", la troisième semble parfaite
//#define BLog(...) do {printf("Benoit:%s(%d): ", __FILE__, __LINE__);printf(" " ##__VA_ARGS__);printf("\n");} while(0)
//#define BLog(...) do {printf("Benoit:%s(%d): ", __FILE__, __LINE__);printf(" " __VA_OPT__(,) __VA_ARGS__);printf("\n");} while(0)
#define BLog(format, ...) do {printf("Benoit:%s:%s(%d): " format "\n", __FILE__, __func__, __LINE__ __VA_OPT__(,) __VA_ARGS__);} while(0)
#define BTraceIn do {printf("Benoit:%s:%s(%d):In \n", __FILE__, __func__, __LINE__);} while(0);
#define BTraceOut do {printf("Benoit:%s:%s(%d):Out \n", __FILE__, __func__, __LINE__);} while(0);


#endif // #ifndef __config_h__