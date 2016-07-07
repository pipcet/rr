#if 1
/* 0x8000000 - LwpInt: threshold interrupt
 * 0x4000000 - LwpPTSC: performance time stamp counter in event record
 * 0x2000000 - LwpCont: continuous mode sampling. This is required(?!).
 */
#define LWP_FLAGS 0xe0000008L
#define LWP_EVENT          2L
#define LWP_FILTER 0x28000000L
#define LWP_OFFSET 0
#elif 0
#define LWP_FLAGS 0x80000008L
#define LWP_EVENT          2L
#define LWP_FILTER 0x28000000L
#elif 0
#define LWP_FLAGS 0x80000004L
#define LWP_EVENT          1L
#define LWP_FILTER 0x00000000L
#define LWP_OFFSET 4
#elif 1
#define LWP_FLAGS 0x80000008L
#define LWP_EVENT          2L
#define LWP_FILTER 0x00000000L
#define LWP_OFFSET 4
#endif
