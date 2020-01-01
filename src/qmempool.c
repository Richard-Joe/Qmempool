#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

struct Qmempool {
    int fd;
    char filepath[128];
    char *startaddr;// 内存首地址
    char *pos;      // 记录剩余空间的首地址（忽略内存碎片）
    size_t size;    // 内存空间总大小
    size_t free;    // 剩余空间大小（忽略内存碎片）
};

static struct Qmempool g_pool = {.fd = -1};

struct mem_node_hdr {
    // char is_free;            // 是否被释放，1-已释放，0-使用中
    struct mem_node_hdr *next;  // 指向下个节点的指针
    struct mem_node_hdr *prev;  // 指向上个节点的指针
    size_t size;                // 节点数据内存空间大小
    char data[0];               // 节点数据的首地址
}__attribute__((packed));

// 节点头部大小
#define NODE_HDR_SIZE sizeof(struct mem_node_hdr)

// 节点大小，头部+数据
#define NODE_SIZE(n) (NODE_HDR_SIZE + n->size)

// 节点尾部指针
#define NODE_TAIL_PTR(n) (n + NODE_SIZE(n))

// 头节点
#define HEAD_NODE_PRT ((struct mem_node_hdr *)g_pool.startaddr)

// 起始节点指针
#define START_NODE_PTR ((struct mem_node_hdr *)(g_pool.startaddr + NODE_HDR_SIZE))

#define container_of(ptr, type, member) ({  \
    void *__mptr = (void *)(ptr);           \
    ((type *)(__mptr - offsetof(type, member))); })

// 根据ptr获取节点
#define NODE_ENTRY(ptr) container_of(ptr, struct mem_node_hdr, data)

// 遍历节点
#define MEM_NODE_FOR_EACH(start, node) \
    for (node = start; node->next != NULL; node=node->next)


static struct mem_node_hdr *__alloc_node(size_t size)
{
    struct mem_node_hdr *node, *newnode;
    MEM_NODE_FOR_EACH(HEAD_NODE_PRT, node) {
        if (node->next - NODE_TAIL_PTR(node) > size)
            break;
    }

    newnode = NODE_TAIL_PTR(node);
    memset(newnode, 0, NODE_HDR_SIZE + size);
    newnode->size = size;

    newnode->prev = node;
    newnode->next = node->next;
    if (node->next) node->next->prev = newnode;
    node->next = newnode;

    // printf("newnode: %p, pos: %p\n", (char *)newnode, g_pool.pos);

    if ((char *)newnode == g_pool.pos) {
        if (size > g_pool.free)
            return NULL;
        g_pool.pos += NODE_SIZE(newnode);
        g_pool.free -= NODE_SIZE(newnode);
    }

    printf("[__alloc_node] addr: %p, size: %u\n", newnode->data, newnode->size);

    return newnode;
}

static void __free_node(struct mem_node_hdr *node)
{
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    printf("[__free_node] addr: %p, size: %u\n", node->data, node->size);
    memset(node, 0, NODE_SIZE(node));
}


static inline void Qmempool_clear(void)
{
    remove(g_pool.filepath);
    memset(&g_pool, 0, sizeof(g_pool));
    g_pool.fd = -1;
}


int Qmmap_init(const char *filepath, size_t size)
{
    int fd;
    struct stat st;

    fd = open(filepath, O_RDWR | O_CREAT, 0700);
    if (fd < 0) {
        printf("open file %s error.\n", filepath);
        return -1;
    }

    if (stat(filepath, &st) < 0) {
        printf("stat file %s error.\n", filepath);
        goto err;
    }

    if (st.st_size < size && ftruncate(fd, size) != 0) {
        printf("set size failed.\n");
        goto err;
    }
    g_pool.startaddr = (char *)mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    if (g_pool.startaddr == MAP_FAILED) {
        printf("mmap failed.\n");
        goto err;
    }
    g_pool.pos = g_pool.startaddr;
    g_pool.size = size;
    g_pool.free = size;
    g_pool.fd = fd;
    snprintf(g_pool.filepath, sizeof(g_pool.filepath), "%s", filepath);

    memset(HEAD_NODE_PRT, 0, NODE_HDR_SIZE);
    return 0;

err:
    close(fd);
    Qmempool_clear();
    return -1;
}

void Qmmap_fini(void)
{
    if (g_pool.fd >= 0)
        close(g_pool.fd);

    if (g_pool.startaddr)
        munmap(g_pool.startaddr, g_pool.size);

    Qmempool_clear();
}

void *Qmalloc(size_t size)
{
    struct mem_node_hdr *newnode;
    newnode = __alloc_node(size);
    if (!newnode) {
        printf("NO MEM!!!\n");
        return NULL;
    }
    return (void *)newnode->data;
}

void Qfree(void *ptr)
{
    struct mem_node_hdr *node;
    node = NODE_ENTRY(ptr);
    __free_node(node);
}

void *Qcalloc(size_t nmemb, size_t size)
{
    return Qmalloc(nmemb * size);
}

void *Qrealloc(void *ptr, size_t size)
{
    struct mem_node_hdr *newnode, *oldnode;

    oldnode = NODE_ENTRY(ptr);
    // 这里不考虑内存变小的情况
    if(oldnode->size >= size)
        return NULL;
    newnode = __alloc_node(size);

    memcpy(newnode->data, oldnode->data, oldnode->size);

    __free_node(oldnode);

    return newnode->data;
}


void check_mem_leak(void)
{
    size_t total_size = 0;
    struct mem_node_hdr *node, *newnode;
    MEM_NODE_FOR_EACH(START_NODE_PTR, node) {
        printf("[MemLeak] Addr: %p, Size: %u\n", node->data, node->size);
        total_size += node->size;
    }
    printf("\n====== Total MemLeak ======\n size: %u\n\n", total_size);
}


#define KB_SIZE 1024

void QMPOOL_TEST_1(void)
{
    char *p1, *p2, *p3;

    p1 = (char *)Qmalloc(KB_SIZE);
    p2 = (char *)Qmalloc(KB_SIZE);
    p3 = (char *)Qcalloc(2, KB_SIZE);

    memset(p1, '1', KB_SIZE - 1);       p1[KB_SIZE] = '\0';
    memset(p2, '2', KB_SIZE - 1);       p2[KB_SIZE] = '\0';
    memset(p3, '3', 2 * KB_SIZE - 1);   p3[2 * KB_SIZE] = '\0';

    printf("p1: %s\n", p1);
    printf("p2: %s\n", p2);
    printf("p3: %s\n", p3);

    p2 = Qrealloc(p2, 2 * KB_SIZE);
    memset(p2, '2', 2 * KB_SIZE - 1);   p2[2 * KB_SIZE] = '\0';
    printf("p2: %s\n", p2);
    printf("p3: %s\n", p3);

    Qfree(p3);
    Qfree(p2);
    Qfree(p1);
}

void QMPOOL_TEST_2(void)
{
    char *p1, *p2, *p3, *p4, *p5;

    p1 = (char *)Qmalloc(2 * KB_SIZE);
    p2 = (char *)Qmalloc(KB_SIZE);

    memset(p1, '1', 2 * KB_SIZE - 1);   p1[2 * KB_SIZE] = '\0';
    memset(p2, '2', KB_SIZE - 1);       p2[KB_SIZE] = '\0';

    printf("p1: %s\n", p1);
    printf("p2: %s\n", p2);

    Qfree(p1);

    p3 = (char *)Qmalloc(KB_SIZE);
    p4 = (char *)Qmalloc(KB_SIZE);
    p5 = (char *)Qmalloc(KB_SIZE);

    memset(p3, '3', KB_SIZE - 1);       p3[KB_SIZE] = '\0';
    memset(p4, '4', KB_SIZE - 1);       p4[KB_SIZE] = '\0';
    memset(p5, '5', KB_SIZE - 1);       p5[KB_SIZE] = '\0';

    printf("p3: %s\n", p3);
    printf("p4: %s\n", p4);
    printf("p5: %s\n", p5);

    Qfree(p5);
    Qfree(p4);
    Qfree(p3);
    Qfree(p2);
}

int main(void)
{
    if (Qmmap_init("/qmempool_mmap", 100 * 1024 * 1024)) { // 100M
        printf("Qmmap_init error.\n");
        return -1;
    }


    QMPOOL_TEST_1();

    QMPOOL_TEST_2();


    check_mem_leak();

    Qmmap_fini();
    return 0;
}