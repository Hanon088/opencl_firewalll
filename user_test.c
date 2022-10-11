#define _XOPEN_SOURCE 700
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /* uintmax_t */
#include <string.h>
#include <sys/mman.h>
#include <unistd.h> /* sysconf */

/* Format documented at:
 * https://github.com/torvalds/linux/blob/v4.9/Documentation/vm/pagemap.txt
 */
typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return                0 for success, 1 for failure
 */
int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr)
{
    size_t nread;
    ssize_t ret;
    uint64_t data;

    nread = 0;
    while (nread < sizeof(data)) {
        ret = pread(pagemap_fd, ((uint8_t*)&data) + nread, sizeof(data),
                (vaddr / sysconf(_SC_PAGE_SIZE)) * sizeof(data) + nread);
        nread += ret;
        if (ret <= 0) {
            return 1;
        }
    }
    entry->pfn = data & (((uint64_t)1 << 54) - 1);
    entry->soft_dirty = (data >> 54) & 1;
    entry->file_page = (data >> 61) & 1;
    entry->swapped = (data >> 62) & 1;
    entry->present = (data >> 63) & 1;
    return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * @param[out] paddr physical address
 * @param[in]  pid   process to convert for
 * @param[in] vaddr  virtual address to get entry for
 * @return           0 for success, 1 for failure
 */
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr)
{
    char pagemap_file[BUFSIZ];
    int pagemap_fd;

    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        return 1;
    }
    PagemapEntry entry;
    if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
        return 1;
    }
    close(pagemap_fd);
    *paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    return 0;
}

enum { BUFFER_SIZE = 4 };

int main(int argc, char **argv)
{
    int fd;
    long page_size;
    char *address;
    char buf[BUFFER_SIZE];
    uintptr_t paddr;
    uint32_t *source_ip, *dest_ip;

    if (argc < 2) {
        printf("Usage: %s <mmap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    page_size = sysconf(_SC_PAGE_SIZE);
    printf("open pathname = %s\n", argv[1]);
    fd = open(argv[1], O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open");
        assert(0);
    }
    printf("fd = %d\n", fd);

    address = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (address == MAP_FAILED) {
        perror("mmap");
        assert(0);
    }
    
    while(1){
        memcpy(source_ip, address, 4);
        memcpy(dest_ip, address+4, 4);
        printf("OCL FIREWALL s %u.%u.%u.%u d %u.%u.%u.%u\n", ((unsigned char*)&source_ip)[3], ((unsigned char*)&source_ip)[2], ((unsigned char*)&source_ip)[1], ((unsigned char*)&source_ip)[0], ((unsigned char*)&dest_ip)[3], ((unsigned char*)&dest_ip)[2], ((unsigned char*)&dest_ip)[1], ((unsigned char*)&dest_ip)[0]);
    }
    if (munmap(address, page_size)) {
        perror("munmap");
        assert(0);
    }

    puts("close");
    close(fd);
    return EXIT_SUCCESS;
}