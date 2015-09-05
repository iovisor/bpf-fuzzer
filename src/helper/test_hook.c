#include <stdio.h>
#include <stdlib.h>

/* some kernel types */
typedef unsigned gfp_t;

/* externs */
extern void bpf_map_put_k(void *map);
extern unsigned long __fdget_k(unsigned int fd);
extern void *bpf_prog_realloc_k(void *fp_old, unsigned int size);

/* for no optimization level specified, the following interface mockings are required */
unsigned long phys_base = 0x0;
void * __kmalloc(size_t size, gfp_t flags) {
	void *p = malloc(size);
#define ___GFP_ZERO             0x8000u
	if (flags & ___GFP_ZERO)
		memset(p, 0, size);
	return p;
}

void *vmalloc(unsigned long size) {
	return malloc(size);
}

void kfree(const void *addr) {
	free(addr);
}

void vfree(const void *addr) {
	free(addr);
}

void warn_slowpath_fmt(const char *file, int line, const char *fmt, ...) {
}

unsigned long _copy_to_user(void *to, const void *from, unsigned n) {
	memcpy(to, from, n);
	return 0;
}

unsigned long _copy_from_user(void *to, const void *from, unsigned n) {
	memcpy(to, from, n);
	return 0;
}

void bpf_map_put(void *map) {
	bpf_map_put_k(map);
}

void *bpf_prog_realloc(void *fp_old, unsigned int size, gfp_t flags) {
	return bpf_prog_realloc_k(fp_old, size);
}

void mutex_lock(void *lock) {
	/* sorry, not support multithreading yet */
	return;
}
void mutex_unlock(void *lock) {
	return;
}

int vscnprintf(char *buf, size_t size, const char *fmt, va_list args) {
        int i;

        i = vsnprintf(buf, size, fmt, args); 

        if (i < size)   
                return i;
        if (size != 0)          
                return size - 1;
        return 0;
}

void fput(struct file *fp) {
	/* do nothing now */
}

void *__memcpy(void *to, const void *from, size_t len) {
	return memcpy(to, from, len);
}

/* __fdget requires maps already associated with fd.
 * bpf_map_get needs to return information related to a map.
 * Needs to sort it out.
 */
unsigned long __fdget(unsigned int fd) {
	unsigned long r = __fdget_k(fd);
	return r;
}

struct fd {
	struct file *file;
	unsigned int flags;
};
void *bpf_map_get(struct fd f) {
	return f.file;
}
