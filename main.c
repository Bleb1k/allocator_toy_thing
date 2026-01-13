#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// this allocator has overhead of 21 bytes per allocation
// recommended to use for allocations of size > 128
// TODO: buddy allocator for sizes <= 128

void *alloc_base = NULL;
void *alloc_end = NULL;
void *alloc_cursor = NULL;
void *alloc_last_allocation = NULL;
void *alloc_last_free = NULL;
#define alloc_meta_sizeof    (sizeof(void *) * 2 + sizeof(uint32_t) + sizeof(char))
#define alloc_meta_prev(ptr) (void **)(ptr)
#define alloc_meta_next(ptr) (void **)((ptr) + sizeof(void *))
#define alloc_meta_size(ptr) (uint32_t *)((ptr) + sizeof(void *) * 2)
#define alloc_meta_tag(ptr)  (char *)((ptr) + sizeof(void *) * 2 + sizeof(uint32_t))
#define alloc_meta_data(ptr) (void *)((ptr) + sizeof(void *) * 2 + sizeof(uint32_t) + sizeof(char))

enum {
	ALLOCATION_INVALID = 0,
	ALLOCATION_UNUSED = 1,
	ALLOCATION_USED = 2,
};

void
allocation_dump(void *ptr)
{
	ptr -= alloc_meta_sizeof;
	void *prev = *alloc_meta_prev(ptr);
	void *next = *alloc_meta_next(ptr);
	const char *tag;
	switch (*alloc_meta_tag(ptr)) {
	case ALLOCATION_UNUSED:
		tag = "<unused>";
		break;
	case ALLOCATION_USED:
		tag = "<used>";
		break;
	default:
	case ALLOCATION_INVALID:
		tag = "<invalid>";
		break;
	}
	printf("%p: Allocation{prev: %p, next: %p, size: %d, tag: %s}\n", ptr, prev, next, *alloc_meta_size(ptr), tag);
}

void
alloc_init(void)
{
	alloc_base = malloc(32 << 20);    // 32MB
	alloc_cursor = alloc_base;
	alloc_end = alloc_base + (32 << 20);
}

char
allocation_check_next(void *ptr)
{
	return *alloc_meta_tag(ptr + *alloc_meta_size(ptr) + alloc_meta_sizeof);
}

void
allocation_pop(void *ptr)
{
	void *next = *alloc_meta_next(ptr);
	void *prev = *alloc_meta_prev(ptr);
	if (next)
		*alloc_meta_prev(next) = prev;
	if (prev)
		*alloc_meta_next(prev) = next;
}

// links b instead of a, a retains links, flush manually
void
allocation_switch(void *a, void *b)
{
	void *next = *alloc_meta_next(a);
	void *prev = *alloc_meta_prev(a);
	if (next) {
		*alloc_meta_prev(next) = b;
		*alloc_meta_next(b) = next;
	}
	if (prev) {
		*alloc_meta_next(prev) = b;
		*alloc_meta_prev(b) = prev;
	}
}

void *
alloc_reserve(size_t size)
{
	void *cursor;

	if (!alloc_last_free) {
		*alloc_meta_size(alloc_cursor) = size;
		cursor = alloc_cursor;
		alloc_cursor += alloc_meta_sizeof + size;
		return cursor;
	}

	cursor = alloc_last_free;

	if (*alloc_meta_size(cursor) >= size) {
		alloc_last_free = *alloc_meta_next(cursor);
		allocation_pop(cursor);
		return cursor;
	}

	while (cursor && *alloc_meta_size(cursor) < size) {
		// add merging code here, this may introduce overhead
		cursor = *alloc_meta_next(cursor);
	}

	if (!cursor) {
		if (alloc_end - alloc_cursor < alloc_meta_sizeof + size)
			return NULL;    // OutOfMemory
		*alloc_meta_size(alloc_cursor) = size;
		cursor = alloc_cursor;
		alloc_cursor += alloc_meta_sizeof + size;
	} else if (*alloc_meta_size(cursor) - size > alloc_meta_sizeof * 3) {
		void *next = alloc_meta_data(cursor) + *alloc_meta_size(cursor) - size - alloc_meta_sizeof;
		*alloc_meta_size(cursor) -= alloc_meta_sizeof + size;
		*alloc_meta_size(next) = size;
		return next;
	}

	return cursor;
}

// linked_list, single allocation is limited to 4GB
void *
alloc(size_t size)
{
	void *allocation = alloc_reserve(size);    // alloc_cursor;
	// 0
	// - void *prev - NULL is none
	// sizeof(void*)
	// - void *next - NULL is none
	// sizeof(void*) * 2
	// - uint32_t size
	// sizeof(void*) * 2 + sizeof(uint32_t)
	// - char tag

	if (alloc_last_allocation) {
		*alloc_meta_prev(allocation) = alloc_last_allocation;
		*alloc_meta_next(alloc_last_allocation) = allocation;
	}

	*alloc_meta_tag(allocation) = ALLOCATION_USED;

	alloc_last_allocation = allocation;
	alloc_cursor = allocation + alloc_meta_sizeof + size;
	return alloc_meta_data(allocation);
}

void
fre(void *ptr)
{
	void *next, *prev;

	ptr -= alloc_meta_sizeof;
	*alloc_meta_tag(ptr) = ALLOCATION_UNUSED;

	// unlink from allocated
	allocation_pop(ptr);
	*alloc_meta_next(ptr) = NULL;
	*alloc_meta_prev(ptr) = NULL;

	// put as last free
	*alloc_meta_next(ptr) = alloc_last_free;
	if (alloc_last_free)
		*alloc_meta_prev(alloc_last_free) = ptr;
	alloc_last_free = ptr;

	// merge unused memory in sequence (forward)
	next = ptr + alloc_meta_sizeof + *alloc_meta_size(ptr);
	while (*alloc_meta_tag(next) == ALLOCATION_UNUSED) {
		*alloc_meta_size(ptr) += *alloc_meta_size(next) + alloc_meta_sizeof;
		allocation_pop(next);
		*alloc_meta_next(next) = NULL;
		*alloc_meta_prev(next) = NULL;
		next = ptr + alloc_meta_sizeof + *alloc_meta_size(ptr);
	}
}

int
main(int argc, char **argv)
{
	alloc_init();

	printf("base: %p; end: %p;\n", alloc_base, alloc_end);
	void *foo = alloc(10), *bar = alloc(43), *baz = alloc(57), *qux = alloc(162);

	printf("\n");
	fre(baz);
	allocation_dump(foo);
	allocation_dump(bar);
	allocation_dump(baz);
	allocation_dump(qux);

	printf("\n");
	fre(qux);
	allocation_dump(foo);
	allocation_dump(bar);
	allocation_dump(baz);
	allocation_dump(qux);

	printf("\n");
	fre(foo);
	allocation_dump(foo);
	allocation_dump(bar);
	allocation_dump(baz);
	allocation_dump(qux);

	printf("\n");
	fre(bar);
	allocation_dump(foo);
	allocation_dump(bar);
	allocation_dump(baz);
	allocation_dump(qux);

	free(alloc_base);
	return 0;
}
