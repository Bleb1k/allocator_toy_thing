#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// this allocator has overhead of 21 bytes per allocation
// recommended to use for allocations of size > 128
// TODO: buddy allocator for sizes <= 128

#define ALLOCATOR_SIZE    (32 << 20)
#define BEST_FIT_CAPACITY 8

void *alloc_base = NULL;
void *alloc_end = NULL;
void *alloc_cursor = NULL;
void *alloc_last_allocation = NULL;
void *alloc_last_free = NULL;
#if 1    // align data by 8 bytes
#define alloc_meta_sizeof ((sizeof(void *) * 2 + sizeof(uint32_t) + sizeof(char)) / 8 + 1) * 8
#else
#define alloc_meta_sizeof (sizeof(void *) * 2 + sizeof(uint32_t) + sizeof(char))
#endif
#define alloc_meta_prev(ptr) (void **)(ptr)
#define alloc_meta_next(ptr) (void **)((ptr) + sizeof(void *))
#define alloc_meta_size(ptr) (uint32_t *)((ptr) + sizeof(void *) * 2)
#define alloc_meta_tag(ptr)  (char *)((ptr) + sizeof(void *) * 2 + sizeof(uint32_t))
#define alloc_meta_data(ptr) (void *)((ptr) + alloc_meta_sizeof)

enum {
	ALLOCATION_INVALID = 0,
	ALLOCATION_UNUSED = 1,
	ALLOCATION_USED = 2,
};

#define dump_ptr(ptr) (ptr ? (void *)((ptr) - alloc_base + ALLOCATOR_SIZE) : NULL)

void
allocation_dump(void *ptr)
{
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
	printf("%p: Allocation{prev: %p, next: %p, size: %d, tag: %s}\n", dump_ptr(ptr), dump_ptr(prev), dump_ptr(next),
	       *alloc_meta_size(ptr), tag);
}

void
memory_dump()
{
	void *cursor = alloc_base;
	printf("\nlast: {alloc: %p, free: %p}, cursor: %p\n", dump_ptr(alloc_last_allocation), dump_ptr(alloc_last_free),
	       dump_ptr(alloc_cursor));
	while (cursor < alloc_end && *alloc_meta_size(cursor) > 0) {
		allocation_dump(cursor);
		cursor += alloc_meta_sizeof + *alloc_meta_size(cursor);
	}
}

#undef dump_ptr

void
alloc_init(void)
{
	alloc_base = malloc(ALLOCATOR_SIZE);    // 32MB
	alloc_cursor = alloc_base;
	alloc_end = alloc_base + ALLOCATOR_SIZE;
	printf("base: %p; end: %p; header_size: %d\n", alloc_base, alloc_end, (int)alloc_meta_sizeof);
}

char
allocation_check_next(void *ptr)
{
	return *alloc_meta_tag(ptr + *alloc_meta_size(ptr) + alloc_meta_sizeof);
}

void
allocation_unlink(void *ptr)
{
	void *next = *alloc_meta_next(ptr);
	void *prev = *alloc_meta_prev(ptr);
	if (next)
		*alloc_meta_prev(next) = prev;
	*alloc_meta_next(ptr) = NULL;
	if (prev)
		*alloc_meta_next(prev) = next;
	*alloc_meta_prev(ptr) = NULL;
}

// links b instead of a, a retains links, flush manually
void
allocation_replace(void *a, void *b)
{
	void *next = *alloc_meta_next(a);
	void *prev = *alloc_meta_prev(a);
	printf("%p <> %p\n", prev, next);
	if (next)
		*alloc_meta_prev(next) = b;
	*alloc_meta_next(b) = next;
	if (prev)
		*alloc_meta_next(prev) = b;
	*alloc_meta_prev(b) = prev;
}

void *
alloc_reserve(size_t size)
{
	void *cursor;
	void *best_fit[BEST_FIT_CAPACITY] = { 0 };
	size_t cur_size, best_size;
	char best_count = 0;

	if (!alloc_last_free) {
		*alloc_meta_size(alloc_cursor) = size;
		cursor = alloc_cursor;
		alloc_cursor += alloc_meta_sizeof + size;
		return cursor;
	}

	cursor = alloc_last_free;
	cur_size = *alloc_meta_size(cursor);

	if (cur_size == size) {
		alloc_last_free = *alloc_meta_next(cursor);
		goto end;
	} else if (cur_size > size) {
		best_fit[best_count++] = cursor;
		best_size = cur_size;
	}

	while (cursor) {
		cur_size = *alloc_meta_size(cursor);
		// add merging code here, this may introduce overhead
		if (cur_size < size) {
			void *next = cursor + alloc_meta_sizeof + cur_size;
			while (*alloc_meta_tag(next) == ALLOCATION_UNUSED) {
				if (best_count) {
					int remove_at = -1;
					for (int i = 0; i < best_count; i++) {
						if (remove_at >= 0) {
							best_fit[remove_at - (i - remove_at)] = best_fit[i];
							continue;
						}
						if (next == best_fit[i]) {
							remove_at = i;
						}
					}
					if (remove_at >= 0) {
						best_count -= 1;
						best_size = *alloc_meta_size(best_fit[best_count - 1]);
					}
				}
				cur_size += *alloc_meta_size(next) + alloc_meta_sizeof;
				allocation_unlink(next);
				next = cursor + alloc_meta_sizeof + cur_size;
			}
			*alloc_meta_size(cursor) = cur_size;
		}
		if (cur_size == size)
			goto end;
		if (cur_size > size && (best_count == 0 || cur_size < best_size)) {
			best_fit[best_count++] = cursor;
			best_size = cur_size;
			if (best_count == BEST_FIT_CAPACITY)
				break;
		}
		cursor = *alloc_meta_next(cursor);
	}

	if (best_count) {
		if (best_count == 1)
			alloc_last_free = *alloc_meta_next(alloc_last_free);
		cursor = best_fit[best_count - 1];
		cur_size = best_size;
	}

	if (!cursor) {
		if (alloc_end - alloc_cursor < alloc_meta_sizeof + size)
			return NULL;    // OutOfMemory
		*alloc_meta_size(alloc_cursor) = size;
		cursor = alloc_cursor;
		alloc_cursor += alloc_meta_sizeof + size;
	} else if (cur_size - size > alloc_meta_sizeof * 3) {
#if 1    // cut and reserve end
		void *next = alloc_meta_data(cursor) + cur_size - size - alloc_meta_sizeof;
		*alloc_meta_size(cursor) -= alloc_meta_sizeof + size;
		*alloc_meta_size(next) = size;
		return next;
#else    // cut and reserve head
		void *next = alloc_meta_data(cursor) + size;
		*alloc_meta_size(cursor) = size;
		*alloc_meta_size(next) = cur_size - alloc_meta_sizeof - size;
		*alloc_meta_tag(next) = ALLOCATION_UNUSED;
		allocation_replace(cursor, next);
		return cursor;
#endif
	}

end:;
	allocation_unlink(cursor);
	return cursor;
}

// linked_list, single allocation is limited to 4GB
void *
alloc(size_t size)
{
	void *allocation = alloc_reserve(size);    // alloc_cursor;
	if (allocation == NULL)
		return NULL;

	*alloc_meta_tag(allocation) = ALLOCATION_USED;

	if (allocation == alloc_last_free) {
		printf("\n");
		allocation_dump(allocation);
	}

	if (alloc_last_allocation)
		*alloc_meta_next(alloc_last_allocation) = allocation;
	*alloc_meta_prev(allocation) = alloc_last_allocation;
	alloc_last_allocation = allocation;

	memory_dump();
	return alloc_meta_data(allocation);
}

void
fre(void *ptr)
{
	void *next, *prev;

	ptr -= alloc_meta_sizeof;
	*alloc_meta_tag(ptr) = ALLOCATION_UNUSED;

	// unlink from allocated
	if (ptr == alloc_last_allocation)
		alloc_last_allocation = *alloc_meta_next(alloc_last_allocation);
	allocation_unlink(ptr);

	// put as last free
	*alloc_meta_next(ptr) = alloc_last_free;
	if (alloc_last_free)
		*alloc_meta_prev(alloc_last_free) = ptr;
	alloc_last_free = ptr;

	// merge unused memory (forward step)
	size_t new_size = *alloc_meta_size(ptr);
	next = ptr + alloc_meta_sizeof + new_size;
	while (*alloc_meta_tag(next) == ALLOCATION_UNUSED) {
		new_size += *alloc_meta_size(next) + alloc_meta_sizeof;
		allocation_unlink(next);
		next = ptr + alloc_meta_sizeof + new_size;
	}
	*alloc_meta_size(ptr) = new_size;

	memory_dump();
}

int
main(int argc, char **argv)
{
	alloc_init();

	void *m[] = {
		alloc(10), alloc(100), alloc(110), alloc(120), alloc(210), alloc(10101),
	};

	fre(m[1]);
	fre(m[3]);
	m[1] = alloc(110);
	m[3] = alloc(20);

	free(alloc_base);
	return 0;
}
