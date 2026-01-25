#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// this allocator has overhead of 21 bytes per allocation
// recommended to use for allocations of size > 128

#define ALLOCATOR_SIZE    (32 << 20)
#define BEST_FIT_CAPACITY 8

void *alloc_base = NULL;
void *alloc_end = NULL;
void *alloc_cursor = NULL;
void *alloc_last_allocation = NULL;
void *alloc_last_free = NULL;
void *alloc_slab_last_4b = NULL;
void *alloc_slab_last_8b = NULL;
void *alloc_slab_last_16b = NULL;
void *alloc_slab_last_32b = NULL;
void *alloc_slab_last_64b = NULL;
void *alloc_slab_last_128b = NULL;
void *alloc_slab_last_256b = NULL;

#define alloc_meta_sizeof           (size_t)alloc_meta_data(0)
#define alloc_meta_prev(ptr)        (void **)(ptr)
#define alloc_meta_next(ptr)        (void **)((ptr) + sizeof(void *))
#define alloc_meta_size(ptr)        (uint32_t *)((ptr) + sizeof(void *) * 2)
#define alloc_meta_tag(ptr)         (AllocationType *)((ptr) + sizeof(void *) * 2 + sizeof(uint32_t))
#define alloc_meta_data(ptr)        (void *)((ptr) + sizeof(void *) * 2 + sizeof(uint32_t) + sizeof(AllocationType))
#define alloc_slab_item_meta_sizeof (size_t)(2)
#define alloc_slab_item_meta(ptr)   (uint16_t *)((ptr) - 2)

#define unreachable() assert(0 && "Unreachable")

#define sized_enum(typ, name)                                                                                          \
	typedef typ name;                                                                                                  \
	enum

// changing this to any other size WILL misalign all allocation
sized_enum(uint32_t, AllocationType) {
	ALLOCATION_SLAB_ITEM = (1 << 0),
	ALLOCATION_USED = (1 << 1),
};

sized_enum(char, SlabSize) {
	SLAB_4B = 0, SLAB_8B = 1, SLAB_16B = 2, SLAB_32B = 3, SLAB_64B = 4, SLAB_128B = 5, SLAB_256B = 6,
};

#define dump_ptr(ptr) (ptr ? (void *)((ptr) - alloc_base + ALLOCATOR_SIZE) : NULL)

void
allocation_dump(void *ptr)
{
	void *prev = *alloc_meta_prev(ptr);
	void *next = *alloc_meta_next(ptr);
	const char *tag_str = (*alloc_meta_tag(ptr) & ALLOCATION_USED) ? "<used>" : "<unused>";
	printf("%p: Allocation{prev: %p, next: %p, size: %d, tag: %s}\n", dump_ptr(ptr), dump_ptr(prev), dump_ptr(next),
	       *alloc_meta_size(ptr), tag_str);
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

void *alloc_reserve(size_t size);

void *
alloc_slab_segment(SlabSize size)
{
	assert((size >= SLAB_4B && size <= SLAB_256B) && "Not a real SlabSize");

	// to make the size of allocation itself a power of two
	void *ptr = alloc_reserve(((4 << size) << 12) - alloc_meta_sizeof);
	if (ptr == NULL)
		return NULL;

	*alloc_meta_tag(ptr) = ALLOCATION_USED;

	if (ptr == alloc_last_free) {
		fprintf(stderr, "[ERROR]: reserved memory still recognized as last freed\n");
		allocation_dump(ptr);
		__builtin_trap();
	}

	// ((4 << size) << 12) - size of allocation in bytes
	// ($ - 512 - alloc_meta_sizeof - alloc_slab_item_sizeof) - how much memory left in bytes for items
	// ($ / (4 << size)) - hom many item slots left
	// ((1 << 12) - $) - how many item slots used by metadata and bitmap
	int occupied_items =
			(1 << 12) - (((4 << size) << 12) - 512 - alloc_meta_sizeof - alloc_slab_item_meta_sizeof) / (4 << size);

	printf("for size %dB, metadata and bitmap occupy %d items\n", 4 << size, occupied_items);

	char *bitmap = memset(alloc_meta_data(ptr), 0xff, 512);
	memset(bitmap, 0, occupied_items / 8);
	bitmap[occupied_items / 8] = 0xff >> (occupied_items % 8);

	for (int i = occupied_items; i < 1 << 12; ++i) {
		void *item = ptr + i * (4 << size);
		uint16_t *item_meta = alloc_slab_item_meta(item);
		*item_meta = (i << 4) + (size << 1) + ALLOCATION_SLAB_ITEM;
		// printf("ptr: %p, meta: %p, %d\n", item, item_meta, (*item_meta) >> 4);
	}
	// for (int i = 0; i < 512; i++) {
	// 	printf("0b%0*hhb\n", (int)8, *(uint8_t *)(bitmap + i));
	// }
	// unreachable();

	return ptr;
}

void *
alloc_slab_get_item(SlabSize size)
{
	void **slab_segment;

	switch (size) {
	case SLAB_4B:
		slab_segment = &alloc_slab_last_4b;
		break;
	case SLAB_8B:
		slab_segment = &alloc_slab_last_8b;
		break;
	case SLAB_16B:
		slab_segment = &alloc_slab_last_16b;
		break;
	case SLAB_32B:
		slab_segment = &alloc_slab_last_32b;
		break;
	case SLAB_64B:
		slab_segment = &alloc_slab_last_64b;
		break;
	case SLAB_128B:
		slab_segment = &alloc_slab_last_128b;
		break;
	case SLAB_256B:
		slab_segment = &alloc_slab_last_256b;
		break;
	default:
		unreachable();
	}

	void *slab = *slab_segment;

	void *bitmap = alloc_meta_data(slab);

	int item_position = 8;
	int i;
	for (i = 0; i < 512; ++i) {
		item_position = __builtin_clz(((uint8_t *)bitmap)[i] << 24);
		// printf("%0*b (%d)\n", 8, (*(((uint8_t *)bitmap) + i)), __builtin_clz(((uint8_t *)bitmap)[i] << 24));
		if (item_position < 8) {
			// printf("item %d from loop %d\n", item_position, i);
			break;
		}
	}
	if (item_position >= 8) {
		void *new_segment = alloc_slab_segment(size);

		*alloc_meta_next(new_segment) = *slab_segment;
		*alloc_meta_prev(*slab_segment) = new_segment;
		*slab_segment = new_segment;

		return alloc_slab_get_item(size);
	}

	// printf("fit: %d, item_offset: %d\n", 4 << size, i * 8 + item_position);
	*(uint8_t *)(bitmap + i) ^= 1 << (7 - item_position);
	void *item = slab + (i * 8 + item_position) * (4 << size);
	uint16_t *item_meta = alloc_slab_item_meta(item);

	// printf("allocated slab item\n");
	printf("\\ ptr: %p, meta: %p, %d\n", item, item_meta, (*item_meta) >> 4);
	// printf("%0*b\n", 16, *alloc_slab_item_meta(item));
	return item;
}

void
alloc_init(void)
{
	alloc_base = malloc(ALLOCATOR_SIZE);    // 32MB
	alloc_cursor = alloc_base;
	alloc_end = alloc_base + ALLOCATOR_SIZE;

	alloc_slab_last_256b = alloc_slab_segment(SLAB_256B);
	alloc_slab_last_128b = alloc_slab_segment(SLAB_128B);
	alloc_slab_last_64b = alloc_slab_segment(SLAB_64B);
	alloc_slab_last_32b = alloc_slab_segment(SLAB_32B);
	alloc_slab_last_16b = alloc_slab_segment(SLAB_16B);
	alloc_slab_last_8b = alloc_slab_segment(SLAB_8B);
	alloc_slab_last_4b = alloc_slab_segment(SLAB_4B);

	// printf("base: %p; end: %p; header_size: %d\n", alloc_base, alloc_end, (int)alloc_meta_sizeof);
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
	// printf("%p <> %p\n", prev, next);
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
			while (!(*alloc_meta_tag(next) & ALLOCATION_USED)) {
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
		*alloc_meta_tag(next) = 0;
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
	if (size <= 0) {
		fprintf(stderr, "[ERROR]: attempt at allocating zero bytes");
		return NULL;
	}

	void *allocation;

	if (size + alloc_slab_item_meta_sizeof <= 256) {
		size += alloc_slab_item_meta_sizeof - 1;
		// TODO: allocate from best fitting slab
		SlabSize fit = sizeof(int) * 8 - __builtin_clz((int)size) - 2;
		// printf("SLAB_4B: %d, SLAB_256B: %d, size: %d, fit: %d, sizeof(int): %d, clz(size): %d\n", SLAB_4B, SLAB_256B,
		//        (int)size, (int)(4 << fit), (int)sizeof(int) * 8, __builtin_clz((int)size));
		assert((fit >= SLAB_4B && fit <= SLAB_256B) && "Not a real SlabSize");
		return alloc_slab_get_item(fit);
		// switch (fit) {
		// case SLAB_4B:
		// 	return alloc_slab_get_item(&alloc_slab_last_4b);
		// case SLAB_8B:
		// 	return alloc_slab_get_item(&alloc_slab_last_8b);
		// case SLAB_16B:
		// 	return alloc_slab_get_item(&alloc_slab_last_16b);
		// case SLAB_32B:
		// 	return alloc_slab_get_item(&alloc_slab_last_32b);
		// case SLAB_64B:
		// 	return alloc_slab_get_item(&alloc_slab_last_64b);
		// case SLAB_128B:
		// 	return alloc_slab_get_item(&alloc_slab_last_128b);
		// case SLAB_256B:
		// 	return alloc_slab_get_item(&alloc_slab_last_256b);
		// default:
		// 	unreachable();
		// }
	}

	allocation = alloc_reserve(size);    // alloc_cursor;
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

	// printf("trying to free %p\n", ptr);
	// uint16_t *meta = alloc_slab_item_meta(ptr);
	// printf("%0*b\n", 16, *meta);
	for (uint16_t meta = *alloc_slab_item_meta(ptr); meta & ALLOCATION_SLAB_ITEM;) {
		SlabSize size = (meta >> 1) & 0b111;
		uint16_t child_id = meta >> 4;
		void *parent_allocation = ptr - (child_id * (4 << size));

		printf("freed slab item\n");
		printf("\\ ptr: %p, meta: %p, %d\n", ptr, alloc_slab_item_meta(ptr), child_id);
		*(char *)(alloc_meta_data(parent_allocation) + child_id / 8) ^= 1 << (7 - child_id % 8);
		return;
	}

	ptr -= alloc_meta_sizeof;
	// you could also just do = 0; but this is more informative (and more error prone because of retained tags in other
	// bits)
	if (*alloc_meta_tag(ptr) & ALLOCATION_USED)
		*alloc_meta_tag(ptr) ^= ALLOCATION_USED;
	else
		fprintf(stderr, "Freeing already freed allocation");

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
	while (!(*alloc_meta_tag(next) & ALLOCATION_USED)) {
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

	void *chunks[4096] = { 0 };

	for (int i = 0; i < 4096; i++) {
		chunks[i] = alloc(84);
	}

	// fre(alloc(10));
	// void *a = alloc(10);
	// fre(alloc(10));
	// fre(a);

	// void *m[] = {
	// 	alloc(10), alloc(100), alloc(110), alloc(120), alloc(210), alloc(10101),
	// };

	// fre(m[1]);
	// fre(m[3]);
	// m[1] = alloc(110);
	// m[3] = alloc(20);

	memory_dump();
	free(alloc_base);
	return 0;
}
