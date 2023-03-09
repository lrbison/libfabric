/*
 * Copyright (c) 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef _SM2_FIFO_H_
#define _SM2_FIFO_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include "sm2_common.h"

#define SM2_FIFO_FREE -3

#define atomic_swap_ptr(addr, value) \
	atomic_exchange_explicit((_Atomic unsigned long *) addr, value, memory_order_relaxed)

#define atomic_compare_exchange(x, y, z) \
	__atomic_compare_exchange_n((int64_t *) (x), (int64_t *) (y), (int64_t)(z), \
								 false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)

// Multi Writer, Single Reader Queue (Not Thread Safe)
// This data structure must live in the SMR
// This implementation of this is a one directional linked list with head/tail pointers
// Every pointer is a relative offset into the Shared Memory Region

// TODO need to have FIFO Queue work with offsets instead of pointers

struct sm2_fifo {
	long int fifo_head;
	long int fifo_tail;
};

// Initialize FIFO queue to empty state
static inline void sm2_fifo_init(struct sm2_fifo *fifo)
{
	// ofi_atomic_initialize64( &fifo->fifo_head, SM2_FIFO_FREE );
	// ofi_atomic_initialize64( &fifo->fifo_tail, SM2_FIFO_FREE );
	fifo->fifo_head = SM2_FIFO_FREE;
	fifo->fifo_tail = SM2_FIFO_FREE;
}

/* Write, Enqueue */
// TODO Remove Owning Region, it is the pt2pt only hack
// TODO Add Memory Barriers Back In
// TODO Verify This is correct
static inline void sm2_fifo_write(struct sm2_fifo *fifo, struct sm2_mmap *map,
        struct sm2_free_queue_entry *fqe)
{
	struct sm2_free_queue_entry *prev_fqe;
	long int offset = sm2_absptr_to_relptr(fqe, map);
	long int prev;

	// Set next pointer to Free
	fqe->nemesis_hdr.next = SM2_FIFO_FREE;

	prev = atomic_swap_ptr(&fifo->fifo_tail, offset);

	assert(prev != offset);

	if (OFI_LIKELY(SM2_FIFO_FREE != prev)) {
		/* not empty */
		prev_fqe = sm2_relptr_to_absptr(prev, map);
		prev_fqe->nemesis_hdr.next = offset;
	} else {
		fifo->fifo_head = offset;
	}
}

/* Read, Dequeue */
// TODO Remove Owning Region, it is the pt2pt only hack
// TODO Add Memory Barriers Back In
// TODO Verify This is correct
static inline struct sm2_free_queue_entry* sm2_fifo_read(struct sm2_fifo *fifo, struct sm2_mmap *map)
{
	struct sm2_free_queue_entry* fqe;
	long int prev_head;

	if (SM2_FIFO_FREE == fifo->fifo_head) {
		return NULL;
	}
	// what if fifo_head changed?
	prev_head = fifo->fifo_head;

	fqe = (struct sm2_free_queue_entry*)sm2_relptr_to_absptr(prev_head, map);
	fifo->fifo_head = SM2_FIFO_FREE;

	assert(fqe->nemesis_hdr.next != prev_head);

	if (OFI_UNLIKELY(SM2_FIFO_FREE == fqe->nemesis_hdr.next)) {
		if (!atomic_compare_exchange(&fifo->fifo_tail, &prev_head, SM2_FIFO_FREE)) {
			while (SM2_FIFO_FREE == fqe->nemesis_hdr.next) {}
			fifo->fifo_head = fqe->nemesis_hdr.next;
		}
	} else {
		fifo->fifo_head = fqe->nemesis_hdr.next;
	}

	return fqe;
}

static inline void sm2_fifo_write_back(struct sm2_free_queue_entry *fqe,
        struct sm2_mmap *map)
{
	int id;
	struct sm2_region *origin_smr;
	struct sm2_fifo *origin_fifo;

	id = sm2_region_ptr_to_id(map, fqe);
	origin_smr = sm2_mmap_ep_region(map, id);
	origin_fifo = sm2_recv_queue(origin_smr);

	fqe->protocol_hdr.op_src = sm2_buffer_return;

	sm2_fifo_write(origin_fifo, map, fqe);
}

#endif /* _SM2_FIFO_H_ */
