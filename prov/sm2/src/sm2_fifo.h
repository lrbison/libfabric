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
#include "sm2.h"

/*
 * Multi Writer, Single Reader Queue (Not Thread Safe)
 * This data structure must live in the SMR
 * This implementation of this is a one directional linked list with head/tail pointers
 * Every pointer is a relative offset into the Shared Memory Region
 */

#define SM2_FIFO_FREE -3

/* TODO: Switch to ofi_atom */
#define atomic_swap_ptr(addr, value) \
	atomic_exchange_explicit((_Atomic unsigned long *) addr, value, memory_order_relaxed)

#define atomic_compare_exchange(x, y, z) \
	__atomic_compare_exchange_n((int64_t *) (x), (int64_t *) (y), (int64_t)(z), \
								 false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)

struct sm2_fifo {
	long int head;
	long int tail;
};

/* Initialize FIFO queue to empty state */
static inline void sm2_fifo_init(struct sm2_fifo *fifo)
{
	// ofi_atomic_initialize64( &fifo->head, SM2_FIFO_FREE );
	// ofi_atomic_initialize64( &fifo->tail, SM2_FIFO_FREE );
	fifo->head = SM2_FIFO_FREE;
	fifo->tail = SM2_FIFO_FREE;
}

/* Write, Enqueue */
// TODO Add Memory Barriers Back In
// TODO Verify This is correct
static inline void sm2_fifo_write(struct sm2_ep *ep, int peer_id,
        struct sm2_free_queue_entry *fqe)
{
	struct sm2_mmap *map = ep->mmap_regions;
	struct sm2_region *peer_region = sm2_smr_region(ep, peer_id);
	struct sm2_fifo *peer_fifo = sm2_recv_queue(peer_region);
	struct sm2_free_queue_entry *prev_fqe;
	long int offset = sm2_absptr_to_relptr(fqe, map);
	long int prev;

	fqe->nemesis_hdr.next = SM2_FIFO_FREE;

	prev = atomic_swap_ptr(&peer_fifo->tail, offset);

	assert(prev != offset);

	if (OFI_LIKELY(SM2_FIFO_FREE != prev)) {
		/* not empty */
		if (prev + sizeof(fqe) > map->size) {
			/* Need to re-map */
			sm2_mmap_remap(map, prev + sizeof(fqe));
		}

		prev_fqe = sm2_relptr_to_absptr(prev, map);
		prev_fqe->nemesis_hdr.next = offset;
	} else {
		peer_fifo->head = offset;
	}
}

/* Read, Dequeue */
// TODO Add Memory Barriers Back In
static inline struct sm2_free_queue_entry* sm2_fifo_read(struct sm2_ep *ep)
{
	struct sm2_mmap *map = ep->mmap_regions;
	struct sm2_region *self_region = sm2_smr_region(ep, ep->self_fiaddr);
	struct sm2_fifo *self_fifo = sm2_recv_queue(self_region);
	struct sm2_free_queue_entry* fqe;
	long int prev_head;

	if (SM2_FIFO_FREE == self_fifo->head) {
		return NULL;
	}

	prev_head = self_fifo->head;

	if (prev_head + sizeof(fqe) > map->size) {
		/* Need to re-map, and re-generate pointers */
		sm2_mmap_remap(map, prev_head + sizeof(fqe));
		self_region = sm2_smr_region(ep, ep->self_fiaddr);
		self_fifo = sm2_recv_queue(self_region);
	}

	fqe = (struct sm2_free_queue_entry*)sm2_relptr_to_absptr(prev_head, map);
	self_fifo->head = SM2_FIFO_FREE;

	assert(fqe->nemesis_hdr.next != prev_head);

	if (OFI_UNLIKELY(SM2_FIFO_FREE == fqe->nemesis_hdr.next)) {
		if (!atomic_compare_exchange(&self_fifo->tail, &prev_head, SM2_FIFO_FREE)) {
			while (SM2_FIFO_FREE == fqe->nemesis_hdr.next) {}
			self_fifo->head = fqe->nemesis_hdr.next;
		}
	} else {
		self_fifo->head = fqe->nemesis_hdr.next;
	}

	return fqe;
}

static inline void sm2_fifo_write_back(struct sm2_ep *ep,
		struct sm2_free_queue_entry *fqe)
{
	struct sm2_mmap *map = ep->mmap_regions;

	fqe->protocol_hdr.op_src = sm2_buffer_return;

	sm2_fifo_write(ep, sm2_region_ptr_to_id(map, fqe), fqe);
}

#endif /* _SM2_FIFO_H_ */
