/*
 * Copyright (c) 2016-2021 Intel Corporation. All rights reserved.
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

#include "config.h"
#include "sm2_common.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>


struct dlist_entry sm2_ep_name_list;
DEFINE_LIST(sm2_ep_name_list);
pthread_mutex_t sm2_ep_list_lock = PTHREAD_MUTEX_INITIALIZER;

void sm2_cleanup(void)
{
	struct sm2_ep_name *ep_name;
	struct dlist_entry *tmp;

	pthread_mutex_lock(&sm2_ep_list_lock);
	dlist_foreach_container_safe(&sm2_ep_name_list, struct sm2_ep_name,
				     ep_name, entry, tmp)
		free(ep_name);
	pthread_mutex_unlock(&sm2_ep_list_lock);
}

static void sm2_peer_addr_init(struct sm2_addr *peer)
{
	memset(peer->name, 0, SM2_NAME_MAX);
	peer->id = -1;
}

size_t sm2_calculate_size_offsets(size_t tx_count, size_t rx_count,
				  size_t *cmd_offset, size_t *resp_offset,
				  size_t *inject_offset, size_t *sar_offset,
				  size_t *peer_offset, size_t *name_offset,
				  size_t *sock_offset)
{
	size_t cmd_queue_offset, resp_queue_offset, inject_pool_offset;
	size_t sar_pool_offset, peer_data_offset, ep_name_offset;
	size_t tx_size, rx_size, total_size, sock_name_offset;

	tx_size = roundup_power_of_two(tx_count);
	rx_size = roundup_power_of_two(rx_count);

	/* Align cmd_queue offset to 128-bit boundary. */
	cmd_queue_offset = ofi_get_aligned_size(sizeof(struct sm2_region), 16);
	resp_queue_offset = cmd_queue_offset + sizeof(struct sm2_cmd_queue) +
			    sizeof(struct sm2_cmd) * rx_size;
	inject_pool_offset = resp_queue_offset + sizeof(struct sm2_resp_queue) +
			     sizeof(struct sm2_resp) * tx_size;
	sar_pool_offset = inject_pool_offset +
		freestack_size(sizeof(struct sm2_inject_buf), rx_size);
	peer_data_offset = sar_pool_offset +
		freestack_size(sizeof(struct sm2_sar_buf), SM2_MAX_PEERS);
	ep_name_offset = peer_data_offset + sizeof(struct sm2_peer_data) *
		SM2_MAX_PEERS;

	sock_name_offset = ep_name_offset + SM2_NAME_MAX;

	if (cmd_offset)
		*cmd_offset = cmd_queue_offset;
	if (resp_offset)
		*resp_offset = resp_queue_offset;
	if (inject_offset)
		*inject_offset = inject_pool_offset;
	if (sar_offset)
		*sar_offset = sar_pool_offset;
	if (peer_offset)
		*peer_offset = peer_data_offset;
	if (name_offset)
		*name_offset = ep_name_offset;
	if (sock_offset)
		*sock_offset = sock_name_offset;

	total_size = sock_name_offset + SM2_SOCK_NAME_MAX;

	/*
 	 * Revisit later to see if we really need the size adjustment, or
 	 * at most align to a multiple of a page size.
 	 */
	total_size = roundup_power_of_two(total_size);

	return total_size;
}

static void sm2_lock_init(pthread_spinlock_t *lock)
{
	pthread_spin_init(lock, PTHREAD_PROCESS_SHARED);
}

int sm2_create(const struct fi_provider *prov, struct sm2_map *map,
	       const struct sm2_attr *attr, struct sm2_mmap *sm2_mmap)
{
	struct sm2_ep_name *ep_name;
	size_t total_size, cmd_queue_offset, peer_data_offset;
	size_t resp_queue_offset, inject_pool_offset, name_offset;
	size_t sar_pool_offset, sock_name_offset;
	int ret, i, id;
	void *mapped_addr;
	size_t tx_size, rx_size;
	struct sm2_region *smr;

	tx_size = roundup_power_of_two(attr->tx_count);
	rx_size = roundup_power_of_two(attr->rx_count);
	total_size = sm2_calculate_size_offsets(tx_size, rx_size, &cmd_queue_offset,
					&resp_queue_offset, &inject_pool_offset,
					&sar_pool_offset, &peer_data_offset,
					&name_offset, &sock_name_offset);

	FI_WARN(prov, FI_LOG_EP_CTRL, "Claiming an entry for (%s)\n", attr->name);
	sm2_coordinator_lock(sm2_mmap);
	ret = sm2_coordinator_allocate_entry(attr->name, sm2_mmap, &id);
	sm2_coordinator_unlock(sm2_mmap);

	/* TODO: handle address-in-use error (FI_EBUSY?)*/
	/* TODO: handle no available space on device error */
	/* TODO: handle no available slots left error */
	

	ep_name = calloc(1, sizeof(*ep_name));
	if (!ep_name) {
		FI_WARN(prov, FI_LOG_EP_CTRL, "calloc error\n");
		ret = -FI_ENOMEM;
		goto close;
	}
	strncpy(ep_name->name, (char *)attr->name, SM2_NAME_MAX - 1);
	ep_name->name[SM2_NAME_MAX - 1] = '\0';

	pthread_mutex_lock(&sm2_ep_list_lock);
	dlist_insert_tail(&ep_name->entry, &sm2_ep_name_list);

	if (ret < 0) {
		FI_WARN(prov, FI_LOG_EP_CTRL, "ftruncate error\n");
		ret = -errno;
		goto remove;
	}

	mapped_addr = sm2_mmap_ep_region(sm2_mmap, id);

	if (mapped_addr == MAP_FAILED) {
		FI_WARN(prov, FI_LOG_EP_CTRL, "mmap error\n");
		ret = -errno;
		goto remove;
	}

	/* TODO: SM2_FLAG_HMEM_ENABLED */
	/*
	if (attr->flags & SM2_FLAG_HMEM_ENABLED) {
		ret = ofi_hmem_host_register(mapped_addr, total_size);
		if (ret)
			FI_WARN(prov, FI_LOG_EP_CTRL,
				"unable to register shm with iface\n");
	}
	*/

	pthread_mutex_unlock(&sm2_ep_list_lock);

	smr = mapped_addr;
	sm2_lock_init(&smr->lock);
	ofi_atomic_initialize32(&smr->signal, 0);

	smr->map = map;
	smr->version = SM2_VERSION;

	smr->flags = attr->flags;
#ifdef HAVE_ATOMICS
	smr->flags |= SM2_FLAG_ATOMIC;
#endif
#if ENABLE_DEBUG
	smr->flags |= SM2_FLAG_DEBUG;
#endif

	smr->total_size = total_size;
	smr->cmd_queue_offset = cmd_queue_offset;
	smr->resp_queue_offset = resp_queue_offset;
	smr->inject_pool_offset = inject_pool_offset;
	smr->sar_pool_offset = sar_pool_offset;
	smr->peer_data_offset = peer_data_offset;
	smr->name_offset = name_offset;
	smr->sock_name_offset = sock_name_offset;
	smr->cmd_cnt = rx_size;
	/* Limit of 1 outstanding SAR message per peer */
	smr->sar_cnt = SM2_MAX_PEERS;
	smr->max_sar_buf_per_peer = SM2_BUF_BATCH_MAX;

	sm2_cmd_queue_init(sm2_cmd_queue(smr), rx_size);
	sm2_resp_queue_init(sm2_resp_queue(smr), tx_size);
	smr_freestack_init(sm2_inject_pool(smr), rx_size,
			sizeof(struct sm2_inject_buf));
	smr_freestack_init(sm2_sar_pool(smr), SM2_MAX_PEERS,
			sizeof(struct sm2_sar_buf));
	for (i = 0; i < SM2_MAX_PEERS; i++) {
		sm2_peer_addr_init(&sm2_peer_data(smr)[i].addr);
		sm2_peer_data(smr)[i].sar_status = 0;
		sm2_peer_data(smr)[i].name_sent = 0;
	}

	strncpy((char *) sm2_name(smr), attr->name, total_size - name_offset);

	/* Must be set last to signal full initialization to peers */
	smr->pid = getpid();
	return 0;

remove:
	dlist_remove(&ep_name->entry);
	pthread_mutex_unlock(&sm2_ep_list_lock);
	free(ep_name);
close:
	return ret;
}

void sm2_unmap_from_endpoint(struct sm2_region *region, int64_t id)
{

}

void sm2_map_free(struct sm2_map *map)
{

}
