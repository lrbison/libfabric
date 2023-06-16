/*
 * Copyright (c) Intel Corporation. All rights reserved
 * Copyright (c) Amazon.com, Inc. or its affiliates. All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "ofi_atom.h"
#include "ofi_hmem.h"
#include "ofi_iov.h"
#include "ofi_mr.h"
#include "sm2.h"
#include "sm2_fifo.h"

static int sm2_progress_proto_inject(struct sm2_xfer_entry *xfer_entry,
				     struct fi_peer_rx_entry *rx_entry,
				     struct sm2_ep *ep, bool matched)
{
	ssize_t hmem_copy_ret;
	struct ofi_mr **mr;
	struct iovec *iov;
	size_t iov_count;
	uint64_t comp_flags;
	void *comp_buf;
	int ret, err;

	if (!matched)
		return FI_SUCCESS;

	assert(rx_entry);
	assert(xfer_entry->hdr.size == rx_entry->size);

	iov = rx_entry->iov;
	iov_count = rx_entry->count;
	mr = (struct ofi_mr **) rx_entry->desc;

	hmem_copy_ret =
		ofi_copy_to_mr_iov(mr, iov, iov_count, 0, xfer_entry->user_data,
				   xfer_entry->hdr.size);

	if (hmem_copy_ret < 0) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Inject recv failed with code %d\n",
			(int) (-hmem_copy_ret));
		err = hmem_copy_ret;
	} else if (hmem_copy_ret != xfer_entry->hdr.size) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL, "Inject recv truncated\n");
		err = -FI_ETRUNC;
	}

	comp_buf = rx_entry->iov[0].iov_base;
	comp_flags = sm2_rx_cq_flags(xfer_entry->hdr.op, rx_entry->flags,
				     xfer_entry->hdr.op_flags);

	if (err) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL, "Error processing op\n");
		ret = sm2_write_err_comp(ep->util_ep.rx_cq, rx_entry->context,
					 comp_flags, rx_entry->tag, err);
	} else {
		ret = sm2_complete_rx(ep, rx_entry->context, xfer_entry->hdr.op,
				      comp_flags, xfer_entry->hdr.size,
				      comp_buf, xfer_entry->hdr.sender_gid,
				      xfer_entry->hdr.tag,
				      xfer_entry->hdr.cq_data);
	}
	if (ret) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Unable to process rx completion\n");
	}

	sm2_fifo_write_back(ep, xfer_entry);
	sm2_get_peer_srx(ep)->owner_ops->free_entry(rx_entry);

	return FI_SUCCESS;
}

int sm2_progress_proto_inject_return(struct sm2_ep *ep,
				     struct sm2_xfer_entry *xfer_entry)
{
	int ret;
	struct sm2_av *av =
		container_of(ep->util_ep.av, struct sm2_av, util_av);
	struct sm2_mmap *map = &av->mmap;

	if (xfer_entry->hdr.op_flags & FI_DELIVERY_COMPLETE) {
		ret = sm2_complete_tx(ep, (void *) xfer_entry->hdr.context,
				      xfer_entry->hdr.op,
				      xfer_entry->hdr.op_flags);
		if (ret)
			FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
				"Unable to process "
				"FI_DELIVERY_COMPLETE "
				"completion\n");
	}

	smr_freestack_push(sm2_freestack(sm2_mmap_ep_region(map, ep->gid)),
			   xfer_entry);
	return ret;
}

static int sm2_start_common(struct sm2_ep *ep,
			    struct sm2_xfer_entry *xfer_entry,
			    struct fi_peer_rx_entry *rx_entry, bool matched)
{
	int ret;

	switch (xfer_entry->hdr.proto) {
	case sm2_proto_inject_return:
		ret = sm2_progress_proto_inject_return(ep, xfer_entry);
		break;
	case sm2_proto_inject:
		ret = sm2_progress_proto_inject(xfer_entry, rx_entry, ep,
						matched);
		break;
	default:
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Unexpected protocol for SM2\n");
		ret = -FI_EINVAL;
		break;
	}

	return ret;
}

int sm2_unexp_start(struct fi_peer_rx_entry *rx_entry)
{
	struct sm2_xfer_entry *xfer_entry = rx_entry->peer_context;
	switch (xfer_entry->hdr.proto) {
	case sm2_proto_inject_return:
	}
	// return sm2_start_common(xfer_entry->hdr.ep, xfer_entry, rx_entry, true);
}

static int sm2_get_rx_entry(struct sm2_ep *ep,
				struct sm2_xfer_entry *xfer_entry,
				struct fi_peer_rx_entry **rx_entry,
				bool *existing_match)
{
	struct fid_peer_srx *peer_srx = sm2_get_peer_srx(ep);
	struct sm2_av *sm2_av;
	fi_addr_t addr;
	int ret;

	sm2_av = container_of(ep->util_ep.av, struct sm2_av, util_av);
	addr = sm2_av->reverse_lookup[xfer_entry->hdr.sender_gid];

	if (xfer_entry->hdr.op == ofi_op_tagged) {
		ret = peer_srx->owner_ops->get_tag(
			peer_srx, addr, xfer_entry->hdr.size,
			xfer_entry->hdr.tag, rx_entry);
		if (ret == -FI_ENOENT) {
			*existing_match = false;
			xfer_entry->hdr.ep = ep;
			(*rx_entry)->peer_context = xfer_entry;
			ret = peer_srx->owner_ops->queue_tag(*rx_entry);
			goto out;
		}
		*existing_match = true;
	} else if (xfer_entry->hdr.op == ofi_op_msg ) {
		ret = peer_srx->owner_ops->get_msg(
			peer_srx, addr, xfer_entry->hdr.size, rx_entry);
		if (ret == -FI_ENOENT) {
			*existing_match = false;
			xfer_entry->hdr.ep = ep;
			(*rx_entry)->peer_context = xfer_entry;
			ret = peer_srx->owner_ops->queue_msg(*rx_entry);
			goto out;
		}
		*existing_match = true;
	} else {
		*rx_entry = NULL;
		*existing_match = false;
	}

out:
	if (ret) {
		*rx_entry = NULL;
		*existing_match = false;
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL, "Error getting rx_entry\n");
		return ret;
	}
	return ret < 0 ? ret : 0;
}

void sm2_progress_recv(struct sm2_ep *ep)
{
	struct sm2_xfer_entry *xfer_entry;
	int ret = 0, i;
	bool found;
	struct fi_peer_rx_entry *rx_entry;

	for (i = 0; i < MAX_SM2_MSGS_PROGRESSED; i++) {
		xfer_entry = sm2_fifo_read(ep);
		if (!xfer_entry)
			break;
		ret = sm2_get_rx_entry(ep, xfer_entry, &rx_entry, &found);
		if (ret == 0)
			ret = sm2_start_common(ep, xfer_entry, rx_entry, found);

		if (ret) {
			if (ret != -FI_EAGAIN) {
				FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
					"Error processing command\n");
			}
			break;
		}
	}
}

void sm2_ep_progress(struct util_ep *util_ep)
{
	struct sm2_ep *ep;

	ep = container_of(util_ep, struct sm2_ep, util_ep);
	ofi_genlock_lock(&ep->util_ep.lock);
	sm2_progress_recv(ep);
	ofi_genlock_unlock(&ep->util_ep.lock);
}
