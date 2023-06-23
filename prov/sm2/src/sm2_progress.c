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
#include "sm2_rma.h"

static int sm2_issue_recv_completion(struct sm2_ep *ep,
				     struct sm2_xfer_entry *xfer_entry,
				     struct fi_peer_rx_entry *rx_entry, int err)
{
	void *comp_buf;
	uint64_t comp_flags;
	ssize_t total_len = rx_entry->size;
	int ret;

	comp_buf = rx_entry->iov[0].iov_base;
	comp_flags = sm2_rx_cq_flags(xfer_entry->hdr.op, rx_entry->flags,
				     xfer_entry->hdr.op_flags);

	if (err) {
		ret = sm2_write_err_comp(ep->util_ep.rx_cq, rx_entry->context,
					 comp_flags, rx_entry->tag,
					 xfer_entry->hdr.cq_data, err);
	} else {
		ret = sm2_complete_rx(
			ep, rx_entry->context, xfer_entry->hdr.op, comp_flags,
			total_len, comp_buf, xfer_entry->hdr.sender_gid,
			xfer_entry->hdr.tag, xfer_entry->hdr.cq_data);
	}

	if (ret) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Unable to process rx completion\n");
	}
	return ret;
}

static int sm2_do_inject_recv(struct sm2_ep *ep,
			      struct sm2_xfer_entry *xfer_entry,
			      struct fi_peer_rx_entry *rx_entry,
			      bool unexp_start)
{
	struct ofi_mr **mr = (struct ofi_mr **) rx_entry->desc;
	struct iovec *iov = rx_entry->iov;
	size_t iov_count = rx_entry->count;
	int ret;

	ret = (int) ofi_copy_to_mr_iov(mr, iov, iov_count, 0,
				       xfer_entry->user_data,
				       xfer_entry->hdr.size);

	if (ret < 0) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Inject recv failed with code %d\n", (-ret));
	} else if (ret != xfer_entry->hdr.size) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL, "Inject recv truncated\n");
		ret = -FI_ETRUNC;
	} else {
		ret = 0;
	}

	ret = sm2_issue_recv_completion(ep, xfer_entry, rx_entry, ret);

	if (!unexp_start) {
		/* Return Free Queue Entries here */
		sm2_fifo_write_back(ep, xfer_entry);
	}
	sm2_get_peer_srx(ep)->owner_ops->free_entry(rx_entry);

	return ret;
}

static int sm2_do_sar_recv(struct sm2_ep *ep, struct sm2_xfer_entry *xfer_entry,
			   struct fi_peer_rx_entry *rx_entry, bool unexp_start)
{
	struct ofi_mr **mr = (struct ofi_mr **) rx_entry->desc;
	struct iovec *iov = rx_entry->iov;
	size_t iov_count = rx_entry->count;
	struct sm2_cmd_sar_msg *cmd_msg = (void *) xfer_entry->user_data;
	struct sm2_cmd_sar_msg *cmd_msg_trigger;
	struct sm2_xfer_entry *xfer_entry_trigger;

	int ret;

	ret = (int) ofi_copy_to_mr_iov(mr, iov, iov_count, 0,
				       cmd_msg->user_data, cmd_msg->data_size);
	/* LAR-TODO: better way to do this?  we lose our buffer addr for CQE at
	 * the end */
	ofi_consume_iov_desc(iov, rx_entry->desc, &rx_entry->count,
			     cmd_msg->data_size);

	if (ret < 0) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Inject recv failed with code %d\n", (-ret));
	} else if (ret != xfer_entry->hdr.size) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL, "Inject recv truncated\n");
		ret = -FI_ETRUNC;
	} else {
		ret = 0;
	}

	if (ret) {
		ret = sm2_issue_recv_completion(ep, xfer_entry, rx_entry, ret);

		/* LAR-TODO: Need to store some error status locally so we
		 * can avoid multiple completions on error... uh... use
		 * iov_count? */
		rx_entry->count = -1;
	}

	bool last_msg =
		(cmd_msg->sar_hdr.proto_flags & FI_SM2_SAR_LAST_MESSAGE_FLAG);
	if (rx_entry->count == 0 && last_msg) {
		ret = sm2_issue_recv_completion(ep, xfer_entry, rx_entry, ret);
	}

	if (unexp_start && !last_msg) {
		/* trigger sender with CTS. */
		/* LAR-TODO: Need error handling here */
		sm2_pop_xfer_entry(ep, &xfer_entry_trigger);
		memcpy(xfer_entry_trigger, xfer_entry,
		       sizeof(xfer_entry->hdr) + sizeof(cmd_msg->sar_hdr));
		cmd_msg_trigger = (void *) xfer_entry_trigger->user_data;
		cmd_msg_trigger->sar_hdr.proto_flags |= FI_SM2_SAR_CTS;
		cmd_msg_trigger->sar_hdr.proto_flags |= FI_SM2_SAR_RESUME;
		cmd_msg_trigger->sar_hdr.proto_flags &= ~FI_SM2_SAR_RETURN;
		xfer_entry_trigger->hdr.sender_gid = ep->gid;
		sm2_fifo_write(ep, xfer_entry->hdr.sender_gid,
			       xfer_entry_trigger);
	} else {
		/* Return Free Queue Entries here */
		cmd_msg->sar_hdr.proto_flags |= FI_SM2_SAR_CTS;
		sm2_sar_write_back(ep, xfer_entry);
	}

	if (last_msg)
		sm2_get_peer_srx(ep)->owner_ops->free_entry(rx_entry);

	return ret;
}

/* LAR-TODO: rename to sm2_start_common_recv (ie, not ATOMIC/RMA)*/
/* LAR-TODO: fix unexp_start name! */
static int sm2_start_common(struct sm2_ep *ep,
			    struct sm2_xfer_entry *xfer_entry,
			    struct fi_peer_rx_entry *rx_entry, bool unexp_start)
{
	int ret = 0;

	switch (xfer_entry->hdr.proto) {
	case sm2_proto_inject:
		ret = sm2_do_inject_recv(ep, xfer_entry, rx_entry, unexp_start);
		break;
	case sm2_proto_sar:
		ret = sm2_do_sar_recv(ep, xfer_entry, rx_entry, unexp_start);
		break;
	default:
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Unidentified operation type\n");
		ret = -FI_EINVAL;
	}
	return ret;
}

int sm2_unexp_start(struct fi_peer_rx_entry *rx_entry)
{
	struct sm2_xfer_ctx *xfer_ctx = rx_entry->peer_context;
	int ret;

	ret = sm2_start_common(xfer_ctx->ep, &xfer_ctx->xfer_entry, rx_entry,
			       false);
	ofi_buf_free(xfer_ctx);

	return ret;
}

static int sm2_alloc_xfer_entry_ctx(struct sm2_ep *ep,
				    struct fi_peer_rx_entry *rx_entry,
				    struct sm2_xfer_entry *xfer_entry)
{
	struct sm2_xfer_ctx *xfer_ctx;

	xfer_ctx = ofi_buf_alloc(ep->xfer_ctx_pool);
	if (!xfer_ctx) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Error allocating xfer_entry ctx\n");
		return -FI_ENOMEM;
	}

	memcpy(&xfer_ctx->xfer_entry, xfer_entry, sizeof(*xfer_entry));
	xfer_ctx->ep = ep;

	rx_entry->peer_context = xfer_ctx;

	return FI_SUCCESS;
}

static int sm2_progress_recv_msg(struct sm2_ep *ep,
				 struct sm2_xfer_entry *xfer_entry)
{
	struct fid_peer_srx *peer_srx = sm2_get_peer_srx(ep);
	struct fi_peer_rx_entry *rx_entry;
	struct sm2_av *sm2_av;
	fi_addr_t addr;
	int ret;
	int (*queue_func)(struct fi_peer_rx_entry *);

	sm2_av = container_of(ep->util_ep.av, struct sm2_av, util_av);
	addr = sm2_av->reverse_lookup[xfer_entry->hdr.sender_gid];

	if (xfer_entry->hdr.op == ofi_op_tagged) {
		ret = peer_srx->owner_ops->get_tag(
			peer_srx, addr, xfer_entry->hdr.size,
			xfer_entry->hdr.tag, &rx_entry);
		queue_func = peer_srx->owner_ops->queue_tag;
	} else {
		ret = peer_srx->owner_ops->get_msg(
			peer_srx, addr, xfer_entry->hdr.size, &rx_entry);
		queue_func = peer_srx->owner_ops->queue_msg;
	}
	if (ret == -FI_ENOENT) {
		ret = sm2_alloc_xfer_entry_ctx(ep, rx_entry, xfer_entry);
		sm2_fifo_write_back(ep, xfer_entry);
		if (ret)
			return ret;

		ret = (*queue_func)(rx_entry);
		goto out;
	}
	if (ret) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL, "Error getting rx_entry\n");
		return ret;
	}
	ret = sm2_start_common(ep, xfer_entry, rx_entry, true);

out:
	return ret < 0 ? ret : 0;
}

static void sm2_do_atomic(void *src, void *dst, void *cmp,
			  enum fi_datatype datatype, enum fi_op op, size_t cnt,
			  uint32_t op_flags)
{
	char tmp_result[SM2_ATOMIC_INJECT_SIZE];

	if (ofi_atomic_isswap_op(op)) {
		ofi_atomic_swap_handler(op, datatype, dst, src, cmp, tmp_result,
					cnt);
	} else if (op_flags & FI_REMOTE_READ && ofi_atomic_isreadwrite_op(op)) {
		ofi_atomic_readwrite_handler(op, datatype, dst, src, tmp_result,
					     cnt);
	} else if (ofi_atomic_iswrite_op(op)) {
		ofi_atomic_write_handler(op, datatype, dst, src, cnt);
	} else {
		FI_WARN(&sm2_prov, FI_LOG_EP_DATA,
			"invalid atomic operation\n");
	}

	if (op_flags & FI_REMOTE_READ)
		memcpy(src, op == FI_ATOMIC_READ ? dst : tmp_result,
		       cnt * ofi_datatype_size(datatype));
}

static int sm2_progress_inject_atomic(struct sm2_xfer_entry *xfer_entry,
				      struct fi_ioc *ioc, size_t ioc_count,
				      size_t *len, struct sm2_ep *ep)
{
	struct sm2_atomic_entry *atomic_entry =
		(struct sm2_atomic_entry *) xfer_entry->user_data;
	uint8_t *src, *comp;
	int i;

	switch (xfer_entry->hdr.op) {
	case ofi_op_atomic_compare:
		src = atomic_entry->atomic_data.buf;
		comp = atomic_entry->atomic_data.comp;
		break;
	default:
		src = atomic_entry->atomic_data.data;
		comp = NULL;
		break;
	}

	for (i = *len = 0; i < ioc_count && *len < xfer_entry->hdr.size; i++) {
		sm2_do_atomic(&src[*len], ioc[i].addr,
			      comp ? &comp[*len] : NULL,
			      atomic_entry->atomic_hdr.datatype,
			      atomic_entry->atomic_hdr.atomic_op, ioc[i].count,
			      xfer_entry->hdr.op_flags);
		*len += ioc[i].count *
			ofi_datatype_size(atomic_entry->atomic_hdr.datatype);
	}

	if (*len != xfer_entry->hdr.size) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL, "recv truncated");
		return -FI_ETRUNC;
	}
	return FI_SUCCESS;
}

static int sm2_progress_rma_read_req(struct sm2_ep *ep,
				     struct sm2_xfer_entry *xfer_entry)
{
	int ret;
	struct sm2_cmd_sar_rma_msg *cmd_rma;
	size_t rma_count = SM2_IOV_LIMIT;
	struct fi_rma_iov *iov;
	size_t payload_used, bytes_to_send;
	struct sm2_domain *domain;
	struct ofi_mr *mr;
	uintptr_t hmem_addr;

	domain = container_of(ep->util_ep.domain, struct sm2_domain,
			      util_domain);

	cmd_rma = (struct sm2_cmd_sar_rma_msg *) xfer_entry->user_data;

	if (cmd_rma->sar_hdr.request_offset) {
		ofi_consume_rma_iov(cmd_rma->rma_iov, &rma_count,
				    cmd_rma->sar_hdr.request_offset);
	}

	iov = cmd_rma->rma_iov;
	payload_used = 0;
	while (rma_count) {
		bytes_to_send =
			MIN(iov->len, SM2_RMA_INJECT_SIZE - payload_used);
		if (bytes_to_send == 0)
			break;
		hmem_addr = (uintptr_t) iov->addr;
		ret = ofi_mr_map_verify(&domain->util_domain.mr_map, &hmem_addr,
					bytes_to_send, iov->key, FI_REMOTE_READ,
					(void **) &mr);
		if (ret) {
			cmd_rma->sar_hdr.proto_flags |= FI_SM2_SAR_ERROR_FLAG;
			break;
		}

		ret = ofi_copy_from_hmem(mr->iface, mr->device,
					 cmd_rma->user_data + payload_used,
					 (void *) hmem_addr, bytes_to_send);
		payload_used += bytes_to_send;
		ofi_consume_rma_iov(cmd_rma->rma_iov, &rma_count,
				    bytes_to_send);

		assert(payload_used <= SM2_RMA_INJECT_SIZE);
		if (ret) {
			cmd_rma->sar_hdr.proto_flags |= FI_SM2_SAR_ERROR_FLAG;
			break;
		}
	}
	xfer_entry->hdr.op = ofi_op_read_rsp;
	sm2_fifo_write(ep, xfer_entry->hdr.sender_gid, xfer_entry);
	return FI_SUCCESS;
}

static int sm2_progress_rma_read_rsp(struct sm2_ep *ep,
				     struct sm2_xfer_entry *xfer_entry)
{
	int ret = 0;
	struct sm2_cmd_sar_rma_msg *cmd_rma = (void *) xfer_entry->user_data;
	struct sm2_sar_ctx *ctx = (void *) cmd_rma->sar_hdr.context;
	struct iovec iov[SM2_IOV_LIMIT];
	void *desc[SM2_IOV_LIMIT];
	enum fi_hmem_iface iface;
	uint64_t device;
	size_t bytes_to_copy, iov_count, bytes_used = 0;

	assert(ctx);
	ctx->msgs_in_flight--;

	cmd_rma = (struct sm2_cmd_sar_rma_msg *) xfer_entry->user_data;
	memcpy(iov, ctx->msg.msg_iov, sizeof(iov));
	memcpy(desc, ctx->msg.desc, sizeof(desc));
	iov_count = ctx->msg.iov_count;
	if (cmd_rma->sar_hdr.request_offset) {
		ofi_consume_iov_desc(iov, desc, &iov_count,
				     cmd_rma->sar_hdr.request_offset);
	}

	ctx->status_flags |=
		cmd_rma->sar_hdr.proto_flags & FI_SM2_SAR_ERROR_FLAG;
	if (ctx->status_flags & FI_SM2_SAR_ERROR_FLAG) {
		sm2_rma_handle_remote_error(ep, xfer_entry, ctx);
		return FI_SUCCESS;
	}

	while (iov_count) {
		bytes_to_copy =
			MIN(iov[0].iov_len, SM2_RMA_INJECT_SIZE - bytes_used);
		if (bytes_to_copy == 0)
			break;
		sm2_get_iface_device(desc[0], &iface, &device);
		ret = ofi_copy_to_hmem(iface, device, iov[0].iov_base,
				       cmd_rma->user_data + bytes_used,
				       bytes_to_copy);
		bytes_used += bytes_to_copy;
		assert(bytes_used <= SM2_RMA_INJECT_SIZE);
		ofi_consume_iov_desc(iov, desc, &iov_count, bytes_to_copy);
		if (ret)
			break;
	}
	ctx->bytes_acked += bytes_used;

	/* report completion if this is the last packet. */
	if (ctx->bytes_acked == ctx->bytes_total) {
		uint64_t comp_flags = ofi_tx_cq_flags(xfer_entry->hdr.op);
		ret = sm2_complete_tx(ep, (void *) xfer_entry->hdr.context,
				      xfer_entry->hdr.op,
				      comp_flags | FI_COMPLETION);
		sm2_free_rma_ctx(ctx);
		sm2_freestack_push(ep, xfer_entry);
		return FI_SUCCESS;
	}

	if (ctx->bytes_requested == ctx->bytes_total) {
		sm2_freestack_push(ep, xfer_entry);
		return FI_SUCCESS;
	}

	ret = sm2_rma_cmd_fill_sar_xfer(xfer_entry, ctx);
	if (!ret)
		sm2_fifo_write(ep, ctx->peer_gid, xfer_entry);
	else
		sm2_rma_handle_local_error(ep, xfer_entry, ctx, ret);

	return FI_SUCCESS;
}

static int sm2_progress_atomic(struct sm2_ep *ep,
			       struct sm2_xfer_entry *xfer_entry)
{
	struct sm2_atomic_entry *atomic_entry =
		(struct sm2_atomic_entry *) xfer_entry->user_data;
	struct sm2_domain *domain = container_of(
		ep->util_ep.domain, struct sm2_domain, util_domain);
	struct fi_ioc ioc[SM2_IOV_LIMIT];
	size_t i;
	size_t ioc_count = atomic_entry->atomic_hdr.rma_ioc_count;
	size_t total_len = 0;
	int err = 0, ret = 0;
	struct fi_rma_ioc *ioc_ptr;

	for (i = 0; i < ioc_count; i++) {
		ioc_ptr = &(atomic_entry->atomic_hdr.rma_ioc[i]);
		ret = ofi_mr_verify(
			&domain->util_domain.mr_map,
			ioc_ptr->count *
				ofi_datatype_size(
					atomic_entry->atomic_hdr.datatype),
			(uintptr_t *) &(ioc_ptr->addr), ioc_ptr->key,
			ofi_rx_mr_reg_flags(
				xfer_entry->hdr.op,
				atomic_entry->atomic_hdr.atomic_op));
		if (ret)
			break;

		ioc[i].addr = (void *) ioc_ptr->addr;
		ioc[i].count = ioc_ptr->count;
	}

	if (ret)
		goto out;

	err = sm2_progress_inject_atomic(xfer_entry, ioc, ioc_count, &total_len,
					 ep);

	if (err) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"error processing atomic op\n");
		ret = sm2_write_err_comp(
			ep->util_ep.rx_cq, NULL,
			sm2_rx_cq_flags(xfer_entry->hdr.op, 0,
					xfer_entry->hdr.op_flags),
			0, xfer_entry->hdr.cq_data, err);
	} else {
		ret = sm2_complete_rx(ep, NULL, xfer_entry->hdr.op,
				      sm2_rx_cq_flags(xfer_entry->hdr.op, 0,
						      xfer_entry->hdr.op_flags),
				      total_len, ioc_count ? ioc[0].addr : NULL,
				      xfer_entry->hdr.sender_gid, 0,
				      xfer_entry->hdr.cq_data);
	}

	if (ret) {
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"unable to process rx completion\n");
		err = ret;
	}
out:
	sm2_fifo_write_back(ep, xfer_entry);
	return err;
}

/* this function is called after the receiver has matched the message and is
   ready for the firehose */
static int sm2_progress_sar_msg_resume(struct sm2_ep *ep,
				       struct sm2_xfer_entry *xfer_entry)
{
	struct sm2_cmd_sar_hdr *sar_hdr = (void *) xfer_entry->user_data;
	struct sm2_sar_ctx *ctx = (void *) sar_hdr->context;
	int ret;

	if (xfer_entry->hdr.sender_gid == ep->gid) {
		/* we triggered the resume.  just return this xfer_entry.
		   Data will come shortly */
		sm2_freestack_push(ep, xfer_entry);
		return FI_SUCCESS;
	}
	/* Otherwise, we are sender and receiver requested resume data. */

	/* return their entry first */
	sm2_sar_write_back(ep, xfer_entry);

	/* start sending more data */
	while (ctx->bytes_sent != ctx->bytes_total &&
	       ctx->msgs_in_flight < SM2_SAR_IN_FLIGHT_TARGET_MSG) {
		ret = sm2_pop_xfer_entry(ep, &xfer_entry);
		if (ret) {
			/* LAR-TODO: now what !?
			   maybe ping-pong this packet until we have entries
			   available?
			 */
		}
		ret = sm2_rma_cmd_fill_sar_xfer(xfer_entry, ctx);
		if (!ret)
			sm2_fifo_write(ep, ctx->peer_gid, xfer_entry);
		else {
			sm2_rma_handle_local_error(ep, xfer_entry, ctx, ret);
			break;
		}
	}

	if (!(ctx->op_flags & FI_DELIVERY_COMPLETE) &&
	    ctx->bytes_sent == ctx->bytes_total) {
		ret = sm2_complete_tx(ep, ctx->msg.context, ctx->op,
				      ctx->op_flags);
		if (!ret)
			ctx->status_flags |= FI_SM2_SAR_STATUS_COMPLETED;
		else
			FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
				"unable to process tx completion\n");
		ret = FI_SUCCESS;
	}
	return ret;
}

/* Fills data into an xfer_entry for either message send or write by originator.
 */
/* LAR-TODO: rename to sm2_progress_sar_send_xfer */
static int sm2_progress_rma_write_origin(struct sm2_ep *ep,
					 struct sm2_xfer_entry *xfer_entry)
{
	struct sm2_cmd_sar_hdr *sar_hdr = (void *) xfer_entry->user_data;
	struct sm2_sar_ctx *ctx = (void *) sar_hdr->context;
	bool tx_complete, rx_complete;
	int ret;

	ctx->msgs_in_flight--;

	ctx->status_flags |= sar_hdr->proto_flags & FI_SM2_SAR_ERROR_FLAG;
	if (ctx->status_flags & FI_SM2_SAR_ERROR_FLAG) {
		sm2_rma_handle_remote_error(ep, xfer_entry, ctx);
		return FI_SUCCESS;
	}

	tx_complete = ctx->bytes_sent == ctx->bytes_total;
	rx_complete = FI_SM2_SAR_LAST_MESSAGE_FLAG & sar_hdr->proto_flags;
	if (rx_complete) {
		if (0 == (ctx->status_flags & FI_SM2_SAR_STATUS_COMPLETED)) {
			ret = sm2_complete_tx(
				ep, (void *) xfer_entry->hdr.context,
				xfer_entry->hdr.op, xfer_entry->hdr.op_flags);
			if (ret)
				FI_WARN(&sm2_prov, FI_EP_RDM,
					"Error generating completion for RMA "
					"write.");
			else
				ctx->status_flags |=
					FI_SM2_SAR_STATUS_COMPLETED;
		}
		sm2_free_rma_ctx(ctx);
		sm2_freestack_push(ep, xfer_entry);
	} else if (tx_complete) {
		sm2_freestack_push(ep, xfer_entry);
	} else {
		ret = sm2_rma_cmd_fill_sar_xfer(xfer_entry, ctx);
		if (ret)
			sm2_rma_handle_local_error(ep, xfer_entry, ctx, ret);
		else
			sm2_fifo_write(ep, ctx->peer_gid, xfer_entry);
	}

	return FI_SUCCESS;
}

static int sm2_progress_rma_write_remote(struct sm2_ep *ep,
					 struct sm2_xfer_entry *xfer_entry)
{
	int ret = 0, jv;
	struct sm2_cmd_sar_rma_msg *cmd_rma;
	struct fi_rma_iov *iov;

	uint8_t *src;
	uint64_t comp_flags;
	void *buf_for_completion = NULL;
	ssize_t total_bytes_for_completion = 0;
	uintptr_t hmem_addr;
	struct sm2_domain *domain;
	struct ofi_mr *mr;

	domain = container_of(ep->util_ep.domain, struct sm2_domain,
			      util_domain);

	cmd_rma = (struct sm2_cmd_sar_rma_msg *) xfer_entry->user_data;

	/* copy data from packet to destination */
	src = (uint8_t *) &cmd_rma->user_data;

	for (jv = 0; jv < SM2_IOV_LIMIT; jv++) {
		iov = &cmd_rma->rma_iov[jv];
		if (iov->len == 0)
			continue;
		hmem_addr = (uintptr_t) iov->addr;
		ret = ofi_mr_map_verify(&domain->util_domain.mr_map, &hmem_addr,
					iov->len, iov->key, FI_REMOTE_WRITE,
					(void **) &mr);
		if (ret) {
			cmd_rma->sar_hdr.proto_flags |= FI_SM2_SAR_ERROR_FLAG;
			goto out;
		}
		ret = ofi_copy_to_hmem(mr->iface, mr->device,
				       (void *) hmem_addr, src, iov->len);
		if (ret) {
			cmd_rma->sar_hdr.proto_flags |= FI_SM2_SAR_ERROR_FLAG;
			goto out;
		}
		src += iov->len;
		assert((long) (src - (uint8_t *) &cmd_rma->user_data) <=
		       SM2_RMA_INJECT_SIZE);
	}

	/* report completion if this is the last packet. */
	if (FI_SM2_SAR_LAST_MESSAGE_FLAG & cmd_rma->sar_hdr.proto_flags) {
		comp_flags = ofi_rx_cq_flags(xfer_entry->hdr.op);
		comp_flags |= FI_REMOTE_CQ_DATA & xfer_entry->hdr.op_flags;
		/* TODO: when sm2 supports FI_RMA_EVENT: */
		/* comp_flags |= FI_COMPLETION & xfer_entry->hdr.op_flags; */
		ret = sm2_complete_rx(
			ep, (void *) xfer_entry->hdr.context,
			xfer_entry->hdr.op, comp_flags,
			total_bytes_for_completion, buf_for_completion,
			xfer_entry->hdr.sender_gid, 0, xfer_entry->hdr.cq_data);
		if (ret) {
			cmd_rma->sar_hdr.proto_flags |= FI_SM2_SAR_ERROR_FLAG;
			FI_WARN(&sm2_prov, FI_LOG_EP_DATA,
				"Problem generating completion event for RMA "
				"write!");
		}
	}

out:
	if (cmd_rma->sar_hdr.proto_flags & FI_SM2_SAR_ERROR_FLAG) {
		ret = sm2_write_err_comp(ep->util_ep.rx_cq,
					 (void *) xfer_entry->hdr.context,
					 xfer_entry->hdr.op_flags, 0,
					 xfer_entry->hdr.cq_data, ret);
	}

	/* return the xfer to the peer */
	cmd_rma->sar_hdr.proto_flags |= FI_SM2_SAR_CTS;
	sm2_sar_write_back(ep, xfer_entry);

	return ret;
}
static int sm2_progress_rma_write(struct sm2_ep *ep,
				  struct sm2_xfer_entry *xfer_entry)
{
	struct sm2_cmd_sar_rma_msg *cmd_rma =
		(struct sm2_cmd_sar_rma_msg *) xfer_entry->user_data;
	if (cmd_rma->sar_hdr.proto_flags & FI_SM2_SAR_RETURN)
		return sm2_progress_rma_write_origin(ep, xfer_entry);
	else
		return sm2_progress_rma_write_remote(ep, xfer_entry);
}

static int sm2_progress_sar_proto(struct sm2_ep *ep,
				  struct sm2_xfer_entry *xfer_entry)
{
	int ret;
	struct sm2_cmd_sar_hdr *sar_hdr = (void *) xfer_entry->user_data;
	switch (xfer_entry->hdr.op) {
	case ofi_op_msg:
	case ofi_op_tagged:
		if (sar_hdr->proto_flags & FI_SM2_SAR_RESUME) {
			ret = sm2_progress_sar_msg_resume(ep, xfer_entry);
		} else if (xfer_entry->hdr.sender_gid == ep->gid)
			ret = sm2_progress_rma_write_origin(ep, xfer_entry);
		else
			ret = sm2_progress_recv_msg(ep, xfer_entry);
		break;
	case ofi_op_write:
		ret = sm2_progress_rma_write(ep, xfer_entry);
		break;
	case ofi_op_read_rsp:
		ret = sm2_progress_rma_read_rsp(ep, xfer_entry);
		break;
	case ofi_op_read_req:
		ret = sm2_progress_rma_read_req(ep, xfer_entry);
		break;
	default:
		FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
			"Unidentified SAR operation type\n");
		ret = -FI_EINVAL;
	}
	return ret;
}

void sm2_progress_recv(struct sm2_ep *ep)
{
	struct sm2_atomic_entry *atomic_entry;
	struct sm2_xfer_entry *xfer_entry;
	int ret = 0, i;

	for (i = 0; i < MAX_SM2_MSGS_PROGRESSED; i++) {
		xfer_entry = sm2_fifo_read(ep);
		if (!xfer_entry)
			break;

		if (xfer_entry->hdr.proto == sm2_proto_return) {
			if (xfer_entry->hdr.op_flags & FI_REMOTE_READ) {
				atomic_entry = (struct sm2_atomic_entry *)
						       xfer_entry->user_data;
				ofi_copy_to_iov(
					atomic_entry->atomic_hdr.result_iov,
					atomic_entry->atomic_hdr
						.result_iov_count,
					0, atomic_entry->atomic_data.data,
					xfer_entry->hdr.size);
			}
			if (xfer_entry->hdr.op_flags & FI_DELIVERY_COMPLETE) {
				ret = sm2_complete_tx(
					ep, (void *) xfer_entry->hdr.context,
					xfer_entry->hdr.op,
					xfer_entry->hdr.op_flags);
				if (ret)
					FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
						"Unable to process "
						"FI_DELIVERY_COMPLETE "
						"completion\n");
			}

			ofi_spin_lock(&ep->tx_lock);
			sm2_freestack_push(ep, xfer_entry);
			ofi_spin_unlock(&ep->tx_lock);
			continue;
		}
		if (xfer_entry->hdr.proto == sm2_proto_sar) {
			ret = sm2_progress_sar_proto(ep, xfer_entry);
		}
		switch (xfer_entry->hdr.op) {
		case ofi_op_msg:
		case ofi_op_tagged:
			ret = sm2_progress_recv_msg(ep, xfer_entry);
			break;
		case ofi_op_atomic:
		case ofi_op_atomic_fetch:
		case ofi_op_atomic_compare:
			ret = sm2_progress_atomic(ep, xfer_entry);
			break;
		default:
			FI_WARN(&sm2_prov, FI_LOG_EP_CTRL,
				"Unidentified operation type\n");
			ret = -FI_EINVAL;
		}
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
