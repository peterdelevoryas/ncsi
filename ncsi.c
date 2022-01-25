/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NC-SI (Network Controller Sideband Interface) "echo" model
 *
 * Copyright (C) 2016-2018 IBM Corp.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "ncsi.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static uint32_t ncsi_calculate_checksum(uint8_t *data, int len)
{
    uint32_t checksum = 0;
    int i;

    /*
     * 32-bit unsigned sum of the NC-SI packet header and NC-SI packet
     * payload interpreted as a series of 16-bit unsigned integer values.
     */
    for (i = 0; i < len; i += 2) {
        checksum += (((uint16_t) data[i]) << 8) + data[i+1];
    }

    checksum = (~checksum + 1);
    return checksum;
}

/* Deselect Package */
static int ncsi_rsp_handler_dp(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                               struct ncsi_rsp_pkt_hdr *rnh)
{
    // Make sure it's not 0x1f, which is usually copied from the command
    // header.
    rnh->common.channel = 0x00;

    return 0;
}

static const char *get_mfr_name(uint32_t mfr_id)
{
    switch (mfr_id) {
    case NCSI_OEM_MFR_MLX_ID:
        return "mlx";
    case NCSI_OEM_MFR_BCM_ID:
        return "bcm";
    case NCSI_OEM_MFR_INTEL_ID:
        return "intel";
    default:
        return "nic";
    }
}

/* Get Version ID */
static int ncsi_rsp_handler_gvi(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                                struct ncsi_rsp_pkt_hdr *rnh)
{
    struct ncsi_rsp_gvi_pkt *rsp = (struct ncsi_rsp_gvi_pkt *)rnh;
    const char *mfr_name = get_mfr_name(slirp->mfr_id);

    rsp->ncsi_version = htonl(0xF1F0F000);
    rsp->mf_id = htonl(slirp->mfr_id);
    snprintf((char *)rsp->fw_name, sizeof(rsp->fw_name), "%s0.1", mfr_name);
    rsp->fw_version = htonl(0x00010000);

    return 0;
}

/* Get Capabilities */
static int ncsi_rsp_handler_gc(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                               struct ncsi_rsp_pkt_hdr *rnh)
{
    struct ncsi_rsp_gc_pkt *rsp = (struct ncsi_rsp_gc_pkt *)rnh;

    rsp->cap = htonl(~0);
    rsp->bc_cap = htonl(~0);
    rsp->mc_cap = htonl(~0);
    rsp->buf_cap = htonl(~0);
    rsp->aen_cap = htonl(~0);
    rsp->vlan_mode = 0xff;
    rsp->uc_cnt = 2;
    return 0;
}

/* Get Link status */
static int ncsi_rsp_handler_gls(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                                struct ncsi_rsp_pkt_hdr *rnh)
{
    struct ncsi_rsp_gls_pkt *rsp = (struct ncsi_rsp_gls_pkt *)rnh;

    rsp->status = htonl(0x1);
    return 0;
}

/* Get Parameters */
static int ncsi_rsp_handler_gp(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                               struct ncsi_rsp_pkt_hdr *rnh)
{
    struct ncsi_rsp_gp_pkt *rsp = (struct ncsi_rsp_gp_pkt *)rnh;

    /* no MAC address filters or VLAN filters on the channel */
    rsp->mac_cnt = 0;
    rsp->mac_enable = 0;
    rsp->vlan_cnt = 0;
    rsp->vlan_enable = 0;

    return 0;
}

/* Response handler for Mellanox command Get Mac Address */
static int ncsi_rsp_handler_oem_mlx_gma(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                                        struct ncsi_rsp_pkt_hdr *rnh)
{
    struct ncsi_rsp_oem_pkt *rsp = (struct ncsi_rsp_oem_pkt *)rnh;

    rnh->common.length = htons(24);
    memcpy(&rsp->data[MLX_MAC_ADDR_OFFSET], slirp->ncsi_mac, ETH_ALEN);

    return 0;
}

/* Response handler for Mellanox command Set MC Affinity */
static int ncsi_rsp_handler_oem_mlx_smaf(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                                         struct ncsi_rsp_pkt_hdr *rnh)
{
    const struct ncsi_cmd_oem_pkt *cmd = (const struct ncsi_cmd_oem_pkt *)nh;
    struct ncsi_rsp_oem_pkt *rsp = (struct ncsi_rsp_oem_pkt *)rnh;
    unsigned char host_number = cmd->data[3];

    rnh->common.length = htons(12);
    rsp->data[0] = 0x00;
    rsp->data[1] = 0x01;
    rsp->data[2] = 0x07;
    rsp->data[3] = host_number;

    return 0;
}

/* Response handler for Mellanox card */
static int ncsi_rsp_handler_oem_mlx(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                                    struct ncsi_rsp_pkt_hdr *rnh)
{
    const struct ncsi_cmd_oem_pkt *cmd;
    const struct ncsi_cmd_oem_mlx_pkt *mlx_cmd;
    struct ncsi_rsp_oem_pkt *rsp;
    struct ncsi_rsp_oem_mlx_pkt *mlx_rsp;

    cmd = (const struct ncsi_cmd_oem_pkt *)nh;
    rsp = (struct ncsi_rsp_oem_pkt *)rnh;
    mlx_cmd = (const struct ncsi_cmd_oem_mlx_pkt *)cmd->data;
    mlx_rsp = (struct ncsi_rsp_oem_mlx_pkt *)rsp->data;
    mlx_rsp->cmd_rev = mlx_cmd->cmd_rev;
    mlx_rsp->cmd = mlx_cmd->cmd;
    mlx_rsp->param = mlx_cmd->param;

    if (mlx_cmd->cmd == NCSI_OEM_MLX_CMD_GMA &&
        mlx_cmd->param == NCSI_OEM_MLX_CMD_GMA_PARAM) {
        return ncsi_rsp_handler_oem_mlx_gma(slirp, nh, rnh);
    }
    if (mlx_cmd->cmd == NCSI_OEM_MLX_CMD_SMAF &&
        mlx_cmd->param == NCSI_OEM_MLX_CMD_SMAF_PARAM) {
        return ncsi_rsp_handler_oem_mlx_smaf(slirp, nh, rnh);
    }

    return 0;
}

static struct ncsi_rsp_oem_handler {
    uint32_t mfr_id;
    int (*handler)(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                   struct ncsi_rsp_pkt_hdr *rnh);
} ncsi_rsp_oem_handlers[] = {
    { NCSI_OEM_MFR_MLX_ID, ncsi_rsp_handler_oem_mlx },
    { NCSI_OEM_MFR_BCM_ID, NULL },
    { NCSI_OEM_MFR_INTEL_ID, NULL },
};

/* OEM Command */
static int ncsi_rsp_handler_oem(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                                struct ncsi_rsp_pkt_hdr *rnh)
{
    const struct ncsi_cmd_oem_pkt *cmd = (const struct ncsi_cmd_oem_pkt *)nh;
    const struct ncsi_rsp_oem_handler *handler = NULL;
    struct ncsi_rsp_oem_pkt *rsp = (struct ncsi_rsp_oem_pkt *)rnh;
    uint32_t mfr_id = ntohl(cmd->mfr_id);
    int i;

    if (mfr_id != slirp->mfr_id) {
        rnh->common.length = 0;
        rnh->code = htons(NCSI_PKT_RSP_C_UNSUPPORTED);
        rnh->reason = htons(NCSI_PKT_RSP_R_UNKNOWN);
        return -1;
    }
    rsp->mfr_id = cmd->mfr_id;

    for (i = 0; i < ARRAY_SIZE(ncsi_rsp_oem_handlers); i++) {
        if (ncsi_rsp_oem_handlers[i].mfr_id == mfr_id) {
            handler = &ncsi_rsp_oem_handlers[i];
            break;
        }
    }

    if (!handler) {
        rnh->common.length = 0;
        rnh->code = htons(NCSI_PKT_RSP_C_UNAVAILABLE);
        rnh->reason = htons(NCSI_PKT_RSP_R_UNKNOWN);
        return -1;
    }
    return handler->handler(slirp, nh, rnh);
}

/* PLDM Command */
static int ncsi_rsp_handler_pldm(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                                 struct ncsi_rsp_pkt_hdr *rnh)
{
    return 0;
}

static const struct ncsi_rsp_handler {
    unsigned char type;
    int payload;
    int (*handler)(Slirp *slirp, const struct ncsi_pkt_hdr *nh,
                   struct ncsi_rsp_pkt_hdr *rnh);
} ncsi_rsp_handlers[] = { { NCSI_PKT_RSP_CIS, 4, NULL },
                          { NCSI_PKT_RSP_SP, 4, NULL },
                          { NCSI_PKT_RSP_DP, 4, ncsi_rsp_handler_dp },
                          { NCSI_PKT_RSP_EC, 4, NULL },
                          { NCSI_PKT_RSP_DC, 4, NULL },
                          { NCSI_PKT_RSP_RC, 4, NULL },
                          { NCSI_PKT_RSP_ECNT, 4, NULL },
                          { NCSI_PKT_RSP_DCNT, 4, NULL },
                          { NCSI_PKT_RSP_AE, 4, NULL },
                          { NCSI_PKT_RSP_SL, 4, NULL },
                          { NCSI_PKT_RSP_GLS, 16, ncsi_rsp_handler_gls },
                          { NCSI_PKT_RSP_SVF, 4, NULL },
                          { NCSI_PKT_RSP_EV, 4, NULL },
                          { NCSI_PKT_RSP_DV, 4, NULL },
                          { NCSI_PKT_RSP_SMA, 4, NULL },
                          { NCSI_PKT_RSP_EBF, 4, NULL },
                          { NCSI_PKT_RSP_DBF, 4, NULL },
                          { NCSI_PKT_RSP_EGMF, 4, NULL },
                          { NCSI_PKT_RSP_DGMF, 4, NULL },
                          { NCSI_PKT_RSP_SNFC, 4, NULL },
                          { NCSI_PKT_RSP_GVI, 40, ncsi_rsp_handler_gvi },
                          { NCSI_PKT_RSP_GC, 32, ncsi_rsp_handler_gc },
                          { NCSI_PKT_RSP_GP, 40, ncsi_rsp_handler_gp },
                          { NCSI_PKT_RSP_GCPS, 172, NULL },
                          { NCSI_PKT_RSP_GNS, 172, NULL },
                          { NCSI_PKT_RSP_GNPTS, 172, NULL },
                          { NCSI_PKT_RSP_GPS, 8, NULL },
                          { NCSI_PKT_RSP_OEM, 0, ncsi_rsp_handler_oem },
                          { NCSI_PKT_RSP_PLDM, 8, ncsi_rsp_handler_pldm },
                          { NCSI_PKT_RSP_GPUUID, 20, NULL } };

/*
 * packet format : ncsi header + payload + checksum
 */
#define NCSI_MAX_PAYLOAD 172
#define NCSI_MAX_LEN (sizeof(struct ncsi_pkt_hdr) + NCSI_MAX_PAYLOAD + 4)

void ncsi_input(Slirp *slirp, const uint8_t *pkt, int pkt_len)
{
    const struct ncsi_pkt_hdr *nh =
        (const struct ncsi_pkt_hdr *)(pkt + ETH_HLEN);
    uint8_t ncsi_reply[ETH_HLEN + NCSI_MAX_LEN];
    struct ethhdr *reh = (struct ethhdr *)ncsi_reply;
    struct ncsi_rsp_pkt_hdr *rnh =
        (struct ncsi_rsp_pkt_hdr *)(ncsi_reply + ETH_HLEN);
    const struct ncsi_rsp_handler *handler = NULL;
    int i;
    int ncsi_rsp_len = sizeof(*nh);
    uint32_t checksum;
    uint32_t *pchecksum;

    if (pkt_len < ETH_HLEN + sizeof(struct ncsi_pkt_hdr)) {
        return; /* packet too short */
    }

    memset(ncsi_reply, 0, sizeof(ncsi_reply));

    memset(reh->h_dest, 0xff, ETH_ALEN);
    memset(reh->h_source, 0xff, ETH_ALEN);
    reh->h_proto = htons(ETH_P_NCSI);

    for (i = 0; i < ARRAY_SIZE(ncsi_rsp_handlers); i++) {
        if (ncsi_rsp_handlers[i].type == nh->type + 0x80) {
            handler = &ncsi_rsp_handlers[i];
            break;
        }
    }

    rnh->common.mc_id = nh->mc_id;
    rnh->common.revision = NCSI_PKT_REVISION;
    rnh->common.id = nh->id;
    rnh->common.type = nh->type + 0x80;
    rnh->common.channel = nh->channel;

    if (handler) {
        rnh->common.length = htons(handler->payload);
        rnh->code = htons(NCSI_PKT_RSP_C_COMPLETED);
        rnh->reason = htons(NCSI_PKT_RSP_R_NO_ERROR);

        if (handler->handler) {
            /* TODO: handle errors */
            handler->handler(slirp, nh, rnh);
        }
        ncsi_rsp_len += ntohs(rnh->common.length);
    } else {
        rnh->common.length = 0;
        rnh->code = htons(NCSI_PKT_RSP_C_UNAVAILABLE);
        rnh->reason = htons(NCSI_PKT_RSP_R_UNKNOWN);
    }

    /* Add the optional checksum at the end of the frame. */
    checksum = ncsi_calculate_checksum((uint8_t *)rnh, ncsi_rsp_len);
    pchecksum = (uint32_t *)((void *)rnh + ncsi_rsp_len);
    *pchecksum = htonl(checksum);
    ncsi_rsp_len += 4;

    slirp_send_packet_all(slirp, ncsi_reply, ETH_HLEN + ncsi_rsp_len);
}

void slirp_send_packet_all(Slirp *slirp, const void *buf, size_t len)
{
  if (send(slirp->socket, buf, len, 0) != (ssize_t)len) {
    perror("send");
  }
}
