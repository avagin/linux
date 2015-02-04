
/* getdelays.c
 *
 * Utility to get per-pid and per-tgid delay accounting statistics
 * Also illustrates usage of the taskstats interface
 *
 * Copyright (C) Shailabh Nagar, IBM Corp. 2005
 * Copyright (C) Balbir Singh, IBM Corp. 2006
 * Copyright (c) Jay Lan, SGI. 2006
 *
 * Compile with
 *	gcc -I/usr/src/linux/include getdelays.c -o getdelays
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <sys/mman.h>

#include <linux/genetlink.h>
#include "taskdiag.h"

#define SOL_NETLINK     270

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)	(len - NLA_HDRLEN)

#define err(code, fmt, arg...)			\
	do {					\
		fprintf(stderr, fmt, ##arg);	\
		exit(code);			\
	} while (0)

int done;
int rcvbufsz;
char name[100];
int dbg = 1;

#define PRINTF(fmt, arg...) {			\
	    if (dbg) {				\
		printf(fmt, ##arg);		\
	    }					\
	}

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	1024
/* Maximum number of cpus expected to be specified in a cpumask */
#define MAX_CPUS	32

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_MSG_SIZE];
};

/*
 * Create a raw netlink socket and bind
 */
static int create_nl_socket(int protocol)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	if (rcvbufsz)
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
				&rcvbufsz, sizeof(rcvbufsz)) < 0) {
			fprintf(stderr, "Unable to set socket rcv buf size to %d\n",
				rcvbufsz);
			goto error;
		}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
		goto error;

	return fd;
error:
	close(fd);
	return -1;
}


//		rc = send_cmd(nl_sd, id, 1 /*mypid*/, TASKDIAG_CMD_GET,
//			      TASKDIAG_CMD_ATTR_PID, &pid_req, sizeof(pid_req));
static int send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
	     __u8 genl_cmd, __u16 nla_type,
	     void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len ;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return -1;
	}
	return 0;
}


/*
 * Probe the controller in genetlink to find the family id
 * for the TASKDIAG family
 */
static int get_family_id(int sd)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[256];
	} ans;

	int id = 0, rc;
	struct nlattr *na;
	int rep_len;

	strcpy(name, TASKDIAG_GENL_NAME);
	rc = send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, (void *)name,
			strlen(TASKDIAG_GENL_NAME)+1);
	if (rc < 0)
		return 0;	/* sendto() failure? */

	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (ans.n.nlmsg_type == NLMSG_ERROR ||
	    (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
	}
	return id;
}

int frame_size = 16384;
unsigned int ring_size;
void *rx_ring, *tx_ring;
void set_rings(int fd)
{
	unsigned int block_size = 16 * getpagesize();
	struct nl_mmap_req req = {
		.nm_block_size		= block_size,
		.nm_block_nr		= 64,
		.nm_frame_size		= 16384,
		.nm_frame_nr		= 64 * block_size / 16384,
	};

	/* Configure ring parameters */
	if (setsockopt(fd, SOL_NETLINK, NETLINK_RX_RING, &req, sizeof(req)) < 0)
		exit(1);
	if (setsockopt(fd, SOL_NETLINK, NETLINK_TX_RING, &req, sizeof(req)) < 0)
		exit(1);

	/* Calculate size of each individual ring */
	ring_size = req.nm_block_nr * req.nm_block_size;

	/* Map RX/TX rings. The TX ring is located after the RX ring */
	rx_ring = mmap(NULL, 2 * ring_size, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);
	if ((long)rx_ring == -1L)
		exit(1);
	tx_ring = rx_ring + ring_size;
}

void build_message(void *data, __u16 nlmsg_type, __u32 nlmsg_pid,
		 __u8 genl_cmd, __u16 nla_type,
		void *nla_data, int nla_len)
{
	struct msgtemplate *msg = data;
	struct nlattr *na;

	msg->n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg->n.nlmsg_type = nlmsg_type;
	msg->n.nlmsg_flags = NLM_F_REQUEST;
	msg->n.nlmsg_seq = 0;
	msg->n.nlmsg_pid = nlmsg_pid;
	msg->g.cmd = genl_cmd;
	msg->g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg->n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
}

int send_msg(int fd, __u16 nlmsg_type, __u32 nlmsg_pid,
		__u8 genl_cmd, __u16 nla_type,
		void *nla_data, int nla_len)
{
	static unsigned int frame_offset = 0;
	struct nl_mmap_hdr *hdr;
	struct nlmsghdr *nlh;
	struct sockaddr_nl addr = {
		.nl_family	= AF_NETLINK,
	};

	hdr = tx_ring + frame_offset;
	if (hdr->nm_status != NL_MMAP_STATUS_UNUSED)
		/* No frame available. Use poll() to avoid. */
		exit(1);

	nlh = (void *)hdr + NL_MMAP_HDRLEN;

	/* Build message */
	build_message(nlh, nlmsg_type, nlmsg_pid, genl_cmd, nla_type, nla_data, nla_len);

	/* Fill frame header: length and status need to be set */
	hdr->nm_len	= nlh->nlmsg_len;
	hdr->nm_status	= NL_MMAP_STATUS_VALID;

	if (sendto(fd, NULL, 0, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		exit(1);

	/* Advance frame offset to next frame */
	frame_offset = (frame_offset + frame_size) % ring_size;
}

void recv_msg(int fd)
{
	static unsigned int frame_offset = 0;
	struct nl_mmap_hdr *hdr;
	struct nlmsghdr *nlh;
	unsigned char buf[16384];
	ssize_t len;

	while (1) {
		struct pollfd pfds[1];

		pfds[0].fd	= fd;
		pfds[0].events	= POLLIN | POLLERR;
		pfds[0].revents	= 0;

		if (poll(pfds, 1, -1) < 0 && errno != -EINTR)
			exit(1);

		/* Check for errors. Error handling omitted */
		if (pfds[0].revents & POLLERR)
			exit(1);

		/* If no new messages, poll again */
		if (!(pfds[0].revents & POLLIN))
			continue;

		/* Process all frames */
		while (1) {
			/* Get next frame header */
			hdr = rx_ring + frame_offset;

			if (hdr->nm_status == NL_MMAP_STATUS_VALID) {
				/* Regular memory mapped frame */
				nlh = (void *)hdr + NL_MMAP_HDRLEN;
				len = hdr->nm_len;

				/* Release empty message immediately. May happen
				 * on error during message construction.
				 */
				if (len == 0)
					goto release;
			} else if (hdr->nm_status == NL_MMAP_STATUS_COPY) {
				/* Frame queued to socket receive queue */
				len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
				if (len <= 0)
					break;
				nlh = (void *)buf;
			} else
				/* No more messages to process, continue polling */
				break;

//			process_msg(nlh);
release:
			/* Release frame back to the kernel */
			hdr->nm_status = NL_MMAP_STATUS_UNUSED;

			/* Advance frame offset to next frame */
			frame_offset = (frame_offset + frame_size) % ring_size;
			return;
		}
	}
}

int main(int argc, char *argv[])
{
	int rc, rep_len;//, aggr_len;
	__u16 id;
	__u32 mypid;
	int nl_sd = -1;
//	int len = 0;
	struct task_diag_pid pid_req = {
			.pid = getpid(),
			.show_flags = TASK_DIAG_SHOW_PIDS |
					TASK_DIAG_SHOW_COMM
	};

//	struct nlattr *na;
	struct msgtemplate msg;


	nl_sd = create_nl_socket(NETLINK_GENERIC);
	if (nl_sd < 0) {
		err(1, "error creating Netlink socket\n");
		return -1;
	}


	mypid = getpid();
	id = get_family_id(nl_sd);
	if (!id) {
		fprintf(stderr, "Error getting family id, errno %d\n", errno);
		goto err;
	}

	set_rings(nl_sd);

	struct timeval start, end;
	int i, j;
	i = 0;
	gettimeofday(&start, NULL);
	while (1) {
		gettimeofday(&end, NULL);
		if ( (start.tv_sec + 1 < end.tv_sec) ||
		    (start.tv_sec + 1 == end.tv_sec && start.tv_usec <= end.tv_usec) ) {
			printf("%d\n", i);
			break;
		}

		i++;

		rc = send_cmd(nl_sd, id, 1 /*mypid*/, TASKDIAG_CMD_GET,
			      TASKDIAG_CMD_ATTR_PID, &pid_req, sizeof(pid_req));
		if (rc < 0) {
			fprintf(stderr, "error sending tid/tgid cmd\n");
			goto done;
		}
		recv_msg(nl_sd);
#if 0
		do {
			rep_len = recv(nl_sd, &msg, sizeof(msg), 0);

			if (rep_len < 0) {
				fprintf(stderr, "nonfatal reply error: errno %d\n",
					errno);
				continue;
			}
			if (msg.n.nlmsg_type == NLMSG_ERROR ||
			    !NLMSG_OK((&msg.n), rep_len)) {
				struct nlmsgerr *err = NLMSG_DATA(&msg);
				fprintf(stderr, "fatal reply error,  errno %d\n",
					err->error);
				goto done;
			}

	#if 0
			PRINTF("nlmsghdr size=%zu, nlmsg_len=%d, rep_len=%d\n",
			       sizeof(struct nlmsghdr), msg.n.nlmsg_len, rep_len);


			rep_len = GENLMSG_PAYLOAD(&msg.n);
			PRINTF("nlmsghdr size=%zu, nlmsg_len=%d, rep_len=%d\n",
			       sizeof(struct nlmsghdr), msg.n.nlmsg_len, rep_len);

			na = (struct nlattr *) GENLMSG_DATA(&msg);
			len = 0;
			while (len < rep_len) {
				len += NLA_ALIGN(na->nla_len);
				switch (na->nla_type) {
				case TASK_DIAG_PID:
					break;
				case TASK_DIAG_PIDS:
				{
					struct task_diag_pids *pids;

					aggr_len = NLA_PAYLOAD(na->nla_len);
					/* For nested attributes, na follows */
					pids = (struct task_diag_pids *) NLA_DATA(na);
					printf("ppid %d\n", pids->ppid);
					break;
				}
				case TASK_DIAG_COMM:
				{
					struct task_diag_comm *comm;
					aggr_len = NLA_PAYLOAD(na->nla_len);
					comm = (struct task_diag_comm *) NLA_DATA(na);
					printf("state %d\n", comm->state);
					break;
				}
				case TASK_DIAG_CRED:
				{
					struct task_diag_creds *creds;
					aggr_len = NLA_PAYLOAD(na->nla_len);
					creds = (struct task_diag_creds *) NLA_DATA(na);
					printf("uid: %d %d %d %d\n", creds->uid, creds->euid, creds->suid, creds->fsuid);
					printf("gid: %d %d %d %d\n", creds->uid, creds->euid, creds->suid, creds->fsuid);
					break;
				}
				default:
					fprintf(stderr, "Unknown nla_type %d\n",
						na->nla_type);
				}
				na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
			}
	#endif
		} while (0);
#endif
	}

	int fd, fd_self;
	char buf[4096];
	fd_self = open("/proc/", O_RDONLY);
	i = 0;
	gettimeofday(&start, NULL);
	while (1) {
		gettimeofday(&end, NULL);
		if ( (start.tv_sec + 1 < end.tv_sec) ||
		    (start.tv_sec + 1 == end.tv_sec && start.tv_usec <= end.tv_usec) ) {
			printf("%d\n", i);
			break;
		}

		i++;

		fd = openat(fd_self, "1/status", O_RDONLY);
		if (fd < 0)
			break;
		read(fd, buf, sizeof(buf));
		close(fd);
	}
done:
err:
	close(nl_sd);
	return 0;
}
