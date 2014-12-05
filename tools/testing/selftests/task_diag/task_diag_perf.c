
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

#include <linux/genetlink.h>
#include "taskdiag.h"

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

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
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

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
		goto error;

	return fd;
error:
	close(fd);
	return -1;
}


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
	char name[100];

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

static int nlmsg_receive(void *buf, int len, int (*cb)(struct nlmsghdr *))
{
	struct nlmsghdr *hdr;

	for (hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
		if (hdr->nlmsg_type == NLMSG_DONE) {
			int *len = (int *)NLMSG_DATA(hdr);

			if (*len < 0) {
				printf("ERROR %d reported by netlink (%s)\n",
					*len, strerror(-*len));
				return *len;
			}

			return 0;
		}
		if (hdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);

			if (hdr->nlmsg_len - sizeof(*hdr) < sizeof(struct nlmsgerr)) {
				printf("ERROR truncated\n");
				return -1;
			}

			if (err->error == 0)
				return 0;

			return -1;
		}
		if (cb(hdr))
			return -1;
	}

	return 1;
}

int show_task(struct nlmsghdr *hdr)
{
	int msg_len;
	struct msgtemplate *msg;
	struct nlattr *na;
	int len;

	msg_len = GENLMSG_PAYLOAD(hdr);

	msg = (struct msgtemplate *)hdr;
	na = (struct nlattr *) GENLMSG_DATA(msg);
	len = 0;
	while (len < msg_len) {
		len += NLA_ALIGN(na->nla_len);
		switch (na->nla_type) {
		case TASK_DIAG_PID:
			break;
		case TASK_DIAG_PIDS:
		{
			struct task_diag_pids *pids;

			/* For nested attributes, na follows */
			pids = (struct task_diag_pids *) NLA_DATA(na);
			printf("ppid %d\n", pids->ppid);
			break;
		}
		case TASK_DIAG_COMM:
		{
			struct task_diag_comm *comm;
			comm = (struct task_diag_comm *) NLA_DATA(na);
			printf("state %d\n", comm->state);
			break;
		}
		case TASK_DIAG_CRED:
		{
			struct task_diag_creds *creds;
			creds = (struct task_diag_creds *) NLA_DATA(na);
			printf("uid: %d %d %d %d\n", creds->uid, creds->euid, creds->suid, creds->fsuid);
			printf("gid: %d %d %d %d\n", creds->uid, creds->euid, creds->suid, creds->fsuid);
			break;
		}
		default:
			fprintf(stderr, "Unknown nla_type %d\n",
				na->nla_type);
		}
		na = (struct nlattr *) (GENLMSG_DATA(msg) + len);
	}

	return 0;
}

static int stop;
void sigalarm(int sig)
{
	stop = 1;
}

int main(int argc, char *argv[])
{
	int rc, rep_len, i;
	__u16 id;
	__u32 mypid;
	int nl_sd = -1;
	struct {
		struct task_diag_pid req;
		int pids[2];
	} pid_req;
	char buf[4096];

	signal(SIGALRM, sigalarm);

	pid_req.req.show_flags = TASK_DIAG_SHOW_PIDS | TASK_DIAG_SHOW_COMM | TASK_DIAG_SHOW_CRED;
	pid_req.req.num = 2;
	pid_req.req.pids[0] = 1;
	pid_req.req.pids[1] = getpid();

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

	stop = 0;
	i = 0;
	alarm(1);
	while (!stop) {
		rc = send_cmd(nl_sd, id, mypid, TASKDIAG_CMD_GET,
			      TASKDIAG_CMD_ATTR_GET, &pid_req, sizeof(pid_req));
		if (rc < 0) {
			fprintf(stderr, "error sending tid/tgid cmd\n");
			goto err;
		}

		rep_len = recv(nl_sd, &buf, sizeof(buf), 0);

		if (rep_len < 0) {
			fprintf(stderr, "nonfatal reply error: errno %d\n",
				errno);
			goto err;
		}

		nlmsg_receive(buf, rep_len, &show_task);

		i++;
	}
	printf("task_diag: %d\n", i);

	int fd, fd_proc;
	fd_proc = open("/proc/", O_RDONLY);

	i = 0;
	stop = 0;
	alarm(1);
	while (!stop) {
		fd = openat(fd_proc, "1/status", O_RDONLY);
		if (fd < 0)
			break;
		read(fd, buf, sizeof(buf));
		close(fd);

		fd = openat(fd_proc, "self/status", O_RDONLY);
		if (fd < 0)
			break;
		read(fd, buf, sizeof(buf));
		close(fd);
		i++;
	}
	printf("proc: %d\n", i);
err:
	close(nl_sd);
	return 0;
}
