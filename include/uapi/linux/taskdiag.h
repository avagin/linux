#ifndef _LINUX_TASKDIAG_H
#define _LINUX_TASKDIAG_H

#include <linux/types.h>
#include <linux/capability.h>

#define TASKDIAG_GENL_NAME	"TASKDIAG"
#define TASKDIAG_GENL_VERSION	0x1

enum {
	TASK_DIAG_PIDS,
};

#define TASK_DIAG_SHOW_PIDS (1ULL << TASK_DIAG_PIDS)

struct task_diag_pids {
	__u32	tgid;
	__u32	ngid;
	__u32	pid;
	__u32	ppid;
	__u32	tpid;
};

enum {
	TASKDIAG_CMD_UNSPEC = 0,	/* Reserved */
	TASKDIAG_CMD_GET,
	__TASKDIAG_CMD_MAX,
};
#define TASKDIAG_CMD_MAX (__TASKDIAG_CMD_MAX - 1)

struct task_diag_pid {
	__u64	show_flags;
	__u32	n_pids;
	__u32	pids[0];
};

enum {
	TASKDIAG_CMD_ATTR_UNSPEC = 0,
	TASKDIAG_CMD_ATTR_GET,
	__TASKDIAG_CMD_ATTR_MAX,
};

#define TASKDIAG_CMD_ATTR_MAX (__TASKDIAG_CMD_ATTR_MAX - 1)

#endif /* _LINUX_TASKDIAG_H */
