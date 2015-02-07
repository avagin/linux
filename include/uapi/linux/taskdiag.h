#ifndef _LINUX_TASKDIAG_H
#define _LINUX_TASKDIAG_H

#include <linux/types.h>
#include <linux/capability.h>

#define TASKDIAG_GENL_NAME	"TASKDIAG"
#define TASKDIAG_GENL_VERSION	0x1

enum {
	TASK_DIAG_PID,
	TASK_DIAG_PIDS,
	TASK_DIAG_COMM,
	TASK_DIAG_CRED,
};

#define TASK_DIAG_SHOW_PIDS (1ULL << TASK_DIAG_PIDS)
#define TASK_DIAG_SHOW_COMM (1ULL << TASK_DIAG_COMM)
#define TASK_DIAG_SHOW_CRED (1ULL << TASK_DIAG_CRED)

enum {
	TASK_DIAG_RUNNING,
	TASK_DIAG_INTERRUPTIBLE,
	TASK_DIAG_UNINTERRUPTIBLE,
	TASK_DIAG_STOPPED,
	TASK_DIAG_TRACE_STOP,
	TASK_DIAG_DEAD,
	TASK_DIAG_ZOMBIE,
};

struct task_diag_comm {
	__u8 state;
	char comm[0];
};

struct task_diag_caps {
	__u32 cap[_LINUX_CAPABILITY_U32S_3];
};

struct task_diag_creds {
	struct task_diag_caps cap_inheritable;
	struct task_diag_caps cap_permitted;
	struct task_diag_caps cap_effective;
	struct task_diag_caps cap_bset;

	__u32 uid;
	__u32 euid;
	__u32 suid;
	__u32 fsuid;
	__u32 gid;
	__u32 egid;
	__u32 sgid;
	__u32 fsgid;
};

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
	__u32	num;
	__u32	pids[0];
};

enum {
	TASKDIAG_CMD_ATTR_UNSPEC = 0,
	TASKDIAG_CMD_ATTR_GET,
	__TASKDIAG_CMD_ATTR_MAX,
};

#define TASKDIAG_CMD_ATTR_MAX (__TASKDIAG_CMD_ATTR_MAX - 1)

#endif /* _LINUX_TASKDIAG_H */
