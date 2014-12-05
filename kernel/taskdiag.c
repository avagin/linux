#include <uapi/linux/taskdiag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>

static struct genl_family family = {
	.id		= GENL_ID_GENERATE,
	.name		= TASKDIAG_GENL_NAME,
	.version	= TASKDIAG_GENL_VERSION,
	.maxattr	= TASKDIAG_CMD_ATTR_MAX,
	.netnsok	= true,
};

static size_t taskdiag_packet_size(void)
{
	size_t size;

	size = nla_total_size(sizeof(u32)) +
		nla_total_size(sizeof(struct task_diag_pids)) +
		nla_total_size(sizeof(struct task_diag_comm)) +
		nla_total_size(sizeof(struct task_diag_creds)) + nla_total_size(0);
	return size;
}

void fill_pids(struct task_struct *p, struct task_diag_pids *pids)
{
	pid_t ppid, tpid;
	struct pid_namespace *ns = task_active_pid_ns(current);

	rcu_read_lock(); // WHY
	ppid = pid_alive(p) ?
		task_tgid_nr_ns(rcu_dereference(p->real_parent), ns) : 0;
	tpid = 0;
	if (pid_alive(p)) {
		struct task_struct *tracer = ptrace_parent(p);
		if (tracer)
			tpid = task_pid_nr_ns(tracer, ns);
	}

	pids->tgid = task_tgid_nr_ns(p, ns);
	pids->ngid = task_numa_group_id(p);
	pids->pid = task_pid_nr_ns(p, ns);
	pids->ppid = ppid;
	pids->tpid = tpid;

	rcu_read_unlock();
}

/*
 * The task state array is a strange "bitmap" of
 * reasons to sleep. Thus "running" is zero, and
 * you can test for combinations of others with
 * simple bit tests.
 */
static const __u8 task_state_array[] = {
	TASK_DIAG_RUNNING,
	TASK_DIAG_INTERRUPTIBLE,
	TASK_DIAG_UNINTERRUPTIBLE,
	TASK_DIAG_STOPPED,
	TASK_DIAG_TRACE_STOP,
	TASK_DIAG_DEAD,
	TASK_DIAG_ZOMBIE,
};

static inline const __u8 get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->state | tsk->exit_state) & TASK_REPORT;

	BUILD_BUG_ON(1 + ilog2(TASK_REPORT) != ARRAY_SIZE(task_state_array)-1);

	return task_state_array[fls(state)];
}

static void fill_comm(struct task_struct *p, struct task_diag_comm *comm)
{
	comm->state = get_task_state(p);

}

static inline void caps2diag(struct task_diag_caps *diag, const kernel_cap_t *cap)
{
	int i;

	for (i = 0; i < _LINUX_CAPABILITY_U32S_3; i++)
		diag->cap[i] = cap->cap[i];
}

static void fill_creds(struct task_struct *p, struct task_diag_creds *diag_cred)
{
	const struct cred *cred;
	struct user_namespace *user_ns = current_user_ns();

	rcu_read_lock();
	cred = __task_cred(p);
	caps2diag(&diag_cred->cap_inheritable, &cred->cap_inheritable);
	caps2diag(&diag_cred->cap_permitted, &cred->cap_permitted);
	caps2diag(&diag_cred->cap_effective, &cred->cap_effective);
	caps2diag(&diag_cred->cap_bset, &cred->cap_bset);
	rcu_read_unlock();

	diag_cred->uid   = from_kuid_munged(user_ns, cred->uid);
	diag_cred->euid  = from_kuid_munged(user_ns, cred->euid);
	diag_cred->suid  = from_kuid_munged(user_ns, cred->suid);
	diag_cred->fsuid = from_kuid_munged(user_ns, cred->fsuid);
	diag_cred->gid   = from_kgid_munged(user_ns, cred->gid);
	diag_cred->egid  = from_kgid_munged(user_ns, cred->egid);
	diag_cred->sgid  = from_kgid_munged(user_ns, cred->sgid);
	diag_cred->fsgid = from_kgid_munged(user_ns, cred->fsgid);

}

static int prepare_reply(struct genl_info *info, u8 cmd, struct sk_buff **skbp,
				size_t size)
{
	struct sk_buff *skb;
	void *reply;

	/*
	 * If new attributes are added, please revisit this allocation
	 */
	skb = genlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	reply = genlmsg_put_reply(skb, info, &family, 0, cmd);
	if (reply == NULL) {
		nlmsg_free(skb);
		return -EINVAL;
	}

	*skbp = skb;
	return 0;
}

/*
 * Send taskstats data in @skb to listener with nl_pid @pid
 */
static int send_reply(struct sk_buff *skb, struct genl_info *info)
{
	struct genlmsghdr *genlhdr = nlmsg_data(nlmsg_hdr(skb));
	void *reply = genlmsg_data(genlhdr);
	int rc;

	rc = genlmsg_end(skb, reply);
	if (rc < 0) {
		nlmsg_free(skb);
		return rc;
	}

	return genlmsg_reply(skb, info);
}

static int taskdiag_user_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *rep_skb;
	struct nlattr *attr;
	struct task_struct *tsk = NULL;
	size_t size;
	pid_t pid;
	int rc;

	if (!info->attrs[TASKDIAG_CMD_ATTR_PID])
		return -EINVAL;

	size = taskdiag_packet_size();

	rc = prepare_reply(info, TASKDIAG_CMD_NEW, &rep_skb, size);
	if (rc < 0)
		return rc;

	pid = nla_get_u32(info->attrs[TASKDIAG_CMD_ATTR_PID]);
	if (nla_put(rep_skb, TASK_DIAG_PID, sizeof(pid), &pid) < 0)
		goto err;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (tsk)
		get_task_struct(tsk);
	rcu_read_unlock();
	if (!tsk) {
		rc = -ESRCH;
		goto err;
	};

	attr = nla_reserve(rep_skb, TASK_DIAG_PIDS, sizeof(struct task_diag_pids));
	if (!attr)
		goto err;

	fill_pids(tsk, nla_data(attr));

	attr = nla_reserve(rep_skb, TASK_DIAG_COMM, sizeof(struct task_diag_comm));
	if (!attr)
		goto err;

	fill_comm(tsk, nla_data(attr));

	attr = nla_reserve(rep_skb, TASK_DIAG_CRED, sizeof(struct task_diag_creds));
	if (!attr)
		goto err;

	fill_creds(tsk, nla_data(attr));

	put_task_struct(tsk);

	return send_reply(rep_skb, info);
err:
	if (tsk)
		put_task_struct(tsk);
	nlmsg_free(rep_skb);
	return rc;
}

static const struct nla_policy taskstats_cmd_get_policy[TASKDIAG_CMD_ATTR_MAX+1] = {
		[TASKDIAG_CMD_ATTR_PID]  = { .type = NLA_U32 },
	};

static const struct genl_ops taskdiag_ops[] = {
	{
		.cmd		= TASKDIAG_CMD_GET,
		.doit		= taskdiag_user_cmd,
		.policy		= taskstats_cmd_get_policy,
		.flags		= GENL_ADMIN_PERM,
	},
};

static int __init taskdiag_init(void)
{
	int rc;

	rc = genl_register_family_with_ops(&family, taskdiag_ops);
	if (rc)
		return rc;

	return 0;
}

/*
 * late initcall ensures initialization of statistics collection
 * mechanisms precedes initialization of the taskstats interface
 */
late_initcall(taskdiag_init);
