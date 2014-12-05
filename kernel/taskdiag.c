#include <uapi/linux/taskdiag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>

static struct genl_family family = {
	.id		= GENL_ID_GENERATE,
	.name		= TASKDIAG_GENL_NAME,
	.version	= TASKDIAG_GENL_VERSION,
	.maxattr	= TASKDIAG_CMD_ATTR_MAX,
	.netnsok	= true,
};

static size_t taskdiag_packet_size(u64 show_flags)
{
	size_t size;

	size = nla_total_size(sizeof(u32));
	if (show_flags & TASK_DIAG_SHOW_PIDS)
		size += nla_total_size(sizeof(struct task_diag_pids));
	if (show_flags & TASK_DIAG_SHOW_COMM)
		size += nla_total_size(sizeof(struct task_diag_comm));
	if (show_flags & TASK_DIAG_SHOW_CRED)
		size += nla_total_size(sizeof(struct task_diag_creds));

	return size;
}

void fill_pids(struct task_struct *p, struct task_diag_pids *pids)
{
	pid_t ppid, tpid;
	struct pid_namespace *ns = task_active_pid_ns(current);

	rcu_read_lock();
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

	cred = get_task_cred(p);

	caps2diag(&diag_cred->cap_inheritable, &cred->cap_inheritable);
	caps2diag(&diag_cred->cap_permitted, &cred->cap_permitted);
	caps2diag(&diag_cred->cap_effective, &cred->cap_effective);
	caps2diag(&diag_cred->cap_bset, &cred->cap_bset);

	diag_cred->uid   = from_kuid_munged(user_ns, cred->uid);
	diag_cred->euid  = from_kuid_munged(user_ns, cred->euid);
	diag_cred->suid  = from_kuid_munged(user_ns, cred->suid);
	diag_cred->fsuid = from_kuid_munged(user_ns, cred->fsuid);
	diag_cred->gid   = from_kgid_munged(user_ns, cred->gid);
	diag_cred->egid  = from_kgid_munged(user_ns, cred->egid);
	diag_cred->sgid  = from_kgid_munged(user_ns, cred->sgid);
	diag_cred->fsgid = from_kgid_munged(user_ns, cred->fsgid);

}

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
				u64 show_flags, u32 portid, u32 seq)
{
	struct nlattr *attr;
	void *reply;

	reply = genlmsg_put(skb, portid, seq, &family, 0, TASKDIAG_CMD_GET);
	if (reply == NULL)
		return -EMSGSIZE;

	if (show_flags & TASK_DIAG_SHOW_PIDS) {
		attr = nla_reserve(skb, TASK_DIAG_PIDS, sizeof(struct task_diag_pids));
		if (!attr)
			goto err;

		fill_pids(tsk, nla_data(attr));
	}

	if (show_flags & TASK_DIAG_SHOW_COMM) {
		attr = nla_reserve(skb, TASK_DIAG_COMM, sizeof(struct task_diag_comm));
		if (!attr)
			goto err;

		fill_comm(tsk, nla_data(attr));
	}

	if (show_flags & TASK_DIAG_SHOW_CRED) {
		attr = nla_reserve(skb, TASK_DIAG_CRED, sizeof(struct task_diag_creds));
		if (!attr)
			goto err;

		fill_creds(tsk, nla_data(attr));
	}

	return genlmsg_end(skb, reply);
err:
	genlmsg_cancel(skb, reply);
	return -EMSGSIZE;
}

static int taskdiag_dumpid(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct tgid_iter iter;
	struct nlattr *na;
	struct task_diag_pid *req;
	int rc;

	if (nlmsg_len(cb->nlh) < GENL_HDRLEN + sizeof(*req))
		return -EINVAL;

	na = nlmsg_data(cb->nlh) + GENL_HDRLEN;
	if (na->nla_type < 0)
		return -EINVAL;

	req = (struct task_diag_pid *) nla_data(na);

	iter.tgid = cb->args[0];
	iter.task = NULL;
	for (iter = next_tgid(ns, iter);
	     iter.task;
	     iter.tgid += 1, iter = next_tgid(ns, iter)) {
		if (!has_pid_permissions(ns, iter.task, 2))
			continue;

		rc = task_diag_fill(iter.task, skb, req->show_flags,
				NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq);
		if (rc < 0) {
			put_task_struct(iter.task);
			if (rc != -EMSGSIZE)
				return rc;
			break;
		}
	}

	cb->args[0] = iter.tgid;

	return skb->len;
}

static int taskdiag_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct task_struct *tsk = NULL;
	struct task_diag_pid *req;
	struct sk_buff *msg;
	size_t size;
	int rc, i;

	req = nla_data(info->attrs[TASKDIAG_CMD_ATTR_GET]);
	if (req == NULL)
		return -EINVAL;

	size = sizeof(*req) + sizeof(req->pids[0]) * req->num;
	if (nla_len(info->attrs[TASKDIAG_CMD_ATTR_GET]) < size)
		return -EINVAL;

	size = taskdiag_packet_size(req->show_flags) * req->num;;
	msg = genlmsg_new(size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	for (i = 0; i < req->num; i++) {
		rcu_read_lock();
		tsk = find_task_by_pid_ns(req->pids[i], ns);
		if (tsk)
			get_task_struct(tsk);
		rcu_read_unlock();
		if (!tsk) {
			rc = -ESRCH;
			goto err;
		};

		if (!has_pid_permissions(ns, tsk, 2)) {
			put_task_struct(tsk);
			continue;
		}

		rc = task_diag_fill(tsk, msg, req->show_flags,
					info->snd_portid, info->snd_seq);
		put_task_struct(tsk);
		if (rc < 0)
			goto err;
	}

	return genlmsg_reply(msg, info);
err:
	nlmsg_free(msg);
	return rc;
}

static const struct nla_policy taskstats_cmd_get_policy[TASKDIAG_CMD_ATTR_MAX+1] = {
	[TASKDIAG_CMD_ATTR_GET]  = {	.type = NLA_UNSPEC,
					.len = sizeof(struct task_diag_pid)
				},
};

static const struct genl_ops taskdiag_ops[] = {
	{
		.cmd		= TASKDIAG_CMD_GET,
		.doit		= taskdiag_doit,
		.dumpit		= taskdiag_dumpid,
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
