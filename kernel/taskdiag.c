#include <uapi/linux/taskdiag.h>
#include <net/genetlink.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>

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

	return size;
}

static int fill_pids(struct task_struct *p, struct sk_buff *skb)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct task_diag_pids *pids;
	struct nlattr *attr;
	pid_t ppid, tpid;

	attr = nla_reserve(skb, TASK_DIAG_PIDS, sizeof(struct task_diag_pids));
	if (!attr)
		return -EMSGSIZE;

	pids = nla_data(attr);

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

	return 0;
}

static int task_diag_fill(struct task_struct *tsk, struct sk_buff *skb,
				u64 show_flags, u32 portid, u32 seq)
{
	void *reply;
	int err;

	reply = genlmsg_put(skb, portid, seq, &family, 0, TASKDIAG_CMD_GET);
	if (reply == NULL)
		return -EMSGSIZE;

	if (show_flags & TASK_DIAG_SHOW_PIDS) {
		err = fill_pids(tsk, skb);
		if (err)
			goto err;
	}

	return genlmsg_end(skb, reply);
err:
	genlmsg_cancel(skb, reply);
	return err;
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

	size = sizeof(*req) + sizeof(req->pids[0]) * req->n_pids;
	if (nla_len(info->attrs[TASKDIAG_CMD_ATTR_GET]) < size)
		return -EINVAL;

	size = taskdiag_packet_size(req->show_flags) * req->n_pids;
	msg = genlmsg_new(size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	for (i = 0; i < req->n_pids; i++) {
		rcu_read_lock();
		tsk = find_task_by_pid_ns(req->pids[i], ns);
		if (tsk)
			get_task_struct(tsk);
		rcu_read_unlock();
		if (!tsk) {
			rc = -ESRCH;
			goto err;
		};

		if (!ptrace_may_access(tsk, PTRACE_MODE_READ)) {
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

static const struct nla_policy
			taskstats_cmd_get_policy[TASKDIAG_CMD_ATTR_MAX+1] = {
	[TASKDIAG_CMD_ATTR_GET]  = {	.type = NLA_UNSPEC,
					.len = sizeof(struct task_diag_pid)
				},
};

static const struct genl_ops taskdiag_ops[] = {
	{
		.cmd		= TASKDIAG_CMD_GET,
		.doit		= taskdiag_doit,
		.policy		= taskstats_cmd_get_policy,
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
