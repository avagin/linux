#!/usr/bin/env python2

import subprocess

trees = [
    ("linux-next",  "master"),
    ("net-next",    "master"),
    ("net",         "master"),
    ("vfs",         "for-next"),
    ("cgroup",      "for-next"),
    ("userns",      "for-next"),
    ("userns",      "for-linus"),
    ("tip",         "auto-latest"),
    ("mmotm",       "auto-latest"),
    ("dsahern",     "neigh/per-net-ns"),
    ("dhowells-fs", "mount-api"),
]

def run_cmd(cmd):
    print cmd,
    ret= subprocess.Popen(cmd, shell = True).wait()
    print "-> %d" % ret
    if ret:
        raise Exception(ret)

run_cmd("git fetch -n linux")
run_cmd("git checkout -f master")
run_cmd("git clean -dxf")
run_cmd("git rebase linux/master")
run_cmd("git push -f origin master")

for t in trees:
    branch="%s-%s" % (t[0], t[1])
    run_cmd("git fetch %s" % t[0])
    p = subprocess.Popen("git diff --stat origin/%s~1 %s/%s" % (branch, t[0], t[1]), stdout = subprocess.PIPE, shell = True)
    out = p.stdout.read()
    p.stdout.close()
    ret = p.wait()
    print out
    if ret == 0 and not out:
        continue
    run_cmd("git branch -f -D %s || true" % branch)
    run_cmd("git checkout -f %s/%s -b %s" % (t[0], t[1], branch))
    run_cmd("git cherry-pick origin/master")
    run_cmd("git push -f origin %s" % branch)

run_cmd("git checkout master")
