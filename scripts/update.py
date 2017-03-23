#!/usr/bin/env python2

import subprocess

trees = [
    ("linux-next",  "master"),
    ("net",         "master"),
    ("vfs",         "for-next"),
    ("percpu",      "for-next"),
    ("cgroup",      "for-next"),
    ("userns",      "for-next"),
    ("tip",         "auto-latest"),
]

def run_cmd(cmd):
    print cmd,
    ret= subprocess.Popen(cmd, shell = True).wait()
    print "-> %d" % ret
    if ret:
        raise Exception(ret)

run_cmd("git fetch linux")
run_cmd("git checkout -f master")
run_cmd("git clean -dxf")
run_cmd("git rebase linux/master")
run_cmd("git push -f origin master")

for t in trees:
    branch="%s-%s" % (t[0], t[1])
    run_cmd("git fetch %s" % t[0])
    run_cmd("git branch -D %s || true" % branch)
    run_cmd("git checkout -f %s/%s -b %s" % (t[0], t[1], branch))
    run_cmd("git cherry-pick origin/master")
    p = subprocess.Popen("git diff --stat origin/%s" % branch, stdout = subprocess.PIPE, shell = True)
    out = p.stdout.read()
    p.stdout.close()
    p.wait()
    print out
    if not out:
        continue
    run_cmd("git push -f origin %s" % branch)

run_cmd("git checkout master")
