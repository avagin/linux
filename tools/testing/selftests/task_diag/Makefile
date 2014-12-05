all: task_diag task_diag_perf task_diag_all task_proc_all

CFLAGS += -Wall -O2

task_diag.o: task_diag.c task_diag_comm.h

task_diag_perf: task_diag_perf.c

task_diag_all.o: task_diag_all.c task_diag_comm.h
task_diag_comm.o: task_diag_comm.c task_diag_comm.h

task_diag_all: task_diag_all.o task_diag_comm.o

task_diag: task_diag.o task_diag_comm.o

clean:
	rm -rf task_diag task_diag_perf task_diag_all
