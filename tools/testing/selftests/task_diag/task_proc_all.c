#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>


int main()
{
	DIR *d;
	int fd;
	struct dirent *de;
	char buf[4096];

	d = opendir("/proc");
	if (d== NULL)
		return 1;

	while ((de = readdir(d))) {
		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		snprintf(buf, sizeof(buf), "/proc/%s/uid_map", de->d_name);
		fd = open(buf, O_RDONLY);
		read(fd, buf, 1);//sizeof(buf));
		close(fd);
	}

	closedir(d);

	return 1;
}
