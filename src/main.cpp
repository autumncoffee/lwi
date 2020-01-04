#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sys/mount.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <ac-common/file.hpp>
#include <time.h>
#include <vector>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#ifdef RELEASE_FILESYSTEM
#include <filesystem>
#else
#include <experimental/filesystem>

namespace std {
    namespace filesystem = std::experimental::filesystem;
}
#endif

dev_t GetDeviceID(const std::string& path) {
    struct stat out;
    int rv = stat(path.c_str(), &out);

    if (rv == -1) {
        perror(("stat(" + path + ")").c_str());
        return 0;
    }

    return out.st_dev;
}

bool IsMountPoint(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return false;
    }

    return (GetDeviceID(path.string()) != GetDeviceID(path.parent_path().string()));
}

void SeedFile(const std::filesystem::path& path, const std::string& data) {
    if (!std::filesystem::exists(path)) {
        NAC::TFile file(path.string(), NAC::TFile::ACCESS_CREATEX);
        file.Append(data);
    }
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " id /path/to/workdir /path/to/binary [binary args]" << std::endl;
        return 1;
    }

    std::filesystem::path workdir(std::filesystem::absolute(argv[2]));
    std::filesystem::create_directories(workdir);

    {
        int rv = chdir(argv[2]);

        if (rv == -1) {
            perror((std::string("chdir(") + argv[2] + ")").c_str());
            return 1;
        }
    }

    {
        std::filesystem::path cgroupDir(workdir / "cgroup");
        std::filesystem::create_directory(cgroupDir);

        static const std::string cgroupVersionFileName(".cgver");

        if (!IsMountPoint(cgroupDir)) {
            int rv = mount("none", cgroupDir.c_str(), "cgroup2", 0, nullptr);

            if (rv == 0) {
                NAC::TFile file(cgroupVersionFileName, NAC::TFile::ACCESS_CREATE);
                file.Append("2");

            } else if (errno == ENODEV) {
                static const std::string defaultCGroupPath("/sys/fs/cgroup");

                if (!IsMountPoint(defaultCGroupPath)) {
                    std::filesystem::create_directories(defaultCGroupPath);
                    rv = mount("cgroup_root", defaultCGroupPath.c_str(), "tmpfs", 0, nullptr);

                    if (rv == -1) {
                        perror("mount(cgroup)");
                        return 1;
                    }
                }

                rv = mount(defaultCGroupPath.c_str(), cgroupDir.c_str(), "none", MS_BIND, nullptr);

                if (rv == -1) {
                    perror("mount(bind cgroup)");
                    return 1;
                }

                NAC::TFile file(cgroupVersionFileName, NAC::TFile::ACCESS_CREATE);
                file.Append("1");

            } else {
                perror("mount(cgroup2)");
                return 1;
            }
        }

        NAC::TFile cgroupVersionFile(cgroupVersionFileName);
        const std::string pidStr(std::to_string(getpid()));

        if (!cgroupVersionFile) {
            std::cerr << "Failed to get cgroup version" << std::endl;
            return 1;
        }

        if (cgroupVersionFile[0] == '1') {
            for (const std::string& controller : {
                "cpu",
                "cpuacct",
                "memory",
                "blkio",
                "pids"
            }) {
                std::filesystem::path path(cgroupDir / controller);

                if (!IsMountPoint(path)) {
                    std::filesystem::create_directory(path);

                    int rv = mount(controller.c_str(), path.c_str(), "cgroup", 0, controller.c_str());

                    if (rv == -1) {
                        perror(("mount(cgroup/" + controller + ")").c_str());
                        return 1;
                    }
                }

                path /= argv[1];
                std::filesystem::create_directory(path);

                NAC::TFile file((path / "cgroup.procs").string(), NAC::TFile::ACCESS_CREATE);
                file.Append(pidStr);

                if (!file) {
                    std::cerr << "Failed to add process to cgroup" << std::endl;
                    return 1;
                }
            }

        } else if (cgroupVersionFile[0] == '2') {
            auto path = cgroupDir / argv[1];
            std::filesystem::create_directory(path);

            NAC::TFile file((path / "cgroup.procs").string(), NAC::TFile::ACCESS_CREATE);
            file.Append(pidStr);

            if (!file) {
                std::cerr << "Failed to add process to cgroup2" << std::endl;
                return 1;
            }

        } else {
            std::cerr << "Invalid cgroup version" << std::endl;
            return 1;
        }
    }

    std::filesystem::path rootDir(workdir / "root");
    std::filesystem::create_directory(rootDir);

    {
        auto etcDir = rootDir / "etc";
        std::filesystem::create_directory(etcDir);

        SeedFile(etcDir / "shadow", "root:*:16176:0:99999:7:::\n");
        SeedFile(etcDir / "passwd", "root:x:0:0:root:/:/bin/sh\n");
        SeedFile(etcDir / "group", "root:x:0:\n");
    }

    {
        std::filesystem::path nsDir(workdir / "ns");
        std::filesystem::create_directory(nsDir);

        static const std::filesystem::path selfNs("/proc/self/ns");

        static const std::vector<std::pair<int, std::string>> nsMap {
            {CLONE_NEWCGROUP, "cgroup"},
            {CLONE_NEWIPC, "ipc"},
            // {CLONE_NEWUSER, "user"},
            {CLONE_NEWNET, "net"},
            {CLONE_NEWUTS, "uts"},
            {CLONE_NEWNS, "mnt"} // this should be the last one
        };

        int flags(0);
        int supportedFlags(0);

        for (const auto& it : nsMap) {
            if (!std::filesystem::exists(selfNs / it.second)) {
                continue;
            }

            supportedFlags |= it.first;

            auto path = nsDir / it.second;

            if (!IsMountPoint(path)) {
                flags |= it.first;
                NAC::TFile file(path.string(), NAC::TFile::ACCESS_CREATE);
            }
        }

        if (flags > 0) {
            int fds[2];

            {
                int rv = pipe(fds);

                if (rv == -1) {
                    perror("pipe");
                    return 1;
                }
            }

            int pid = fork();

            if (pid < 0) {
                perror("fork");
                return 1;

            } else if (pid == 0) {
                close(fds[0]);
                int rv = unshare(flags);

                if (rv == -1) {
                    perror("unshare");
                    return 1;
                }

                write(fds[1], "1", 1);

                unsigned int toSleep(60);

                while (toSleep > 0) {
                    toSleep = sleep(toSleep);
                }

                return 0;

            } else {
                close(fds[1]);

                char buf;
                int rv = read(fds[0], &buf, 1);

                if (rv != 1) {
                    if (rv == -1) {
                        perror("read");
                    }

                    kill(pid, 9);
                    waitpid(pid, nullptr, 0);
                    return 1;
                }

                const std::filesystem::path childNs("/proc/" + std::to_string(pid) + "/ns");

                for (const auto& it : nsMap) {
                    if (flags & it.first) {
                        int rv = mount((childNs / it.second).c_str(), (nsDir / it.second).c_str(), "none", MS_BIND, nullptr);

                        if (rv == -1) {
                            perror(("mount(bind namespace " + it.second + ")").c_str());
                            kill(pid, 9);
                            waitpid(pid, nullptr, 0);
                            return 1;
                        }
                    }
                }

                kill(pid, 9);
                waitpid(pid, nullptr, 0);
            }
        }

        {
            int rv = unshare(CLONE_NEWPID);

            if (rv == -1) {
                perror("unshare(newpid)");
                return 1;
            }
        }

        for (const auto& it : nsMap) {
            if (!(supportedFlags & it.first)) {
                continue;
            }

            auto path = nsDir / it.second;
            int fh = open(path.c_str(), O_RDONLY);

            if (fh == -1) {
                perror(("open(" + path.string() + ")").c_str());
                return 1;
            }

            int rv = setns(fh, it.first);

            if (rv == -1) {
                perror(("setns(" + it.second + ")").c_str());
                close(fh);
                return 1;
            }

            close(fh);
        }
    }

    {
        for (const std::string& dir : {
            "bin",
            "lib",
            "lib64",
            "sbin",
            "usr"
        }) {
            std::filesystem::path source("/" + dir);

            if (!std::filesystem::exists(source)) {
                continue;
            }

            auto dest = rootDir / dir;
            std::filesystem::create_directory(dest);

            if (!std::filesystem::is_empty(dest)) {
                continue;
            }

            int rv = mount(source.c_str(), dest.c_str(), "none", MS_BIND|MS_RDONLY, nullptr);

            if (rv == -1) {
                perror(("mount(" + source.string() + ")").c_str());
                return 1;
            }

            rv = mount("none", dest.c_str(), nullptr, MS_REMOUNT|MS_BIND|MS_RDONLY, nullptr);

            if (rv == -1) {
                perror(("ro-remount(" + source.string() + ")").c_str());
                return 1;
            }
        }
    }

    {
        int rv = chroot(rootDir.c_str());

        if (rv == -1) {
            perror(("chroot(" + rootDir.string() + ")").c_str());
            return 1;
        }
    }

    {
        int rv = chdir("/");

        if (rv == -1) {
            perror("chdir(/)");
            return 1;
        }
    }

    int pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;

    } else if (pid == 0) {
        {
            int rv = setuid(0);

            if (rv == -1) {
                perror("setuid");
                return 1;
            }

            rv = setgid(0);

            if (rv == -1) {
                perror("setgid");
                return 1;
            }
        }

        {
            int rv = unshare(CLONE_NEWNS);

            if (rv == -1) {
                perror("unshare(newns)");
                return 1;
            }
        }

        {
            static const std::vector<std::tuple<std::string, std::string, std::string, int>> specialFses {
                {"sysfs", "sys", "/sys", 0},
                {"proc", "proc", "/proc", MS_REC},
                {"devtmpfs", "udev", "/dev", 0}
            };

            for (const auto& [fstype, source, dest, flags] : specialFses) {
                std::filesystem::create_directory(dest);

                if (IsMountPoint(dest)) {
                    continue;
                }

                int rv = mount(source.c_str(), dest.c_str(), fstype.c_str(), flags, nullptr);

                if (rv == -1) {
                    perror(("mount(" + dest + ")").c_str());
                    return 1;
                }
            }
        }

        execvp(argv[3], &argv[3]);
        perror("execvp");
        return 1;

    } else {
        while (true) {
            int status;
            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);

            } else if (WIFSIGNALED(status)) {
                return 1;

            } else {
                sleep(1);
            }
        }
    }
}
