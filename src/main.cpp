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
#include <ac-common/utils/string.hpp>
#include <sys/syscall.h>
#include <unordered_set>
#include <fstream>

#ifdef RELEASE_FILESYSTEM
#include <filesystem>
#else
#include <experimental/filesystem>

namespace std {
    namespace filesystem = std::experimental::filesystem;
}
#endif

#define STDERR(impl, errmsg) { \
    if ((impl) == -1) { \
        PError(errmsg); \
        exit(1); \
    } \
}

static inline void PError(const char* msg) {
    perror(msg);
}

static inline void PError(const std::string& msg) {
    PError(msg.c_str());
}

static inline void PError(const std::filesystem::path& msg) {
    PError(msg.c_str());
}

static inline dev_t GetDeviceID(const std::string& path) {
    struct stat out;
    STDERR(
        stat(path.c_str(), &out),
        "stat(" + path + ")"
    );

    return out.st_dev;
}

static inline std::unordered_set<std::string> GetMounts() {
    std::unordered_set<std::string> out;
    std::ifstream file("/proc/self/mounts");
    std::string line;

    while (std::getline(file, line)) {
        auto&& parts = NAC::NStringUtils::Split(line, ' ');

        if (parts.size() > 1) {
            out.insert((std::string)parts.at(1));
        }
    }

    return out;
}

static inline bool IsMountPoint(const std::filesystem::path& path, const std::unordered_set<std::string>& mounts) {
    if (!std::filesystem::exists(path)) {
        return false;
    }

    if (GetDeviceID(path.string()) != GetDeviceID(path.parent_path().string())) {
        return true;
    }

    return mounts.count(path.string()) > 0;
}

static inline void SeedFile(const std::filesystem::path& path, const std::string& data) {
    if (!std::filesystem::exists(path)) {
        NAC::TFile file(path.string(), NAC::TFile::ACCESS_CREATEX);
        file.Append(data);
    }
}

static inline bool SetFileContent(const std::filesystem::path& path, const std::string& content) {
    NAC::TFile file(path.string(), NAC::TFile::ACCESS_CREATE);
    file.Append(content);
    return (bool)file;
}

static inline void MountSpecial() {
    static const std::unordered_set<std::string> emptyMounts;
    static const std::vector<std::tuple<std::string, std::string, std::string>> specialFses {
        {"sysfs", "sys", "/sys"},
        {"proc", "proc", "/proc"},
        {"devtmpfs", "udev", "/dev"}
    };

    for (const auto& [fstype, source, dest] : specialFses) {
        std::filesystem::create_directory(dest);

        if (IsMountPoint(dest, emptyMounts)) {
            continue;
        }

        int rv = mount(source.c_str(), dest.c_str(), fstype.c_str(), MS_REC|MS_NOSUID|MS_NOEXEC, nullptr);

        if (rv == -1) {
            PError("mount(" + dest + ")");
        }
    }
}

int WatcherPid_;
int ChildPid_;

void SignalForward(int sig) {
    if (ChildPid_ > 0) {
        kill(ChildPid_, sig);
    }
}

void SignalExit(int sig) {
    if (ChildPid_ > 0) {
        kill(ChildPid_, sig);

    } else {
        exit(1);
    }
}

int main(int argc, char** argv) {
    ChildPid_ = 0;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    for (const auto sig : {
        SIGHUP,
        SIGINT,
        SIGQUIT,
        SIGABRT,
        SIGTERM
    }) {
        signal(sig, SignalExit);
    }

    for (const auto sig : {
        SIGUSR1,
        SIGUSR2,
        SIGWINCH
    }) {
        signal(sig, SignalForward);
    }

    const char* runId("\0");
    const char* pathToWorkdir("\0");
    std::vector<char*> binaryAndArgs;
    size_t memoryLimit(0);
    size_t cpuMax(0);
    size_t cpuMaxPeriod(0);
    uid_t newUid(65534);
    gid_t newGid(65534);
    bool defaultMounts(true);
    bool haveCPUMax(false);
    bool haveCPUMaxPeriod(false);
    bool haveMemoryLimit(false);
    bool tryCGroup2(true);
    bool tryCGroup1(true);
    unsigned int killTimeout(3);
    bool tryUserNs(true);

    auto mounts = GetMounts();

    {
        size_t posNum(0);

        for (int i = 1; i < argc; ++i) {
            if (posNum > 1) {
                binaryAndArgs.push_back(argv[i]);
                continue;
            }

            if (strcmp("--mem-max", argv[i]) == 0) {
                ++i;
                NAC::NStringUtils::FromString(strlen(argv[i]), argv[i], memoryLimit);
                haveMemoryLimit = true;

            } else if (strcmp("--cpu-max", argv[i]) == 0) {
                ++i;
                NAC::NStringUtils::FromString(strlen(argv[i]), argv[i], cpuMax);
                haveCPUMax = true;

            } else if (strcmp("--cpu-max-period", argv[i]) == 0) {
                ++i;
                NAC::NStringUtils::FromString(strlen(argv[i]), argv[i], cpuMaxPeriod);
                haveCPUMaxPeriod = true;

            } else if (strcmp("--root", argv[i]) == 0) {
                newUid = 0;
                newGid = 0;

            } else if (strcmp("--uid", argv[i]) == 0) {
                ++i;
                NAC::NStringUtils::FromString(strlen(argv[i]), argv[i], newUid);

            } else if (strcmp("--gid", argv[i]) == 0) {
                ++i;
                NAC::NStringUtils::FromString(strlen(argv[i]), argv[i], newGid);

            } else if (strcmp("--no-default-mounts", argv[i]) == 0) {
                defaultMounts = false;

            } else if (strcmp("--no-cgroup2", argv[i]) == 0) {
                tryCGroup2 = false;

            } else if (strcmp("--no-cgroup1", argv[i]) == 0) {
                tryCGroup1 = false;

            } else if (strcmp("--kill-timeout", argv[i]) == 0) {
                ++i;
                NAC::NStringUtils::FromString(strlen(argv[i]), argv[i], killTimeout);

            } else if (strcmp("--no-user-ns", argv[i]) == 0) {
                tryUserNs = false;

            } else {
                switch (posNum) {
                    case 0: {
                        runId = argv[i];
                        ++posNum;
                        break;
                    }
                    case 1: {
                        pathToWorkdir = argv[i];
                        ++posNum;
                        break;
                    }
                    default:
                        return 1;
                }
            }
        }
    }

    if (haveCPUMaxPeriod && !haveCPUMax) {
        std::cerr << "--cpu-max-period should not be used without --cpu-max" << std::endl;
        return 1;
    }

    if (haveCPUMaxPeriod && (cpuMaxPeriod == 0)) {
        std::cerr << "--cpu-max-period should be greater than 0" << std::endl;
        return 1;
    }

    if (
        (strlen(runId) == 0)
        || (strlen(pathToWorkdir) == 0)
        || binaryAndArgs.empty()
    ) {
        std::cerr
            << "USAGE:\n\t" << argv[0] << " [--mem-max 1073741824] [--cpu-max 10000] [--cpu-max-period 100000] [--root] [--uid 0] [--gid 0] [--no-default-mounts] [--no-cgroup2] [--no-cgroup1] [--kill-timeout 3] [--no-user-ns] id /path/to/workdir /path/to/binary [binary args]\n"
            << "\n"
            << "REQUIRED PARAMETERS:\n"
            << "\tid - Unique id for running command; will be used as cgroup name\n"
            << "\t/path/to/workdir - Path to container directory\n"
            << "\t/path/to/binary - Path to binary that should be run within container\n"
            << "\n"
            << "OPTIONAL PARAMETERS:\n"
            << "\t--mem-max - Hard limit for memory, in bytes; \"0\" means \"unlimited\"\n"
            << "\t--cpu-max - How much CPU time could be consumed in each period; \"0\" means \"unlimited\"\n"
            << "\t--cpu-max-period - Duration of CPU usage period\n"
            << "\t--root - Keep running as root\n"
            << "\t--uid - Run as user with that id (setuid)\n"
            << "\t--gid - Run with a group of that id (setgid)\n"
            << "\t--no-default-mounts - Do not attempt to mount default host directories such as /bin and /lib into chroot\n"
            << "\t--no-cgroup2 - Do not try to use cgroup v2\n"
            << "\t--no-cgroup1 - Do not try to use cgroup v1\n"
            << "\t--kill-timeout - Seconds to wait before sending SIGKILL to child processes after controlling process disappeared\n"
            << "\t--no-user-ns - Do not create new user namespace\n"
            << std::endl
        ;

        return 1;
    }

    binaryAndArgs.push_back(nullptr);

    std::filesystem::path workdir(std::filesystem::absolute(pathToWorkdir));
    std::filesystem::create_directories(workdir);

    STDERR(
        chdir(pathToWorkdir),
        std::string("chdir(") + pathToWorkdir + ")"
    );

    {
        std::filesystem::path cgroupDir(workdir / "cgroup");
        std::filesystem::create_directory(cgroupDir);

        static const std::string cgroupVersionFileName(".cgver");
        static const std::filesystem::path defaultCGroupV1Path("/sys/fs/cgroup");

        if (!IsMountPoint(cgroupDir, mounts)) {
            int rv = -1;

            if (tryCGroup2) {
                rv = mount("none", cgroupDir.c_str(), "cgroup2", 0, nullptr);

            } else {
                errno = ENODEV;
            }

            if (rv == 0) {
                SetFileContent(cgroupVersionFileName, "2");

            } else if ((errno == ENODEV) && tryCGroup1) {
                if (!IsMountPoint(defaultCGroupV1Path, mounts)) {
                    std::filesystem::create_directories(defaultCGroupV1Path);
                    STDERR(
                        mount("cgroup_root", defaultCGroupV1Path.c_str(), "tmpfs", 0, nullptr),
                        "mount(cgroup)"
                    );
                }

                STDERR(
                    mount(defaultCGroupV1Path.c_str(), cgroupDir.c_str(), "none", MS_BIND, nullptr),
                    "mount(bind cgroup)"
                );

                SetFileContent(cgroupVersionFileName, "1");

            } else {
                PError("mount(cgroup2)");
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
                std::filesystem::path path(defaultCGroupV1Path / controller);

                if (!IsMountPoint(path, mounts)) {
                    std::filesystem::create_directory(path);
                    STDERR(
                        mount("cgroup", path.c_str(), "cgroup", 0, controller.c_str()),
                        "mount(cgroup/" + controller + ")"
                    );
                }

                path /= runId;
                std::filesystem::create_directory(path);

                if ((controller == "memory") && haveMemoryLimit) {
                    if (!SetFileContent(path / "memory.limit_in_bytes", (
                            (memoryLimit == 0)
                                ? std::string("-1")
                                : std::to_string(memoryLimit)
                    ))) {
                        std::cerr << "Failed to set memory limit" << std::endl;
                        return 1;
                    }
                }

                if ((controller == "cpu") && haveCPUMax) {
                    if (!SetFileContent(path / "cpu.cfs_quota_us", (
                            (cpuMax == 0)
                                ? std::string("-1")
                                : std::to_string(cpuMax)
                    ))) {
                        std::cerr << "Failed to set CPU limit" << std::endl;
                        return 1;
                    }

                    if (haveCPUMaxPeriod) {
                        if (!SetFileContent(path / "cpu.cfs_period_us", std::to_string(cpuMaxPeriod))) {
                            std::cerr << "Failed to set CPU period duration" << std::endl;
                            return 1;
                        }
                    }
                }

                if (!SetFileContent(path / "cgroup.procs", pidStr)) {
                    std::cerr << "Failed to add process to cgroup" << std::endl;
                    return 1;
                }
            }

        } else if (cgroupVersionFile[0] == '2') {
            auto path = cgroupDir / runId;
            std::filesystem::create_directory(path);

            if (!SetFileContent(path / "cgroup.subtree_control", "+cpu +memory +io +pids")) {
                std::cerr << "Failed to setup cgroup2" << std::endl;
                return 1;
            }

            if (haveMemoryLimit) {
                if (!SetFileContent(path / "memory.max", (
                        (memoryLimit == 0)
                            ? std::string("max")
                            : std::to_string(memoryLimit)
                ))) {
                    std::cerr << "Failed to set memory limit" << std::endl;
                    return 1;
                }
            }

            if (haveCPUMax) {
                std::string value;

                if (cpuMax == 0) {
                    value = "max";

                } else {
                    value = std::to_string(cpuMax);
                }

                if (haveCPUMaxPeriod) {
                    value += " " + std::to_string(cpuMaxPeriod);
                }

                if (!SetFileContent(path / "cpu.max", value)) {
                    std::cerr << "Failed to set CPU limit" << std::endl;
                    return 1;
                }
            }

            if (!SetFileContent(path / "cgroup.procs", pidStr)) {
                std::cerr << "Failed to add process to cgroup2" << std::endl;
                return 1;
            }

        } else {
            std::cerr << "Invalid cgroup version" << std::endl;
            return 1;
        }
    }

    int watcherFds[2];
    STDERR(pipe(watcherFds), "pipe");

    WatcherPid_ = fork();

    if (WatcherPid_ < 0) {
        PError("fork");
        return 1;

    } else if (WatcherPid_ == 0) {
        close(watcherFds[1]);
        STDERR(setsid(), "setsid");
        uint64_t childPid;
        size_t offset(0);

        while (offset < sizeof(childPid)) {
            int rv = read(watcherFds[0], ((char*)&childPid) + offset, sizeof(childPid) - offset);

            if (rv > 0) {
                offset += (size_t)read;

            } else {
                if (rv < 0) {
                    if ((errno == EINTR) || (errno == ETIMEDOUT)) {
                        continue;
                    }

                    PError("read");
                }

                exit(1);
            }
        }

        while (true) {
            char buf;
            int rv = read(watcherFds[0], &buf, 1);

            if ((rv < 0) && ((errno == EINTR) || (errno == ETIMEDOUT))) {
                continue;
            }

            while (killTimeout > 0) {
                killTimeout = sleep(killTimeout);
            }

            kill(-1 * (int)childPid, SIGKILL);
            break;
        }

        exit(0);
    }

    STDERR(std::atexit([](){
        kill(WatcherPid_, SIGKILL);

    }), "atexit");

    close(watcherFds[0]);

    std::string uidMap;
    std::string gidMap;

    const std::vector<std::pair<std::string, std::string*>> userNsCfg {
        {"uid_map", &uidMap},
        {"gid_map", &gidMap}
    };

    auto loadUserNsData = [&userNsCfg, &tryUserNs](const std::string& source = "self"){
        if (!tryUserNs) {
            return;
        }

        std::string line;
        std::string strippedLine;

        for (auto&& [mapPath, out] : userNsCfg) {
            std::ifstream file("/proc/" + source + "/" + mapPath);

            while (std::getline(file, line)) {
                NAC::NStringUtils::Strip(line, strippedLine, 3, " \t\r");
                (*out) += strippedLine + "\n";
            }
        }
    };

    auto saveUserNsData = [&userNsCfg, &tryUserNs](const std::string& source){
        if (!tryUserNs) {
            return;
        }

        for (const auto& [mapPath, data] : userNsCfg) {
            if (data->empty()) {
                continue;
            }

            if (!SetFileContent(std::filesystem::path("/proc/" + source + "/" + mapPath), *data)) {
                std::cerr << "Failed to write " << mapPath << std::endl;
                exit(1);
            }
        }
    };

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

            if (!IsMountPoint(path, mounts)) {
                flags |= it.first;

                {
                    NAC::TFile file(path.string(), NAC::TFile::ACCESS_CREATE);
                }

                // if (it.first == CLONE_NEWUSER) {
                //     loadUserNsData();
                // }
            }
        }

        if (flags > 0) {
            int fds[2];
            STDERR(pipe(fds), "pipe");

            int pid = fork();

            if (pid < 0) {
                PError("fork");
                return 1;

            } else if (pid == 0) {
                close(fds[0]);

                STDERR(unshare(flags), "unshare");
                STDERR(write(fds[1], "1", 1), "write");

                unsigned int toSleep(60);

                while (toSleep > 0) {
                    toSleep = sleep(toSleep);
                }

                exit(0);

            } else {
                close(fds[1]);

                char buf;
                int rv = read(fds[0], &buf, 1);

                if (rv != 1) {
                    if (rv == -1) {
                        PError("read");
                    }

                    kill(pid, SIGKILL);
                    waitpid(pid, nullptr, 0);
                    return 1;
                }

                close(fds[0]);

                // if (flags & CLONE_NEWUSER) {
                //     saveUserNsData(std::to_string(pid));
                // }

                const std::filesystem::path childNs("/proc/" + std::to_string(pid) + "/ns");

                for (const auto& it : nsMap) {
                    if (flags & it.first) {
                        int rv = mount((childNs / it.second).c_str(), (nsDir / it.second).c_str(), "none", MS_BIND, nullptr);

                        if (rv == -1) {
                            PError("mount(bind namespace " + it.second + ")");
                            kill(pid, SIGKILL);
                            waitpid(pid, nullptr, 0);
                            return 1;
                        }
                    }
                }

                kill(pid, SIGKILL);
                waitpid(pid, nullptr, 0);
            }
        }

        STDERR(unshare(CLONE_NEWPID), "unshare(newpid)");

        for (const auto& it : nsMap) {
            if (!(supportedFlags & it.first)) {
                continue;
            }

            auto path = nsDir / it.second;
            int fh = open(path.c_str(), O_RDONLY);

            if (fh == -1) {
                PError("open(" + path.string() + ")");
                return 1;
            }

            STDERR(setns(fh, it.first), "setns(" + it.second + ")");

            close(fh);
        }
    }

    // MountSpecial();
    //
    // mounts.merge(GetMounts());

    std::filesystem::path rootDir(workdir / "root");
    std::filesystem::create_directories(rootDir);

    if (!IsMountPoint(rootDir, mounts)) {
        STDERR(
            mount(rootDir.c_str(), rootDir.c_str(), "none", MS_BIND|MS_PRIVATE, nullptr),
            "mount(bind root)"
        );
    }

    STDERR(
        mount("none", rootDir.c_str(), nullptr, MS_REMOUNT|MS_BIND|MS_PRIVATE, nullptr),
        "private-remount(" + rootDir.string() + ")"
    );

    if (defaultMounts) {
        {
            auto etcDir = rootDir / "etc";
            std::filesystem::create_directory(etcDir);

            SeedFile(etcDir / "shadow", "root:*:16176:0:99999:7:::\nnobody:*:15828:0:99999:7:::\n");
            SeedFile(etcDir / "passwd", "root:x:0:0:root:/:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");
            SeedFile(etcDir / "group", "root:x:0:\nnobody:x:65534:\n");
        }

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

            if (IsMountPoint(dest, mounts)) {
                continue;
            }

            STDERR(
                mount(source.c_str(), dest.c_str(), "none", MS_BIND|MS_RDONLY, nullptr),
                "mount(" + source.string() + ")"
            );

            STDERR(
                mount("none", dest.c_str(), nullptr, MS_REMOUNT|MS_BIND|MS_RDONLY, nullptr),
                "ro-remount(" + source.string() + ")"
            );
        }
    }

    STDERR(chdir(rootDir.c_str()), "chdir(" + rootDir.string() + ")");

    uidMap = "";
    gidMap = "";

    loadUserNsData();

    int parentToChildFds[2], childToParentFds[2];
    STDERR(pipe(parentToChildFds), "pipe");
    STDERR(pipe(childToParentFds), "pipe");

    ChildPid_ = fork();

    if (ChildPid_ < 0) {
        PError("fork");
        return 1;

    } else if (ChildPid_ == 0) {
        close(watcherFds[1]);
        close(parentToChildFds[1]);
        close(childToParentFds[0]);

        STDERR(setpgid(0, 0), "setpgid");

        signal(SIGTTOU, SIG_IGN);
        STDERR(tcsetpgrp(STDIN_FILENO, getpid()), "tcsetpgrp");
        signal(SIGTTOU, SIG_DFL);

        STDERR(unshare(CLONE_NEWNS), "unshare(newns)");
        STDERR(syscall(SYS_pivot_root, ".", "."), "pivot_root");
        STDERR(umount2(".", MNT_DETACH), "umount2");
        STDERR(chroot("."), "chroot");

        MountSpecial();

        if (tryUserNs) {
            {
                char req('1');
                int rv = unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWCGROUP);

                if (rv == -1) {
                    const auto e = errno;
                    PError("unshare(newuser)");

                    if (e == EPERM) {
                        req = '0';

                    } else {
                        exit(1);
                    }
                }

                STDERR(write(childToParentFds[1], &req, 1), "write");
            }

            {
                char buf;
                int rv = read(parentToChildFds[0], &buf, 1);

                if (rv != 1) {
                    if (rv < 0) {
                        PError("read");
                    }

                    exit(1);
                }
            }
        }

        close(parentToChildFds[0]);
        close(childToParentFds[1]);

        STDERR(setgid(newGid), "setgid");
        STDERR(setuid(newUid), "setuid");

        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        execvp(binaryAndArgs.front(), binaryAndArgs.data());
        PError("execvp");
        exit(1);

    } else {
        close(parentToChildFds[0]);
        close(childToParentFds[1]);

        if (tryUserNs) {
            {
                char buf;
                int rv = read(childToParentFds[0], &buf, 1);

                if (rv != 1) {
                    if (rv < 0) {
                        PError("read");
                    }

                    exit(1);
                }

                if (buf == '1') {
                    saveUserNsData(std::to_string(ChildPid_));
                }
            }

            STDERR(write(parentToChildFds[1], "1", 1), "write");
        }

        close(parentToChildFds[1]);
        close(childToParentFds[0]);

        {
            size_t offset(0);
            uint64_t out(ChildPid_);

            while (offset < sizeof(out)) {
                int rv = write(watcherFds[1], ((char*)&out) + offset, sizeof(out) - offset);

                if (rv > 0) {
                    offset += (size_t)rv;

                } else {
                    if (rv < 0) {
                        if ((errno == EINTR) || (errno == ETIMEDOUT)) {
                            continue;
                        }

                        PError("write");
                    }

                    break;
                }
            }
        }

        while (true) {
            int status;
            STDERR(waitpid(ChildPid_, &status, 0), "waitpid");

            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);

            } else if (WIFSIGNALED(status)) {
                return 1;

            } else if (WIFSTOPPED(status) || WIFCONTINUED(status)) {
                sleep(1);

            } else {
                return 1;
            }
        }
    }
}
