/*
 * DFRoot root agent.
 *
 * Runs as uid 0 (spawned by the dfroot kernel module through call_usermodehelper,
 * or manually via `bootstrap --agent`).  It watches a job directory for
 * requests coming from the DFRoot app and executes them:
 *
 *   op=flash      install / re-flash a custom .ko as a KernelSU-style module
 *   op=uninstall  remove an installed module
 *   op=list       list installed modules
 *   op=ping       health check
 *
 * Job files live in /data/user_de/0/df.root/jobs/<id>.job and hold simple
 * "key=value" lines.  The result is written to <id>.out using the same format.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef DF_DIR
#define DF_DIR       "/data/user_de/0/df.root"
#endif
#ifndef JOBS_DIR
#define JOBS_DIR     DF_DIR "/jobs"
#endif
#ifndef PID_FILE
#define PID_FILE     JOBS_DIR "/agent.pid"
#endif
#ifndef STATE_DIR
#define STATE_DIR    DF_DIR "/module_state"
#endif
#ifndef MODULES_DIR
#define MODULES_DIR  "/data/adb/modules"
#endif

#define MAX_KV       32
#define MAX_LINE     1024
#define MAX_MODS     256

typedef struct {
    char key[64];
    char val[512];
} kv_t;

typedef struct {
    kv_t kv[MAX_KV];
    int  n;
} job_t;

typedef struct {
    char id[64];
    char name[128];
    char version[64];
    char author[128];
    int  loaded;
} mod_t;

/* ------------------------------------------------------------------ utils */

static void unescape(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '\\' && r[1] == 'n') { *w++ = '\n'; r++; }
        else if (*r == '\\' && r[1] == '\\') { *w++ = '\\'; r++; }
        else *w++ = *r;
    }
    *w = '\0';
}

static int write_file(const char *path, const char *data, size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n <= 0) { close(fd); return -1; }
        off += (size_t)n;
    }
    close(fd);
    /* open() honours umask, force the mode explicitly */
    chmod(path, mode);
    return 0;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) { close(in); return -1; }
    char buf[16384];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0) { close(in); close(out); return -1; }
            off += w;
        }
    }
    close(in);
    close(out);
    chmod(dst, mode);
    return n < 0 ? -1 : 0;
}

static int ensure_dir(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0) { chmod(path, mode); return 0; }
    if (errno == EEXIST) return 0;
    return -1;
}

static int rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode)) return unlink(path);

    DIR *d = opendir(path);
    if (!d) return -1;
    struct dirent *e;
    char child[MAX_LINE];
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        rm_rf(child);
    }
    closedir(d);
    return rmdir(path);
}

static int valid_id(const char *id)
{
    if (!id || !*id) return 0;
    size_t len = strlen(id);
    if (len == 0 || len >= 64) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = id[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')
            continue;
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------- jobs */

static const char *job_get(const job_t *j, const char *key)
{
    for (int i = 0; i < j->n; i++)
        if (!strcmp(j->kv[i].key, key)) return j->kv[i].val;
    return NULL;
}

static int job_parse(const char *path, job_t *out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[16384];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    out->n = 0;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        if (out->n >= MAX_KV) break;
        kv_t *kv = &out->kv[out->n++];
        snprintf(kv->key, sizeof(kv->key), "%s", line);
        snprintf(kv->val, sizeof(kv->val), "%s", eq + 1);
        unescape(kv->val);
    }
    return 0;
}

/* --------------------------------------------------------------- modules */

#define MAX_LOADED 512

static int read_loaded(char names[][64], int max)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
    char line[MAX_LINE];
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < max) {
        char mod[64];
        if (sscanf(line, "%63s", mod) == 1)
            snprintf(names[n++], 64, "%s", mod);
    }
    fclose(f);
    return n;
}

/* The name the kernel knows a module by is the one inside the .ko, which is
 * not necessarily the module id.  Remember it so a re-flash can unload the
 * running instance before loading the new one. */
static void kernel_name_for(const char *id, char *out, size_t out_size)
{
    char path[MAX_LINE];
    snprintf(path, sizeof(path), "%s/%s.name", STATE_DIR, id);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(out, (int)out_size, f)) {
            size_t l = strlen(out);
            while (l && (out[l - 1] == '\n' || out[l - 1] == '\r')) out[--l] = '\0';
            fclose(f);
            if (out[0]) return;
        } else {
            fclose(f);
        }
    }
    snprintf(out, out_size, "%s", id);
}

static void save_kernel_name(const char *id, const char *name)
{
    if (!name || !*name) return;
    ensure_dir(STATE_DIR, 0777);
    char path[MAX_LINE];
    snprintf(path, sizeof(path), "%s/%s.name", STATE_DIR, id);
    write_file(path, name, strlen(name), 0644);
}

static int load_module(const char *path);

/* Load a .ko and figure out which name the kernel gave it. */
static int load_module_detect(const char *path, char *name_out, size_t name_size)
{
    char before[MAX_LOADED][64], after[MAX_LOADED][64];
    int nb = read_loaded(before, MAX_LOADED);
    int rc = load_module(path);
    if (rc != 0) return rc;
    int na = read_loaded(after, MAX_LOADED);
    name_out[0] = '\0';
    for (int i = 0; i < na; i++) {
        int seen = 0;
        for (int j = 0; j < nb; j++)
            if (!strcmp(after[i], before[j])) { seen = 1; break; }
        if (!seen) {
            snprintf(name_out, name_size, "%s", after[i]);
            break;
        }
    }
    return 0;
}

static int module_loaded(const char *name)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
    char line[MAX_LINE];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char mod[128];
        if (sscanf(line, "%127s", mod) == 1 && !strcmp(mod, name)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int unload_module(const char *name)
{
    long ret = syscall(__NR_delete_module, name, O_NONBLOCK);
    return ret == 0 ? 0 : -errno;
}

static int load_module(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    long ret = syscall(__NR_finit_module, fd, "", 0);
    int err = (ret == 0) ? 0 : -errno;
    close(fd);
    return err;
}

static void read_prop(const char *dir, mod_t *m)
{
    char path[MAX_LINE];
    snprintf(path, sizeof(path), "%s/module.prop", dir);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *val = eq + 1;
        size_t l = strlen(val);
        while (l && (val[l - 1] == '\n' || val[l - 1] == '\r')) val[--l] = '\0';
        if (!strcmp(line, "id") && !m->id[0]) snprintf(m->id, sizeof(m->id), "%s", val);
        else if (!strcmp(line, "name")) snprintf(m->name, sizeof(m->name), "%s", val);
        else if (!strcmp(line, "version")) snprintf(m->version, sizeof(m->version), "%s", val);
        else if (!strcmp(line, "author")) snprintf(m->author, sizeof(m->author), "%s", val);
    }
    fclose(f);
}

static int list_modules(mod_t *out, int max)
{
    DIR *d = opendir(MODULES_DIR);
    if (!d) return -1;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d)) && n < max) {
        if (e->d_name[0] == '.') continue;
        char dir[MAX_LINE];
        snprintf(dir, sizeof(dir), "%s/%s", MODULES_DIR, e->d_name);
        struct stat st;
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        mod_t *m = &out[n++];
        memset(m, 0, sizeof(*m));
        snprintf(m->id, sizeof(m->id), "%s", e->d_name);
        read_prop(dir, m);
        if (!m->name[0]) snprintf(m->name, sizeof(m->name), "%s", m->id);
        if (!m->version[0]) snprintf(m->version, sizeof(m->version), "unknown");
        char kn[64];
        kernel_name_for(m->id, kn, sizeof(kn));
        m->loaded = module_loaded(m->id) || (strcmp(kn, m->id) && module_loaded(kn));
    }
    closedir(d);
    return n;
}

/* Remove every *.ko that sits directly inside the module directory. */
static int purge_ko_files(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    char path[MAX_LINE];
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l < 3 || strcmp(e->d_name + l - 3, ".ko")) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        unlink(path);
    }
    closedir(d);
    return 0;
}

/* The kernel refuses to load a module whose file is not labelled
 * system_file.  Modules installed by the SU manager carry that label, so we
 * reuse the label of an already installed module (or fall back to the
 * standard one) for the .ko we write ourselves. */
static int get_selinux_context(const char *path, char *out, size_t out_size)
{
    ssize_t n = getxattr(path, "security.selinux", out, out_size - 1);
    if (n <= 0) return -1;
    out[n] = '\0';
    return 0;
}

static int set_selinux_context(const char *path, const char *ctx)
{
    if (setxattr(path, "security.selinux", ctx, strlen(ctx), 0) == 0) return 0;
    return -errno;
}

static void reference_context(char *out, size_t out_size)
{
    out[0] = '\0';
    DIR *d = opendir(MODULES_DIR);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char dir[MAX_LINE];
            snprintf(dir, sizeof(dir), "%s/%s", MODULES_DIR, e->d_name);
            DIR *sd = opendir(dir);
            if (!sd) continue;
            struct dirent *se;
            while ((se = readdir(sd))) {
                size_t l = strlen(se->d_name);
                if (l < 3 || strcmp(se->d_name + l - 3, ".ko")) continue;
                char p[MAX_LINE];
                snprintf(p, sizeof(p), "%s/%s", dir, se->d_name);
                char ctx[256];
                if (get_selinux_context(p, ctx, sizeof(ctx)) == 0 && ctx[0]) {
                    snprintf(out, out_size, "%s", ctx);
                    closedir(sd);
                    closedir(d);
                    return;
                }
            }
            closedir(sd);
        }
        closedir(d);
    }
    if (!out[0])
        snprintf(out, out_size, "u:object_r:system_file:s0");
}

static int flash_module(job_t *job, char *msg, size_t msg_size)
{
    const char *id = job_get(job, "id");
    const char *ko = job_get(job, "ko");
    const char *name = job_get(job, "name");
    const char *version = job_get(job, "version");
    const char *version_code = job_get(job, "versionCode");
    const char *author = job_get(job, "author");
    const char *description = job_get(job, "description");
    const char *load_now = job_get(job, "load_now");

    if (!valid_id(id)) {
        snprintf(msg, msg_size, "invalid module id");
        return -1;
    }
    if (!ko || !*ko) {
        snprintf(msg, msg_size, "no .ko file supplied");
        return -1;
    }
    struct stat st;
    if (stat(ko, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(msg, msg_size, "ko file not found: %s", ko);
        return -1;
    }

    if (!name || !*name) name = id;
    if (!version || !*version) version = "1.0";
    if (!version_code || !*version_code) version_code = "1";
    if (!author || !*author) author = "DFRoot";
    if (!description || !*description) description = "Flashed by DFRoot";

    ensure_dir(MODULES_DIR, 0755);

    char dir[MAX_LINE], ko_dst[MAX_LINE], prop_path[MAX_LINE], prop[1024];
    snprintf(dir, sizeof(dir), "%s/%s", MODULES_DIR, id);

    /* re-flash: unload the running module first so the new one can bind */
    char kernel_name[64];
    kernel_name_for(id, kernel_name, sizeof(kernel_name));
    if (module_loaded(id) || module_loaded(kernel_name)) {
        const char *victim = module_loaded(kernel_name) ? kernel_name : id;
        int rc = unload_module(victim);
        if (rc != 0)
            snprintf(msg, msg_size, "warning: could not unload '%s' (%s), continuing",
                     victim, strerror(-rc));
    }

    if (ensure_dir(dir, 0755) != 0) {
        snprintf(msg, msg_size, "cannot create module dir %s: %s", dir, strerror(errno));
        return -1;
    }

    purge_ko_files(dir);

    snprintf(ko_dst, sizeof(ko_dst), "%s/%s.ko", dir, id);
    if (copy_file(ko, ko_dst, 0644) != 0) {
        snprintf(msg, msg_size, "cannot write %s: %s", ko_dst, strerror(errno));
        return -1;
    }

    char ctx[256], note[256] = "";
    reference_context(ctx, sizeof(ctx));
    if (set_selinux_context(ko_dst, ctx) != 0)
        snprintf(note, sizeof(note), " (SELinux label not set: %s)", strerror(errno));

    int n = snprintf(prop, sizeof(prop),
                     "id=%s\n"
                     "name=%s\n"
                     "version=%s\n"
                     "versionCode=%s\n"
                     "author=%s\n"
                     "description=%s\n"
                     "updateJson=\n",
                     id, name, version, version_code, author, description);
    snprintf(prop_path, sizeof(prop_path), "%s/module.prop", dir);
    if (write_file(prop_path, prop, (size_t)n, 0644) != 0) {
        snprintf(msg, msg_size, "cannot write module.prop: %s", strerror(errno));
        return -1;
    }

    int want_load = (load_now && !strcmp(load_now, "1"));
    if (want_load) {
        char detected[64] = "";
        int rc = load_module_detect(ko_dst, detected, sizeof(detected));
        if (rc == 0 && detected[0])
            save_kernel_name(id, detected);
        if (rc != 0) {
            snprintf(msg, msg_size,
                     "module '%s' installed, but loading failed: %s (rc=%d)%s",
                     id, strerror(-rc), rc, note);
            return 1;
        }
        snprintf(msg, msg_size, "module '%s' installed and loaded%s", id, note);
        return 0;
    }

    snprintf(msg, msg_size, "module '%s' installed (loads on next boot)%s", id, note);
    return 0;
}

static int uninstall_module(job_t *job, char *msg, size_t msg_size)
{
    const char *id = job_get(job, "id");
    if (!valid_id(id)) {
        snprintf(msg, msg_size, "invalid module id");
        return -1;
    }
    char kernel_name[64];
    kernel_name_for(id, kernel_name, sizeof(kernel_name));
    if (module_loaded(id)) unload_module(id);
    if (module_loaded(kernel_name)) unload_module(kernel_name);
    char dir[MAX_LINE];
    snprintf(dir, sizeof(dir), "%s/%s", MODULES_DIR, id);
    if (rm_rf(dir) != 0) {
        snprintf(msg, msg_size, "cannot remove %s: %s", dir, strerror(errno));
        return -1;
    }
    snprintf(msg, msg_size, "module '%s' removed", id);
    return 0;
}

/* ------------------------------------------------------------------ loop */

static void handle_job(const char *job_path, const char *out_path)
{
    job_t job;
    char msg[1024] = "";

    if (job_parse(job_path, &job) != 0) {
        const char *err = "status=error\nmessage=cannot parse job\n";
        write_file(out_path, err, strlen(err), 0644);
        unlink(job_path);
        return;
    }

    const char *op = job_get(&job, "op");
    if (!op) op = "flash";

    int rc = 0;
    if (!strcmp(op, "ping")) {
        snprintf(msg, sizeof(msg), "agent alive (uid=%d)", (int)getuid());
    } else if (!strcmp(op, "flash")) {
        rc = flash_module(&job, msg, sizeof(msg));
    } else if (!strcmp(op, "uninstall")) {
        rc = uninstall_module(&job, msg, sizeof(msg));
    } else if (!strcmp(op, "list")) {
        mod_t mods[MAX_MODS];
        int n = list_modules(mods, MAX_MODS);
        char out[16384];
        size_t off = 0;
        off += (size_t)snprintf(out + off, sizeof(out) - off,
                                "status=ok\nmessage=%d modules\n", n);
        for (int i = 0; i < n && off + 512 < sizeof(out); i++) {
            off += (size_t)snprintf(out + off, sizeof(out) - off, "mod=%s|%s|%s|%s\n",
                                    mods[i].id, mods[i].name, mods[i].version,
                                    mods[i].loaded ? "loaded" : "idle");
        }
        write_file(out_path, out, off, 0644);
        unlink(job_path);
        return;
    } else {
        rc = -1;
        snprintf(msg, sizeof(msg), "unknown op: %s", op);
    }

    char out[2048];
    int n = snprintf(out, sizeof(out), "status=%s\nmessage=%s\n",
                     rc < 0 ? "error" : "ok", msg);
    write_file(out_path, out, (size_t)n, 0644);
    unlink(job_path);
}

static int find_job(char *out, size_t out_size)
{
    DIR *d = opendir(JOBS_DIR);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l < 5 || strcmp(e->d_name + l - 4, ".job")) continue;
        snprintf(out, out_size, "%s/%s", JOBS_DIR, e->d_name);
        found = 1;
        break;
    }
    closedir(d);
    return found;
}

void dfroot_agent_loop(void)
{
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    setsid();

    ensure_dir(JOBS_DIR, 0777);
    chmod(JOBS_DIR, 0777);

    char pid[32];
    int n = snprintf(pid, sizeof(pid), "%d\n", (int)getpid());
    write_file(PID_FILE, pid, (size_t)n, 0666);

    for (;;) {
        char job_path[MAX_LINE], out_path[MAX_LINE];
        if (find_job(job_path, sizeof(job_path))) {
            size_t l = strlen(job_path);
            snprintf(out_path, sizeof(out_path), "%.*s.out", (int)(l - 4), job_path);
            handle_job(job_path, out_path);
            continue;
        }
        usleep(300 * 1000);
    }
}
