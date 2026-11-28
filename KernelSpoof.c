#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <kputils.h>

#define KS_NAME "KernelSpoof"
KPM_NAME(KS_NAME);
KPM_VERSION("0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FreeAsCrazy");
KPM_DESCRIPTION("通过 /proc/KernelSpoof 控制，直接修改 init_uts_ns 伪装内核 uname release/version");

#define KS_DEFAULT_SPOOF \
    "Linux localhost 4.19.157-perf-g8779875ad741 " \
    "#1 SMP PREEMPT Thu Mar 16 22:52:44 CST 2023 aarch64"

#define KS_LEN          64
#define KS_FIELD        (KS_LEN + 1)

#define KS_REL_OFF      (2 * KS_FIELD)
#define KS_VER_OFF      (3 * KS_FIELD)
#define KS_MACH_OFF     (4 * KS_FIELD)
#define KS_SCAN         1024
#define KS_PROC_CMD_MAX 1024
#define KS_PROC_OUT_MAX 4096
#define KS_READ_CHUNK   256
#define KS_STATUS_MAX   (KS_FIELD * 2 + 32)
#define KS_MODE_DEFAULT 0
#define KS_MODE_PRESET  1
#define KS_MODE_CUSTOM  2
#define KS_SPACE(c)     ((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n')

typedef long (*ks_proc_read_fn)(void *file, char __user *buf,
                                unsigned long count, loff_t *ppos);
typedef long (*ks_proc_write_fn)(void *file, const char __user *buf,
                                 unsigned long count, loff_t *ppos);
struct ks_file_operations {
    void *owner;
    void *llseek;
    ks_proc_read_fn read;
    ks_proc_write_fn write;
    void *tail[28];
};
_Static_assert(offsetof(struct ks_file_operations, read) == 16, "read offset");
_Static_assert(offsetof(struct ks_file_operations, write) == 24, "write offset");
_Static_assert(offsetof(struct ks_file_operations, tail) +
               9 * sizeof(void *) == 104, "open offset");
_Static_assert(sizeof(struct ks_file_operations) == 256, "fops size");

typedef void *(*ks_proc_create_fn)(const char *name, unsigned short mode,
                                   void *parent,
                                   const struct ks_file_operations *fops);
typedef void (*ks_remove_proc_entry_fn)(const char *name, void *parent);
typedef unsigned long (*ks_copy_from_user_fn)(void *to,
                                              const void __user *from,
                                              unsigned long n);

static char g_def_rel[KS_FIELD], g_def_ver[KS_FIELD];
static char *g_uts;
static int g_mode;
static ks_remove_proc_entry_fn g_proc_remove;
static void *g_proc_entry;
static ks_copy_from_user_fn g_copy_from_user;
static char g_status[KS_STATUS_MAX];
static char g_proc_out[KS_PROC_OUT_MAX];
static int g_proc_out_len, g_proc_out_pos;
static int g_cmd_busy;
static struct ks_file_operations ks_proc_fops;

typedef unsigned long (*ks_lock_fn)(void *lock);
typedef void (*ks_unlock_fn)(void *lock, unsigned long flags);
static ks_lock_fn g_lock_fn;
static ks_unlock_fn g_unlock_fn;
static u8 g_lock_word[128] __attribute__((aligned(64)));

typedef void (*ks_rwsem_fn)(void *sem);
typedef int (*ks_rwsem_trylock_fn)(void *sem);
static void *g_uts_sem;
static ks_rwsem_fn g_down_write, g_up_write;
static ks_rwsem_trylock_fn g_uts_trylock;

/* 获取自旋锁 */
static unsigned long ks_lock(void) { return g_lock_fn((void *)g_lock_word); }
/* 释放自旋锁 */
static void ks_unlock(unsigned long flags) { g_unlock_fn((void *)g_lock_word, flags); }
/* 获取 UTS 写锁 */
static int ks_uts_lock(int nonblock)
{
    if (!nonblock) {
        g_down_write(g_uts_sem);
        return 1;
    }
    return g_uts_trylock(g_uts_sem);
}
/* 释放 UTS 写锁 */
static void ks_uts_unlock(void) { g_up_write(g_uts_sem); }

/* 获取命令执行权 */
static int ks_cmd_try_begin(void)
{
    unsigned long flags = ks_lock();
    int ok = !g_cmd_busy;
    if (ok) g_cmd_busy = 1;
    ks_unlock(flags);
    return ok;
}

/* 释放命令执行权 */
static void ks_cmd_end(void)
{
    unsigned long flags = ks_lock();
    g_cmd_busy = 0;
    ks_unlock(flags);
}

/* 保存命令输出 */
static void ks_store_out(const char *s)
{
    unsigned long flags;
    int n = s ? (int)strnlen(s, KS_PROC_OUT_MAX) : 0;
    flags = ks_lock();
    if (n) memcpy(g_proc_out, s, n);
    g_proc_out_len = n;
    g_proc_out_pos = 0;
    ks_unlock(flags);
}

/* 匹配命令 */
static int ks_cmd(const char *args, const char *name)
{
    int n = (int)strlen(name);
    return !strncmp(args, name, n) && (!args[n] || KS_SPACE(args[n]));
}

/* 提取 set 参数 */
static const char *ks_set_arg(const char *args)
{
    if (!ks_cmd(args, "set"))
        return 0;
    args += 3;
    while (KS_SPACE(*args)) args++;
    return args;
}

/* 判断 release 格式 */
static int ks_is_release(const char *s, int n)
{
    int i = 0;
    while (i < n && s[i] >= '0' && s[i] <= '9') i++;
    return i && i + 1 < n && s[i] == '.' &&
           s[i + 1] >= '0' && s[i + 1] <= '9';
}

/* 判断 aarch64 */
static int ks_is_machine(const char *s, int n)
{
    return n == 7 && !strncmp(s, "aarch64", 7);
}

/* 检查可打印字符 */
static int ks_printable(const char *s, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (s[i] < 0x20 || s[i] > 0x7e) return 0;
    return 1;
}

/* 获取字段长度 */
static int ks_field_len(const char *p)
{
    int n = (int)strnlen(p, KS_FIELD);
    return n < KS_FIELD && ks_printable(p, n) ? n : -1;
}

/* 解析 uname -a */
static const char *ks_parse(const char *s, char *rel, char *ver)
{
    const char *tok[32];
    int tlen[32], n = 0, i, mach_i = -1, off;

    while (1) {
        while (KS_SPACE(*s)) s++;
        if (!*s) break;
        if (n >= (int)(sizeof(tok) / sizeof(tok[0])))
            return "error: too many fields\n";
        tok[n] = s;
        while (*s && !KS_SPACE(*s)) s++;
        tlen[n] = (int)(s - tok[n]);
        n++;
    }
    if (n < 5 || tlen[0] != 5 || strncmp(tok[0], "Linux", 5))
        return "error: not uname -a output\n";
    if (!ks_is_release(tok[2], tlen[2]))
        return "error: release not found\n";

    for (i = n - 1; i > 2; i--)
        if (ks_is_machine(tok[i], tlen[i])) { mach_i = i; break; }
    if (mach_i < 0)
        return "error: machine not found\n";

    while (mach_i - 1 > 2 && ks_is_machine(tok[mach_i - 1], tlen[mach_i - 1]))
        mach_i--;
    if (mach_i <= 3)
        return "error: version not found\n";
    if (tlen[2] > KS_LEN || !ks_printable(tok[2], tlen[2]))
        return "error: bad release\n";

    memcpy(rel, tok[2], tlen[2]);
    rel[tlen[2]] = '\0';
    off = 0;
    for (i = 3; i < mach_i; i++) {
        if (!ks_printable(tok[i], tlen[i])) return "error: bad version\n";
        if (i > 3) ver[off++] = ' ';
        if (off + tlen[i] > KS_LEN) return "error: version too long\n";
        memcpy(ver + off, tok[i], tlen[i]);
        off += tlen[i];
    }
    ver[off] = '\0';
    return 0;
}

/* 写入 UTS 字段 */
static void ks_write_field(int off, const char *value)
{
    memset(g_uts + off, 0, KS_FIELD);
    strscpy(g_uts + off, value, KS_FIELD);
}

/* 保存真实值 */
static const char *ks_save_defaults(void)
{
    if (ks_field_len(g_uts + KS_VER_OFF) <= 0)
        return "error: default version empty\n";
    strscpy(g_def_rel, g_uts + KS_REL_OFF, KS_FIELD);
    strscpy(g_def_ver, g_uts + KS_VER_OFF, KS_FIELD);
    return 0;
}

/* 查找 UTS 名称 */
static char *ks_find_uts(char *base)
{
    int i, len;

    for (i = 0; i + KS_MACH_OFF + KS_FIELD <= KS_SCAN; i++) {
        char *name = base + i;
        if (memcmp(name, "Linux", 5) || name[5]) continue;
        if (!ks_is_release(name + KS_REL_OFF,
                           ks_field_len(name + KS_REL_OFF))) continue;
        if (ks_field_len(name + KS_VER_OFF) < 0) continue;
        len = ks_field_len(name + KS_MACH_OFF);
        if (len <= 0 || !ks_is_machine(name + KS_MACH_OFF, len)) continue;
        return name;
    }
    return 0;
}

/* 恢复真实值 */
static void ks_restore(int nonblock, int *rc)
{
    unsigned long flags;

    if (!ks_uts_lock(nonblock)) {
        if (rc) *rc = -EBUSY;
        return;
    }
    flags = ks_lock();
    if (g_mode != KS_MODE_DEFAULT) {
        ks_write_field(KS_REL_OFF, g_def_rel);
        ks_write_field(KS_VER_OFF, g_def_ver);
        g_mode = KS_MODE_DEFAULT;
    }
    ks_unlock(flags);
    ks_uts_unlock();
    if (rc) *rc = 0;
}

/* 应用一条伪装 */
static const char *ks_apply_spoof(const char *line, int mode, int nonblock,
                                  int *rc)
{
    char rel[KS_FIELD], ver[KS_FIELD];
    const char *err = ks_parse(line, rel, ver);
    unsigned long flags;

    if (err) {
        if (rc) *rc = -EINVAL;
        return err;
    }
    if (!ks_uts_lock(nonblock)) {
        if (rc) *rc = -EBUSY;
        return 0;
    }
    flags = ks_lock();

    if (g_mode == KS_MODE_DEFAULT) {
        err = ks_save_defaults();
        if (err) {
            ks_unlock(flags);
            ks_uts_unlock();
            if (rc) *rc = -EINVAL;
            return err;
        }
    }
    ks_write_field(KS_REL_OFF, rel);
    ks_write_field(KS_VER_OFF, ver);
    g_mode = mode;
    ks_unlock(flags);
    ks_uts_unlock();
    if (rc) *rc = 0;
    return 0;
}

/* 应用预设伪装 */
static const char *ks_apply_preset(int nonblock, int *rc)
{
    return ks_apply_spoof(KS_DEFAULT_SPOOF, KS_MODE_PRESET, nonblock, rc);
}

/* 生成状态文本 */
static const char *ks_status_text(void)
{
    const char *prefix;
    unsigned long flags = ks_lock();
    int off, n;

    switch (g_mode) {
    case KS_MODE_PRESET: prefix = "预设伪装\n"; break;
    case KS_MODE_CUSTOM: prefix = "自定义伪装\n"; break;
    default: prefix = "真实\n"; break;
    }
    off = (int)strlen(prefix);
    memcpy(g_status, prefix, off);
    n = ks_field_len(g_uts + KS_REL_OFF);
    if (n > 0) {
        memcpy(g_status + off, g_uts + KS_REL_OFF, n);
        off += n;
    }
    g_status[off++] = '\n';
    n = ks_field_len(g_uts + KS_VER_OFF);
    if (n > 0) {
        memcpy(g_status + off, g_uts + KS_VER_OFF, n);
        off += n;
    }
    g_status[off++] = '\n';
    g_status[off] = '\0';
    ks_unlock(flags);
    return g_status;
}

/* 生成帮助文本 */
static const char *ks_help_text(void)
{
    return "KernelSpoof 命令：\n"
           "status              显示当前状态和 release/version\n"
           "set <uname -a>      自定义伪装\n"
           "preset              预设伪装\n"
           "rest                恢复真实值\n"
           "help                显示本帮助\n";
}

/* 执行命令 */
static const char *ks_exec(const char *args, int nonblock, int *rc)
{
    const char *p;

    if (rc) *rc = 0;
    if (!args) return 0;
    while (KS_SPACE(*args)) args++;
    if (!*args) return 0;
    if (ks_cmd(args, "help"))
        return ks_help_text();
    if (ks_cmd(args, "status"))
        return ks_status_text();
    if (ks_cmd(args, "rest")) {
        ks_restore(nonblock, rc);
        return 0;
    }
    if (ks_cmd(args, "preset"))
        return ks_apply_preset(nonblock, rc);
    p = ks_set_arg(args);
    if (p && *p)
        return ks_apply_spoof(p, KS_MODE_CUSTOM, nonblock, rc);
    return ks_help_text();
}

/* ctl0 控制回调 */
static long ks_ctl0(const char *args, char __user *out_msg, int outlen)
{
    const char *s;
    int len, rc;

    if (!args || !out_msg || outlen <= 0)
        return -EINVAL;
    if (!ks_cmd_try_begin())
        return -EBUSY;
    s = ks_exec(args, 1, &rc);
    if (!s) s = "";
    len = (int)strlen(s);
    if (len >= outlen) len = outlen - 1;
    if (compat_copy_to_user(out_msg, s, len + 1) != len + 1)
        rc = -EFAULT;
    ks_cmd_end();
    return rc;
}

/* procfs 读回调 */
static long ks_proc_read(void *file, char __user *buf, unsigned long count,
                         loff_t *ppos)
{
    char tmp[KS_READ_CHUNK];
    unsigned long flags;
    int n = 0;

    (void)file; (void)ppos;
    if (current_uid() != 0) return -EPERM;
    flags = ks_lock();
    if (g_proc_out_pos < g_proc_out_len) {
        n = g_proc_out_len - g_proc_out_pos;
        if ((unsigned long)n > count) n = (int)count;
        if ((unsigned long)n > KS_READ_CHUNK) n = KS_READ_CHUNK;
        memcpy(tmp, g_proc_out + g_proc_out_pos, n);
        g_proc_out_pos += n;
        if (g_proc_out_pos >= g_proc_out_len) {
            g_proc_out_len = 0;
            g_proc_out_pos = 0;
        }
    }
    ks_unlock(flags);
    if (n <= 0) return 0;
    return compat_copy_to_user(buf, tmp, n) == n ? n : -EFAULT;
}

/* procfs 写回调 */
static long ks_proc_write(void *file, const char __user *buf,
                          unsigned long count, loff_t *ppos)
{
    char cmd[KS_PROC_CMD_MAX + 1];
    unsigned long left;
    int len;

    (void)file; (void)ppos;
    if (current_uid() != 0) return -EPERM;
    if (!count) return 0;
    if (count > KS_PROC_CMD_MAX) return -EINVAL;

    left = g_copy_from_user(cmd, buf, count);
    if (left) return -EFAULT;
    cmd[count] = '\0';
    len = (int)strlen(cmd);
    while (len > 0 && KS_SPACE(cmd[len - 1])) cmd[--len] = '\0';
    if (!ks_cmd_try_begin()) return -EBUSY;
    ks_store_out(ks_exec(cmd, 0, 0));
    ks_cmd_end();
    return (long)count;
}

/* 创建 procfs 节点 */
static int ks_proc_init(void)
{
    ks_proc_create_fn create =
        (ks_proc_create_fn)kallsyms_lookup_name("proc_create");

    g_proc_remove = (ks_remove_proc_entry_fn)
        kallsyms_lookup_name("remove_proc_entry");
    if (!create || !g_proc_remove) {
        pr_err("KernelSpoof: procfs symbols missing\n");
        return -ENOSYS;
    }
    ks_proc_fops.read = ks_proc_read;
    ks_proc_fops.write = ks_proc_write;
    g_proc_entry = create(KS_NAME, 0600, 0, &ks_proc_fops);
    if (!g_proc_entry) {
        pr_err("KernelSpoof: create /proc/%s failed\n", KS_NAME);
        return -ENOMEM;
    }
    return 0;
}

/* 删除 procfs 节点 */
static void ks_proc_exit(void)
{
    if (g_proc_entry) {

        g_proc_remove(KS_NAME, 0);
        g_proc_entry = 0;
    }
}

/* KPM 初始化 */
static long ks_init(const char *args, const char *event, void *__user reserved)
{
    ks_lock_fn lf;
    ks_unlock_fn uf;
    ks_rwsem_fn dw, uw;
    ks_rwsem_trylock_fn tw;
    char *base;

    (void)args; (void)event; (void)reserved;
    if (!kallsyms_lookup_name) {
        pr_err("KernelSpoof: kallsyms_lookup_name missing\n");
        return -ENOSYS;
    }
    lf = (ks_lock_fn)kallsyms_lookup_name("_raw_spin_lock_irqsave");
    uf = (ks_unlock_fn)kallsyms_lookup_name("_raw_spin_unlock_irqrestore");
    if (!lf || !uf) {
        pr_err("KernelSpoof: spinlock symbols missing\n");
        return -ENOSYS;
    }
    g_copy_from_user = (ks_copy_from_user_fn)
        kallsyms_lookup_name("__arch_copy_from_user");
    if (!g_copy_from_user) {
        pr_err("KernelSpoof: copy_from_user symbol missing\n");
        return -ENOSYS;
    }
    g_uts_sem = (void *)kallsyms_lookup_name("uts_sem");
    dw = (ks_rwsem_fn)kallsyms_lookup_name("down_write");
    uw = (ks_rwsem_fn)kallsyms_lookup_name("up_write");
    tw = (ks_rwsem_trylock_fn)kallsyms_lookup_name("down_write_trylock");
    if (!g_uts_sem || !dw || !uw || !tw) {
        pr_err("KernelSpoof: uts_sem symbols missing\n");
        return -ENOSYS;
    }
    g_lock_fn = lf;
    g_unlock_fn = uf;
    g_down_write = dw;
    g_up_write = uw;
    g_uts_trylock = tw;

    base = (char *)kallsyms_lookup_name("init_uts_ns");
    if (!base) {
        pr_err("KernelSpoof: init_uts_ns not found\n");
        return -ENOSYS;
    }
    ks_uts_lock(0);
    g_uts = ks_find_uts(base);
    ks_uts_unlock();
    if (!g_uts) {
        pr_err("KernelSpoof: init_uts_ns.name not found\n");
        return -ENOSYS;
    }
    if (ks_apply_preset(0, 0)) {
        pr_err("KernelSpoof: default spoof failed\n");
        return -ENOSYS;
    }
    return ks_proc_init();
}

/* KPM 退出 */
static long ks_exit(void *__user reserved)
{
    (void)reserved;

    if (g_uts) {
        ks_proc_exit();
        ks_restore(0, 0);
    }
    return 0;
}

KPM_INIT(ks_init);
KPM_CTL0(ks_ctl0);
KPM_EXIT(ks_exit);
