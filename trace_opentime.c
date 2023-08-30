
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);
struct time {
    unsigned long long boottime;
};
BPF_ARRAY(time_array,struct time,10);

struct event {
    char filename[64];
    int dfd;
    int flags;
    int mode;
    int pid;
    int pname;
    u64 opentime;
    u64 lasttime;
};
// BPF_HASH(birth, int, struct event , 10240);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {

    struct event event = {};
    struct event *e1 = NULL;
    int index = 0;
    struct time *info  = NULL;
    info = time_array.lookup(&index);

    if(info != NULL)
    {
        event.opentime = bpf_ktime_get_ns();
        // if time > 15:39:53 ,then return 
        if(event.opentime / 1000000000+ info->boottime  > 1692862793)
            return 0;
    }
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.dfd = args->dfd;
    event.flags = args->flags;
    event.mode = args->mode;
    // birth.update(&event.pid,&event);
    buffer.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}