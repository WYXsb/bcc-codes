
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);


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
BPF_HASH(birth, int, struct event , 10240);
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    int zero = 0;

    struct event event = {};
    struct event *e1 = NULL;

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.dfd = args->dfd;
    event.flags = args->flags;
    event.mode = args->mode;
    event.opentime = bpf_ktime_get_ns();
    birth.update(&event.pid,&event);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_close)
{   
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct event *event = NULL;
    event = birth.lookup(&pid);
    if(event != NULL)
    {
        //bpf_trace_printk("%s\\n",event->filename);
        event->lasttime = bpf_ktime_get_ns() - event->opentime;
        buffer.ringbuf_output(event, sizeof(struct event), 0);
    }
    return 0;
}

