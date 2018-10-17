#### MCELOG user space
```
/* Take decode ASCII code as example
 *
 * Only try to explain how to work for cache-threshold-trigger in meclog.conf
 *
 */
main()(mcelog.c)
  ascii_command()
    decodefatal(f) ---> f = fopen(inputfile, "r"); /* Maybe~~inputfile: /dev/mcelog */
      while (next > 0 || getdelim(&line, &linelen, '\n', inf) > 0) {
      >>>
        getdelim(&line, &linelen, '\n', inf) /* return "line" as string start */
      >>>
        dump_mce_final
          dump_mce
            decode_intel_mc
              decode_mci
                decode_mca
                  run_yellow_trigger
                    run_trigger(yellow_trigger, NULL, env, false);
                      execve(trigger, argv, env);
                      >>>
                        trigger == yellow_trigger;
                        yellow_trigger = config_string("cache", "cache-threshold-trigger");
                      >>>
                        env == environment variable, like "CPU","LEVEL" in cache-error-trigger
                      >>>

```

```

Regarding the enviroment variable, lilke "DIMM",etc, are transfer as the third param of run_trigger(bc->trigger, NULL, env), this is the call chain below:(dimm)
process_mcefd
  mce_filter
    mce_filter_intel
      intel_memory_error
        memory_error
          memdb_trigger
            run_trigger(bc->trigger, NULL, env);

Regarding the "Cache" Macro value, the call chain below:
main (mcelog.c)
  general_setup()
  process()
    dump_mce()
      decode_intel_mc()
        decode_mca()
          run_yellow_trigger()
            run_trigger(yellow_trigger, NULL, env)

Why there are not any enviroment when mcelog trigger call the script shell, I think there are something wrong when transfer the third param named "env".

```

```
Another way to trigger a error

dump_mce
  diskdb_resolve_addr
    new_error
      run_trigger(trigger, loc, val, max_error)

static void run_trigger(char *trigger, char *loc, unsigned long val,
                        unsigned long max)
{
        pid_t pid;

        Lprintf("Running error trigger because memory at %s had %lu errors\n",
                loc, max);
        close_dimm_db();
        if ((pid = fork()) == 0) {
                char valbuf[20], maxbuf[20];
                char *argv[] = {
                        trigger,
                        loc,
                        valbuf,
                        maxbuf,
                        NULL
                };  
                char *env[] = {
                        "PATH=/sbin:/usr/bin",
                        NULL
                };  
                sprintf(valbuf, "%lu", val);
                sprintf(maxbuf, "%lu", max);
                execve(trigger, argv, env);
                _exit(1);
        }
        int status;
        if (waitpid(pid, &status, 0) ||
            !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
                Eprintf("Cannot run error trigger %s for %s\n", trigger, loc);
        open_dimm_db(NULL);
}

Based on my investigation so far, if call this run_trigger() function, there is not any other environment macro **variable**.      

main
  parse_config
    config_options(options, combined_modifier)

combined_modifier
  diskdb_modifier

    int diskdb_modifier(int opt)
{
        char *end;

        switch (opt) {
        case O_DATABASE:
                dimm_db_fn = optarg;
                checkdmi();
                checkdimmdb();
                break;
        case O_ERROR_TRIGGER:
                checkdmi();
                open_dimm_db(dimm_db_fn);
                error_thresh = strtoul(optarg, &end, 0);
                if (end == optarg || *end != ',')
                        usage();
                error_trigger = end + 1;  
                break;
        default:
                return 0;
        }   
        return 1;
}

end + 1 is the error_trigger name




```

#### MCELOG kernel space
```

The real hardware mce issue routine:
(arch/x86/kernel/entry_32.S)
#ifdef CONFIG_X86_MCE
ENTRY(machine_check)
        RING0_INT_FRAME
        ASM_CLAC
        pushl_cfi $0
        pushl_cfi machine_check_vector
        jmp error_code
        CFI_ENDPROC
END(machine_check)
#endif

mcheck_cpu_init()
{
...
  machine_check_vector = do_machine_check
...
}

do_machine_check
  mce_report_event
    mce_notify_irq
      schedule_work(&mce_trigger_work)
    /*
     * Triggering the work queue here is just an insurance
     * policy in case the syscall exit notify handler
     * doesn't run soon enough or ends up running on the
     * wrong CPU (can happen when audit sleeps)
     */
    mce_schedule_work


static DECLARE_WORK(mce_trigger_work, mce_do_trigger)

mce_do_trigger
  call_usermodehelper(mce_helper, mce_helper_argv, NULL, UMH_WAIT_PROC)
    call_usermodehelper_setup
      INIT_WORK(&sub_info->work, __call_usermodehelper)
    call_usermodehelper_exec
      queue_work(khelper_wq, &sub_info->work)

__call_usermodehelper
  do_execve(getname_kernel(sub_info->path),
            (const char __user *const __user *)sub_info->argv,
            (const char __user *const __user *)sub_info->envp)

```

#### MCELOG kernel space, default action
```
do_machine_check
  mce_report_event
    mce_notify_irq
      schedule_work(&mce_trigger_work)
    /*
     * Triggering the work queue here is just an insurance
     * policy in case the syscall exit notify handler
     * doesn't run soon enough or ends up running on the
     * wrong CPU (can happen when audit sleeps)
     */
    mce_schedule_work

mce_schedule_work()
      schedule_work(&mce_work)

mcheck_init()
  INIT_WORK(&mce_work, mce_process_work)

mce_process_work
  mce_gen_pool_process
    atomic_notifier_call_chain(&x86_mce_decoder_chain, 0, mce)
      __atomic_notifier_call_chain
        notifier_call_chain
          ret = nb->notifier_call(nb, val, v) <===> mce_cpu_callback() or srao_decode_notifier()


mcheck_init_device()
   __register_hotcpu_notifier(&mce_cpu_notifier)

static struct notifier_block mce_cpu_notifier = {
    .notifier_call = mce_cpu_callback,
}

  /* Get notified when a cpu comes on/off. Be hotplug friendly. */
  static int
  mce_cpu_callback(struct notifier_block *nfb, unsigned long action, void *hcpu)
  {
          unsigned int cpu = (unsigned long)hcpu;
          struct timer_list *t = &per_cpu(mce_timer, cpu);

          switch (action & ~CPU_TASKS_FROZEN) {
          case CPU_ONLINE:
                  mce_device_create(cpu);
                  if (threshold_cpu_callback)
                          threshold_cpu_callback(action, cpu);
                  break;
          case CPU_DEAD:
                  if (threshold_cpu_callback)
                          threshold_cpu_callback(action, cpu);
                  mce_device_remove(cpu);
                  mce_intel_hcpu_update(cpu);

                  /* intentionally ignoring frozen here */
                  if (!(action & CPU_TASKS_FROZEN))
                          cmci_rediscover();
                  break;
          case CPU_DOWN_PREPARE:
                  smp_call_function_single(cpu, mce_disable_cpu, &action, 1);
                  del_timer_sync(t);
                  break;
          case CPU_DOWN_FAILED:
                  smp_call_function_single(cpu, mce_reenable_cpu, &action, 1);
                  mce_start_timer(cpu, t);
                  break;
          }

          return NOTIFY_OK;
  }    

  static int srao_decode_notifier(struct notifier_block *nb, unsigned long val,
                                  void *data)
  {
          struct mce *mce = (struct mce *)data;
          unsigned long pfn;

          if (!mce)
                  return NOTIFY_DONE;

          if (mce->usable_addr && (mce->severity == MCE_AO_SEVERITY)) {
                  pfn = mce->addr >> PAGE_SHIFT;
                  memory_failure(pfn, MCE_VECTOR, 0);
          }    

          return NOTIFY_OK;
  }
  static struct notifier_block mce_srao_nb = {
          .notifier_call  = srao_decode_notifier,
          .priority = INT_MAX,
  };

/*
 * Notifier chains are of four types:
 *
 *      Atomic notifier chains: Chain callbacks run in interrupt/atomic
 *              context. Callouts are not allowed to block.
 *      Blocking notifier chains: Chain callbacks run in process context.
 *              Callouts are allowed to block.
 *      Raw notifier chains: There are no restrictions on callbacks,
 *              registration, or unregistration.  All locking and protection
 *              must be provided by the caller.
 *      SRCU notifier chains: A variant of blocking notifier chains, with
 *              the same restrictions.
 *
 * atomic_notifier_chain_register() may be called from an atomic context,
 * but blocking_notifier_chain_register() and srcu_notifier_chain_register()
 * must be called from a process context.  Ditto for the corresponding
 * _unregister() routines.
 *
 * atomic_notifier_chain_unregister(), blocking_notifier_chain_unregister(),
 * and srcu_notifier_chain_unregister() _must not_ be called from within
 * the call chain.
 *
 * SRCU notifier chains are an alternative form of blocking notifier chains.
 * They use SRCU (Sleepable Read-Copy Update) instead of rw-semaphores for
 * protection of the chain links.  This means there is _very_ low overhead
 * in srcu_notifier_call_chain(): no cache bounces and no memory barriers.
 * As compensation, srcu_notifier_chain_unregister() is rather expensive.
 * SRCU notifier chains should be used when the chain will be called very
 * often but notifier_blocks will seldom be removed.  Also, SRCU notifier
 * chains are slightly more difficult to use because they require special
 * runtime initialization.
 */

typedef int (*notifier_fn_t)(struct notifier_block *nb,
                        unsigned long action, void *data);

struct notifier_block {
        notifier_fn_t notifier_call;
        struct notifier_block __rcu *next;
        int priority;
};

```
#### MCELOG mce Init
```
do_machine_check
  mce_gather_info
    mce_setup(m)

static __init int mcheck_init_device(void)
  {
          int err;
          int i = 0;

          if (!mce_available(&boot_cpu_data)) {
                  err = -EIO;
                  goto err_out;
          }

          if (!zalloc_cpumask_var(&mce_device_initialized, GFP_KERNEL)) {
                  err = -ENOMEM;
                  goto err_out;
          }

          mce_init_banks();

          err = subsys_system_register(&mce_subsys, NULL);
          if (err)
                  goto err_out_mem;

          cpu_notifier_register_begin();
          for_each_online_cpu(i) {
                  err = mce_device_create(i);
                  if (err) {
                          /*
                           * Register notifier anyway (and do not unreg it) so
                           * that we don't leave undeleted timers, see notifier
                           * callback above.
                           */
                          __register_hotcpu_notifier(&mce_cpu_notifier);
                          cpu_notifier_register_done();
                          goto err_device_create;
                  }
          }

          __register_hotcpu_notifier(&mce_cpu_notifier);
          cpu_notifier_register_done();

          register_syscore_ops(&mce_syscore_ops);

          /* register character device /dev/mcelog */
          err = misc_register(&mce_chrdev_device); ===================>register character device /dev/mcelog
>>>>
  static const struct file_operations mce_chrdev_ops = {
          .open                   = mce_chrdev_open,
          .release                = mce_chrdev_release,
          .read                   = mce_chrdev_read,
          .write                  = mce_chrdev_write,
          .poll                   = mce_chrdev_poll,
          .unlocked_ioctl         = mce_chrdev_ioctl,
          .llseek                 = no_llseek,
  };

  static struct miscdevice mce_chrdev_device = {
          MISC_MCELOG_MINOR,
          "mcelog",
          &mce_chrdev_ops,
  };

>>>>          
          if (err)
                  goto err_register;

          return 0;

  err_register:
          unregister_syscore_ops(&mce_syscore_ops);

  err_device_create:
          /*
           * We didn't keep track of which devices were created above, but
           * even if we had, the set of online cpus might have changed.
           * Play safe and remove for every possible cpu, since
           * mce_device_remove() will do the right thing.
           */
          for_each_possible_cpu(i)
                  mce_device_remove(i);

  err_out_mem:
          free_cpumask_var(mce_device_initialized);

  err_out:
          pr_err("Unable to init device /dev/mcelog (rc: %d)\n", err);

          return err;
  }
device_initcall_sync(mcheck_init_device);


The final record place:

  /*
   * Lockless MCE logging infrastructure.
   * This avoids deadlocks on printk locks without having to break locks. Also
   * separate MCEs from kernel messages to avoid bogus bug reports.
   */

  static struct mce_log mcelog = {
          .signature      = MCE_LOG_SIGNATURE,
          .len            = MCE_LOG_LEN,
          .recordlen      = sizeof(struct mce),
  };

  void mce_log(struct mce *mce)



```

#### MCELOG user space get the log from /dev/mcelog
```
  static const struct file_operations mce_chrdev_ops = {
          .open                   = mce_chrdev_open,
          .release                = mce_chrdev_release,
          .read                   = mce_chrdev_read,
          .write                  = mce_chrdev_write,
          .poll                   = mce_chrdev_poll,
          .unlocked_ioctl         = mce_chrdev_ioctl,
          .llseek                 = no_llseek,
  };

Corresponding to user space:

main()
{
  ....
fd = open(logfn, O_RDONLY);
ioctl(fd, MCE_GET_RECORD_LEN, &d.recordlen)
ioctl(fd, MCE_GET_LOG_LEN, &d.loglen)
  ....
}

process()
{
  ....
  len = read(fd, buf, recordlen * loglen)
  ....
}

```
