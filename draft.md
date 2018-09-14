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
