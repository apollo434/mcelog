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
