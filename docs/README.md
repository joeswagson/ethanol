# Process Module Logging

This project logs the module name for each process that meets the criteria:

- Process name ends with `sober`
- Access is granted (no denial errors)

The log output format is:

```
Process <pid> (<module_name>): <process_name>
```

Example:
```
Process 1234 (my_module): /home/joe/CLionProjects/ethanol/bin/sober_app
```