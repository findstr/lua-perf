# lua-perf
[![cn](https://img.shields.io/badge/lang-cn-red.svg)](./README.md)

`lua-perf` is a performance profiling tool implemented based on `eBPF`, currently supporting `Lua 5.4`.

## Features

- Provides performance analysis for mixed `C` and `Lua` code, as well as pure `C` code.
- Uses stack sampling technique with minimal performance impact on the target process, making it suitable for production environments.
- Performs stack backtracing in the kernel space using `eh-frame`, eliminating the need for the target process to use the `-fno-omit-frame-pointer` option to preserve stack frame pointers.

## Requirements

To use `lua-perf`, make sure you meet the following requirements:

- The installed kernel version needs to be `5.17` or above.

## Generating Flame Graphs

To generate flame graphs, you need to use `lua-perf` in conjunction with the [FlameGraph](https://github.com/brendangregg/FlameGraph.git) tool. Here's how you can do it:

1. First, run the command `sudo lua-perf -p <pid> -f <HZ>` to sample the call stacks of the target process and generate a `perf.fold` file in the current directory. `<pid>` is the process ID of the target process, which can be a process inside a Docker container or a process on the host machine. `<HZ>` is the stack sampling frequency, with a default value of `1000` (1000 samples per second).

2. Next, convert the `perf.fold` file to a flame graph by running `./FlameGraph/flamegraph.pl perf.folded > perf.svg`.

3. Finally, you will find the generated flame graph, `perf.svg`, in the current directory.

Here's an example flame graph:

![perf](./examples/perf.svg)

## Logging
In the BPF program, bpf_trace_printk is used to print logs. If you suspect any abnormalities in the performance sampling, you can view the logs using the following commands:

```
sudo mount -t tracefs nodev /sys/kernel/tracing
sudo cat /sys/kernel/debug/tracing/trace_pipe
These commands will help you access the logs and view them. If you have any further questions, feel free to ask.
```

## Known Issues

`lua-perf` currently has the following known issues:

- Lack of support for `CFA_expression`, which may result in failed stack backtracing in extreme cases.
- When analyzing Lua stacks, the search for the `L` pointer is currently done by assuming it is stored in register `rbx`, which is correct for most cases with `GCC -O2`. However, depending on the optimization level of GCC, the value of `L` may be stored in a different register, leading to failures in Lua stack analysis.
- The analysis of `CFA` instructions does not handle `vdso` at the moment, causing stack backtracing failures for function calls in `vdso`.
- The process of merging C stacks and Lua stacks uses a heuristic strategy, which may have some flaws in extreme cases (none have been found so far).

## Future Work

The following tasks are planned for `lua-perf`:

- Support for `CFA_expression`
- Support for `vdso`
- Dynamic analysis of the `L` register
- Optimization of the merging strategy for C stacks and Lua stacks
- Support for more versions of Lua

