// Package sysinfo exposes the runtime capacities algorithms need to size
// parallelism and buffers: logical CPUs, GOMAXPROCS, and (where the platform
// exposes it) the memory limit and currently available memory. | Package sysinfo
// 暴露算法用来确定并行度与缓冲大小的运行时容量：逻辑 CPU 数、GOMAXPROCS，以及
// 平台可提供的内存上限与当前可用内存。
//
// Every value is read from the running process's environment; nothing is
// hard-coded. Memory queries are container-aware on Linux (cgroup v1/v2 plus
// /proc/meminfo) and return 0 when the platform cannot report a value, which
// lets callers fall back to a conservative default. | 所有取值都来自进程运行环境，
// 不写死任何数值。Linux 的内存查询感知 cgroup v1/v2 与 /proc/meminfo；平台无法
// 提供时返回 0，调用方据此回退到保守默认值。
//
// Typical usage | 典型用法：
//
//	workers := sysinfo.Parallelism()
//	limit := sysinfo.MemoryLimit()
package sysinfo
