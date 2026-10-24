// Package nodeid resolves a stable, deployment-unique node identity. | Package nodeid 解析稳定且
// 部署内唯一的节点身份。
//
// A node identity is not recomputed from hardware on every start. The first
// resolution derives a value from the best platform seed available, writes it to
// a durable identity file and from then on reads that file. This is what makes
// the identity survive reboots, operating-system upgrades, hardware replacement
// and virtual-machine or container migration: the identity travels with the
// disk, not with the motherboard. | 节点身份不在每次启动时重新从硬件计算。首次解析会从可用的
// 最佳平台种子推导一个值，写入持久身份文件，此后只读取该文件。正因如此，身份才能跨重启、系统
// 升级、硬件替换以及虚机/容器迁移保持不变：身份跟着磁盘走，而不是跟着主板走。
//
// Precedence: | 优先级：
//
//  1. an explicitly configured id (node.id / YD_NODE_ID); | 显式配置的 id（node.id / YD_NODE_ID）；
//  2. the persisted identity file (node.id_file); | 持久身份文件（node.id_file）；
//  3. a platform seed (machine-id, SMBIOS UUID, Windows MachineGuid,
//     IOPlatformUUID), persisted before it is returned; | 平台种子（machine-id、SMBIOS UUID、
//     Windows MachineGuid、IOPlatformUUID），返回前先持久化；
//  4. a random id that is persisted when possible. | 随机 id，尽可能持久化。
//
// Containers deserve special care: a container shares the host's SMBIOS and may
// inherit /etc/machine-id from its image, so host-derived seeds are skipped by
// default. A container identity is stable only when the identity file lives on a
// per-instance volume; otherwise it is unique but changes when the container is
// recreated. Set Options.AllowSharedSeed only for single-container hosts. |
// 容器需要特别处理：容器共享宿主机的 SMBIOS，且可能从镜像继承 /etc/machine-id，因此默认跳过
// 宿主相关的种子。只有身份文件位于每实例独立的卷上时，容器身份才稳定；否则它唯一，但容器重建后
// 会变化。仅在「一台主机只跑一个容器」时开启 Options.AllowSharedSeed。
//
// Cloned disks, VM snapshots and image layers can duplicate the identity file.
// Uniqueness therefore cannot be proven locally: configure Options.Claimer with a
// deployment-wide lease (for example Redis SET NX PX plus renewal) when replicas
// may be cloned. | 磁盘克隆、虚机快照与镜像层都可能复制身份文件，因此唯一性无法在本地证明：
// 当副本可能被克隆时，用部署级的租约（例如 Redis SET NX PX 加续期）实现 Options.Claimer。
package nodeid
