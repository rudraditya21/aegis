# Docker build matrix

These images are for testing aegis across common Linux distributions. You can run them on macOS/Windows via Docker Desktop, but the container itself is Linux.

## Build

From the repo root:

```bash
bash docker/build-matrix.sh
```

Optional overrides:

```bash
IMAGE_PREFIX=aegis CARGO_FEATURES=pcap BUILD_PROFILE=release bash docker/build-matrix.sh
```

## Run (example)

```bash
docker run --rm -it aegis:debian --help
```

## Notes

- Default build uses the `pcap` backend (portable). AF_XDP and DPDK require Linux kernel support and extra host setup (hugepages, privileges, NIC binding).
- To test AF_XDP inside a container, run with `--privileged` and mount `/sys/fs/bpf` and hugepage filesystems as needed.
