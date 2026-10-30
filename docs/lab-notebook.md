# Lab Notebook — Container Escape Detection

## 2026-10-30 — Session 1: Testbed environment + Falco setup

### Environment (testbed VM)
- Host: Apple Silicon (M5) Mac, UTM
- Guest: Kali GNU/Linux Rolling, kernel 6.12.33+kali-arm64 (ARM64/aarch64)
- cgroup: v2 (cgroup2fs)
- BTF: present (/sys/kernel/btf/vmlinux) — enables modern eBPF / CO-RE
- Docker: 27.5.1
- Note: Kali used as container host (pentest distro, atypical) — recorded as a limitation.

### Falco
- Version: 0.45.2 (aarch64), from official apt repo
- Driver: modern_ebpf (no kernel module/headers needed, thanks to BTF)
- Service: falco-modern-bpf.service (active)

### Detection test
- Attack: docker run --rm alpine cat /etc/shadow
- Result: DETECTED. Rule "Sensitive file opened for reading by non-trusted program"
  - container_name=strange_banach, image=alpine:latest, container_id=e741b9e214d3
  - process=cat, command=cat /etc/shadow

### Findings
- FALSE POSITIVE: benign Postgres health-check (pg_isready) in unrelated container
  (16954052_cyberdelia_db) trips the same "Read sensitive file" rule every ~10s.
  -> Relevant to false-positive analysis in the discussion.
- ATTRIBUTION: multiple containers produce identical alert text, so alerts must be
  matched to an attack by container_id + timestamp window, not by rule name.

### Housekeeping
- Unrelated containers running this session: cyberdelia proxy/app/db.
  Must be stopped before benign-baseline and trial runs to keep the host clean.

### Next
- Install Tetragon (second detector).
- Stop cyberdelia containers for a clean host.
- Build harness skeleton: reset -> start detector -> run one procedure
  -> capture alert by container_id -> write one CSV row.

### Tetragon (same session)
- Image: quay.io/cilium/tetragon:v1.6.0 (standalone Docker; --pid=host --cgroupns=host --privileged; BTF mounted)
- Policy: examples/quickstart/file_monitoring.yaml (a published example policy)
- Test: docker run --rm alpine cat /etc/shadow -> DETECTED (process /bin/cat + read events on /etc/shadow)
- Key finding: detection semantics differ between tools. Falco = one discrete named alert;
  Tetragon = event stream (process lineage + file reads) filtered by policy.
  -> Methodology must define per-tool what counts as a detection / partial detection.
- Host noise: Kali desktop (xfce4-panel-genmon-vpnip.sh) spawns processes ~1/sec, flooding events.
  Reinforces: quiet the host + attribute by container_id + time window.
