# IAC-HARDENING — OS / kernel / network hardening baseline

*Implementation: `hardening/tasks/main.yml`*

**Execution chain:** Execution → Execution → Execution

**1. Execution** — Ansible baseline applies kernel/sysctl hardening…

`hardening/tasks/main.yml:L20-L22`

```yaml

- name: Apply kernel and sysctl hardening
  ansible.builtin.include_tasks: kernel.yml
```

**2. Execution** — …a default-deny firewall…

`hardening/tasks/main.yml:L30-L32`

```yaml
- name: Apply firewall configuration
  ansible.builtin.include_tasks: firewall.yml
  when: hardening_firewall_enabled
```

**3. Execution** — …and host audit rules — declaratively and idempotently across the fleet.

`hardening/tasks/main.yml:L34-L35`

```yaml
- name: Apply audit rules
  ansible.builtin.include_tasks: audit.yml
```
