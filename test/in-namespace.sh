#!/bin/sh
# Run a command in a network namespace of its own, with a yeetd of its own, so
# a test that loads a firewall cannot touch one that is already up on this
# host or collide with another test run. The namespace has its own loopback
# (ifindex 1), its own bpffs and its own daemon sockets; all of it is removed
# on the way out.
#
#   sh test/in-namespace.sh COMMAND [ARG ...]
#
# The command runs as the calling user, from the repository root, with a
# `yeet` first on PATH (and named by $YEET) that talks to the namespace's
# daemon. Needs Linux, sudo, yeet and yeetd. YEET and YEETD name the binaries
# when the ones on PATH are not the ones to use.
set -eu

[ "$(uname -s)" = Linux ] || { echo "test/in-namespace.sh needs Linux: the policies are loaded into the kernel" >&2; exit 2; }
[ $# -gt 0 ] || { echo "usage: sh test/in-namespace.sh COMMAND [ARG ...]" >&2; exit 2; }

here=$(cd "$(dirname "$0")/.." && pwd)
real() { readlink -f "$(command -v "$1")"; }
yeet=${YEET:-$(real yeet)}
yeetd=${YEETD:-$(real yeetd)}

ns="pfwrules$$"
run="/run/$ns"
work=$(mktemp -d)
state="$work/yeetd"
log="$work/yeetd.log"

cleanup() {
	status=$?
	if sudo test -f "$run/yeetd.pid"; then sudo kill "$(sudo cat "$run/yeetd.pid")" 2>/dev/null || true; fi
	sleep 1
	sudo ip netns pids "$ns" 2>/dev/null | while read -r pid; do sudo kill "$pid" 2>/dev/null || true; done
	sudo ip netns del "$ns" 2>/dev/null || true
	[ "$status" -eq 0 ] || { echo "--- yeetd in the namespace said:" >&2; tail -n 20 "$log" >&2 || true; }
	sudo rm -rf -- "$run" "$work"
	exit "$status"
}
trap cleanup EXIT INT TERM

sudo ip netns add "$ns"
sudo ip netns exec "$ns" ip link set lo up
# The tests listen on the policies' own ports, 80 and 443 among them. This
# setting belongs to the namespace, not the host.
sudo ip netns exec "$ns" sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
sudo mkdir -p "$run" "$state"

# `ip netns exec` gives the command a mount namespace too, so this bpffs is
# the namespace's own and its pins die with it.
sudo setsid ip netns exec "$ns" sh -c "mount -t bpf bpf /sys/fs/bpf; exec '$yeetd' --home '$state' --socket '$run/yeetd.sock' --user-socket '$run/yeetd.user.sock' --pid-file '$run/yeetd.pid' --disable-transponder --no-splash" >"$log" 2>&1 &

i=0
until sudo test -S "$run/yeetd.user.sock"; do
	i=$((i + 1))
	[ "$i" -le 100 ] || { echo "yeetd did not come up in namespace $ns" >&2; exit 1; }
	sleep 0.2
done

# A `yeet` that talks to that daemon.
mkdir -p "$work/bin" "$work/home"
printf '#!/bin/sh\nexec "%s" --socket "%s" --user-socket "%s" "$@"\n' "$yeet" "$run/yeetd.sock" "$run/yeetd.user.sock" >"$work/bin/yeet"
chmod +x "$work/bin/yeet"
chmod 755 "$work"

sudo ip netns exec "$ns" sudo -u "$(id -un)" env HOME="$HOME" PATH="$work/bin:$PATH" YEET="$work/bin/yeet" SCRATCH_HOME="$work/home" \
	PFW_CORE="${PFW_CORE:-}" PFW="${PFW:-}" PFW_SOURCE="${PFW_SOURCE:-}" CI="${CI:-}" YEET_API_KEY="${YEET_API_KEY:-}" \
	sh -c 'cd "$1" && shift && exec "$@"' -- "$here" "$@"
