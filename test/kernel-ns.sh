#!/bin/sh
# Run test/kernel.mjs in a network namespace of its own, with a yeetd of its
# own, so it cannot touch a firewall that is already up on this host or
# collide with another test run. The namespace has its own loopback (ifindex
# 1), its own bpffs and its own daemon sockets; all of it is removed on the
# way out.
#
#   PFW_CORE=/path/to/pfw-core sh test/kernel-ns.sh [policy ...]
#
# Needs Linux, sudo, yeet and yeetd, node 24 or newer, and a pfw-core with
# its object built (bin/vm.bpf.o). YEET and YEETD name the binaries when the
# ones on PATH are not the ones to use.
set -eu

[ "$(uname -s)" = Linux ] || { echo "test/kernel-ns.sh needs Linux: the policies are loaded into the kernel" >&2; exit 2; }
: "${PFW_CORE:?set PFW_CORE to a pfw-core checkout with bin/vm.bpf.o built}"
PFW_CORE=$(cd "$PFW_CORE" && pwd)
[ -f "$PFW_CORE/bin/vm.bpf.o" ] || { echo "$PFW_CORE/bin/vm.bpf.o is missing: run make bpf in pfw-core, or make in pfw" >&2; exit 2; }

here=$(cd "$(dirname "$0")/.." && pwd)
real() { readlink -f "$(command -v "$1")"; }
YEET=${YEET:-$(real yeet)}
YEETD=${YEETD:-$(real yeetd)}
NODE=$(real node)

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
sudo mkdir -p "$run" "$state"

# `ip netns exec` gives the command a mount namespace too, so this bpffs is
# the namespace's own and its pins die with it.
sudo setsid ip netns exec "$ns" sh -c "mount -t bpf bpf /sys/fs/bpf; exec '$YEETD' --home '$state' --socket '$run/yeetd.sock' --user-socket '$run/yeetd.user.sock' --pid-file '$run/yeetd.pid' --disable-transponder --no-splash" >"$log" 2>&1 &

i=0
until sudo test -S "$run/yeetd.user.sock"; do
	i=$((i + 1))
	[ "$i" -le 100 ] || { echo "yeetd did not come up in namespace $ns" >&2; exit 1; }
	sleep 0.2
done

# A `yeet` that talks to that daemon, first on PATH for the test.
mkdir -p "$work/bin"
printf '#!/bin/sh\nexec "%s" --socket "%s" --user-socket "%s" "$@"\n' "$YEET" "$run/yeetd.sock" "$run/yeetd.user.sock" >"$work/bin/yeet"
chmod +x "$work/bin/yeet"
chmod 755 "$work"

sudo ip netns exec "$ns" sudo -u "$(id -un)" env HOME="$HOME" PATH="$work/bin:$(dirname "$NODE"):$PATH" PFW_CORE="$PFW_CORE" \
	sh -c 'cd "$1" && shift && exec node test/kernel.mjs "$@"' -- "$here" "$@"
