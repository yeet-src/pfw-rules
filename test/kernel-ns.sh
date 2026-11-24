#!/bin/sh
# test/kernel.mjs in a network namespace of its own (see in-namespace.sh).
#
#   PFW_CORE=/path/to/pfw-core sh test/kernel-ns.sh [policy ...]
#
# Needs node 24 or newer and a pfw-core with its object built (bin/vm.bpf.o).
set -eu
: "${PFW_CORE:?set PFW_CORE to a pfw-core checkout with bin/vm.bpf.o built}"
PFW_CORE=$(cd "$PFW_CORE" && pwd)
export PFW_CORE
[ -f "$PFW_CORE/bin/vm.bpf.o" ] || { echo "$PFW_CORE/bin/vm.bpf.o is missing: run make bpf in pfw-core, or make in pfw" >&2; exit 2; }
exec sh "$(dirname "$0")/in-namespace.sh" "$(readlink -f "$(command -v node)")" test/kernel.mjs "$@"
