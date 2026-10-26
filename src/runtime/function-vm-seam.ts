// Test seam for dispatch tests: no KVM, jailer or store. Records every function-VM boot and dispose so a test can
// assert one VM per invocation and a teardown on every path. Not a test file itself.
import type { FirecrackerHandle } from "./firecracker-client.ts";
import { _resetFunctionVmAdmissionForTest, _setFunctionVmOpsForTest, type BootFunctionVmArgs } from "./function-vm.ts";

export type FunctionVmSeamState = { boots: BootFunctionVmArgs[]; disposed: string[]; materialized: string[] };

export function installFunctionVmSeam(): FunctionVmSeamState {
  const state: FunctionVmSeamState = { boots: [], disposed: [], materialized: [] };
  _resetFunctionVmAdmissionForTest();
  _setFunctionVmOpsForTest({
    env: () => ({ kernelPath: "/test/vmlinux", cacheDir: "/tmp/k9o-test-rootfs-cache" }),
    materialize: async ({ rootfsKey }) => {
      state.materialized.push(rootfsKey);
      return { path: "/tmp/k9o-test-rootfs-cache/fn.ext4", hit: true, bytes: 1 };
    },
    boot: async (args) => {
      state.boots.push(args);
      return {
        vmId: args.vmId,
        handle: { id: args.vmId } as unknown as FirecrackerHandle,
        udsPath: `/run/k9o/firecracker/${args.vmId}.vsock`,
        jailUid: 100_001,
        consoleDiagnostics: () => "k9o-init: test console line",
        dispose: async () => {
          state.disposed.push(args.vmId);
        },
      };
    },
  });
  return state;
}

export function removeFunctionVmSeam(): void {
  _setFunctionVmOpsForTest(null);
  _resetFunctionVmAdmissionForTest();
}
