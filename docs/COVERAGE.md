# Coverage

CI requires exact 100% line and branch counts for reachable production code.
No production source exclusions are currently approved. Test harness files under
`tests/` are excluded from the production report; they execute on native and wasm.
Nightly is necessary for LLVM branch instrumentation, while stable remains the
supported compiler. Empty coverage cannot pass. Full library acceptance also
requires independently reviewed real integration evidence.
