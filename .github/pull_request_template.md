# What this changes

<!-- One or two sentences. What is different afterwards. -->

## Why

<!-- The problem, not the patch. If this corrects an earlier assumption, say
     which one and what the measurement showed. -->

## Evidence

<!-- How you know it works. A command and its output beats a description.
     "Tests pass" is what CI is for and is not evidence on its own. -->

```
```

## Checklist

- [ ] Behaviour that can silently degrade has a check that fails when it does
- [ ] Kernel-side changes were loaded on a kernel other than the development one
- [ ] Anything measured is recorded with the method, not just the number
- [ ] Documentation that states the old behaviour has been corrected

## Privilege

<!-- Delete if untouched. -->

- [ ] This changes the capability set, mounts, or securityContext

If ticked: which capability, what breaks without it, and how that was
established. The set in ADR-006 was measured by removing each one until
something failed — a change to it needs the same.
