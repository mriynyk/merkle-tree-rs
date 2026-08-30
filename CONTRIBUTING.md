# Contributing

## Issues

Opening an issue before a pull request is recommended, not required. A self-contained, well-described
pull request is fine on its own; an issue first is worth it when the change is large or its direction
is open to debate.

A bug report should state the crate version and how to reproduce the problem.

## Pull requests

Every check on a pull request must pass. The checks run automatically.

A change in behavior comes with a test that covers it.

## Documentation

Code is expected to be documented, split by audience:

- `///` and `//!` describe the **contract** — what a caller may rely on, stated in terms of the
  problem domain. Every public item carries one.
- `//` comments inside a body explain **mechanics** — why a step is written the way it is, where that
  is not obvious from the code itself.

Keep the two apart: a doc comment describes what a caller can rely on, not how the function is
written inside.

## Security

Do not report a suspected vulnerability in a public issue. Use private vulnerability reporting, under
the repository's Security tab.
