#!/bin/bash

set -e -u

for b in buster bullseye bookworm trixie; do
  echo "Pushing build_${b}" >&2
  git push origin HEAD:refs/heads/build_${b}
done
