#!/bin/bash

#
# Copyright 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/../..
. bin/build_helpers.sh

#
# copy_repo.sh <source> <destination>
#
# Copy the given node directory to the artifact repository.
#
# Example:
# libsignal-client$ node/scripts/copy_repo.sh ../libsignal-client-node
#

mkdir -p $1

./node/scripts/rewrite_package_json.py package.json > $1/package.json
cp -vf node/index.ts $1
cp -vf node/libsignal_client.d.ts $1

mkdir -p $1/dist
cp -vf node/dist/index.d.ts $1/dist
cp -vf node/dist/index.js $1/dist
cp -vf node/libsignal_client.d.ts $1/dist

mkdir -p $1/build
cp -vf build/Release/libsignal_client_*.node $1/build

# Ensure that the LICENSE file is up to date.
cp -vf ./LICENSE $1

# Ensure that the README.md file is up to date.
cp -vf ./README.md $1
