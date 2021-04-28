#!/usr/bin/env python

#
# Copyright 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import sys
import json

def remove_subdir(l):
    l = l.replace('node/', '')

    if l == "tsc -b node":
        l = "tsc"

    return l

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        raise Exception("Usage: %s <path to package.json>" % (args[0]))

    info = json.loads(open(args[1], 'r').read())
    del info['files']

    info['main'] = remove_subdir(info['main'])
    info['types'] = remove_subdir(info['types'])

    for script in info['scripts']:
        info['scripts'][script] = remove_subdir(info['scripts'][script])

    if 'prepare' in info['scripts']:
        del info['scripts']['prepare']
    print(json.dumps(info, indent=2, sort_keys=True, separators=(',', ': ')))

if __name__ == '__main__':
    sys.exit(main())
