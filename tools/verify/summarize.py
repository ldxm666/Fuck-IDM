#!/usr/bin/env python3
"""Compact summariser for the soak3 logs (UTF-16LE, written by Tee-Object).

Prints one row per run: MData first appearance + the RESULT line, plus any
popup_other titles.  Keeps output small so it can be polled cheaply.
"""
import glob, os, re, sys

pat = sys.argv[1] if len(sys.argv) > 1 else r'logs\verify\soak3-*.log'
files = sorted(glob.glob(pat), key=os.path.getmtime)
if not files:
    print('no logs match', pat); sys.exit(0)
f = files[-1]
txt = open(f, 'rb').read().decode('utf-16', errors='replace')
print('LOG', os.path.basename(f))
run = None
first = {}
titles = {}
res = []
for line in txt.split('\n'):
    m = re.search(r'run=(\d+)/\d+', line)
    if m and '##########' in line:
        run = int(m.group(1)); continue
    if run and 'MData PRESENT at' in line and run not in first:
        t = re.search(r'at ([\d.]+)s', line)
        g = re.search(r':\s*(\S+)\s*$', line.strip())
        first[run] = (t.group(1) if t else '?', g.group(1) if g else '?')
    if run and 'popup_other titles' in line:
        titles[run] = line.split(':', 1)[1].strip()
    if 'RESULT run=' in line:
        res.append(line.strip())
print('%-4s %-9s %s' % ('run', 'MData@', 'tree'))
for r in sorted(first):
    print('%-4d %-9s %s' % (r, first[r][0] + 's', first[r][1]))
print()
for l in res:
    print(l)
for r in sorted(titles):
    print('  run %d popup_other titles: %s' % (r, titles[r]))
