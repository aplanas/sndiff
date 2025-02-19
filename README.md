## sndiff

`sndiff` is a small tool that report differences between snapshots in
openSUSE Tumbleweed and MicroOS.

By default shows information about packages and files in `/etc`, that
can return `diff -u` output for changelogs and modified files.  See
`sndiff --help` for all the options.

### Examples

`sndiff 3`: Compare the snapshot 3 with the current active one,
showing list of updated, downgraded, added and removed packages, and
changed, added and removed files in `/etc`.

`sndiff 3 4`: Compare snapshots 3 (old) and 4 (new), showing the same
information than before.

`sndiff --short 3 4`: Present the information in a compact way.

`sndiff --packages 3 4`: Only compares packages from snapshots 3 and
4.

`sndiff --etc 3 4`: Only compares `/etc` files.

`sndiff --diff 3 4`: Shows `diff -u` (10 lines max) of changelog
for updated or downgraded packages, and changed files from `/etc`.

`sndiff --diff --json 3 4`: Generate JSON output, this time
includes the full differences.

`sndiff --no-colors 3 4`  -- No colorized output
