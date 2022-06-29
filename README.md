# About

This is a simple file monitoring script written in Go that uses SHA256 to check whether files in a directory have been tampered.
It creates a list of all files in a directory, storing their names and hashes. Then in future scans, it hashes all of those files again and compares their new hashes to their old ones to figure out if anything has changed.

# Usage 

- -h Show help menu.
- -b baseline scan.
- -s hash scan.
- -ts timed hash scan.

Example : go go-watcher.go <scan type> <scan directory> <scan file directory> <time interval for timed scans> <number of timed scans>

Firstly, do a baseline scan on the directory. It will store the hashes of its files. At this point you can do hash scans to check if any of those files have been tampered