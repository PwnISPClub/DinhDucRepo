#!/bin/sh

socat tcp-listen:9993,fork,reuseaddr exec:"/app/bof7 2>/dev/null"