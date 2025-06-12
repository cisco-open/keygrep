#!/bin/bash

# Outline of a "mangling" function script

set -euo pipefail

# Replace newlines with spaces
newlines_to_spaces() {
    sed ':a;N;$!ba;s/\n/ /g'
}

# Replace newlines with literal \n
escape_newlines() {
    sed ':a;N;$!ba;s/\n/\\n/g'
}

# Replace newlines with literal \\n
double_escape_newlines() {
    sed ':a;N;$!ba;s/\n/\\\\n/g'
}

#echo -e "hello\nworld" | newlines_to_spaces
#echo -e "hello\nworld" | escape_newlines
#echo -e "hello\nworld" | double_escape_newlines
