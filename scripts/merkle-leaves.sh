#!/bin/bash

TREE_ID=${1:-0}
FROM=${2:-0}
TO=${3:-10}

echo 'Usage: merkle-leaves.sh <TREE_ID> <FROM> <TO>'

echo 'Fetching Tree #'$TREE_ID' Leaves from '$FROM' to '$TO''
echo '--------------------------------'
curl http://localhost:9933 \
    -H "Content-Type: application/json" \
    -d '{
            "id": "1",
            "jsonrpc": "2.0",
            "method": "merkle_treeLeaves",
            "params": ['$TREE_ID', '$FROM', '$TO']
        }'
