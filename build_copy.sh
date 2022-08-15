#!/bin/bash
echo "===== make clean release docker ====="
make clean release docker

echo "===== cp release/linux-amd64/bin/* ../fabric-samples-gm/bin/ ====="
cp release/linux-amd64/bin/* ../fabric-samples-gm/bin/

echo "===== over ====="
