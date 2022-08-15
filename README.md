fabric-gm
============================

基于fabric`2.2.5`版本的国密改造。

# 编译
本地事先准备好go环境与docker环境,如:
- go : 1.17.5
- docker : 20.10.14
- docker-compose : 1.25.0

执行本地编译
```sh
# 该命令清空本地编译的二进制与docker镜像
make clean

# 编译二进制文件
make release

# 编译docker镜像
make docker
```

# 测试
fabric-gm的测试需要国密改造后的`fabric-samples`，参考: `https://gitee.com/zhaochuninhefei/fabric-samples-gm`。


# 版权声明
本项目采取木兰宽松许可证, 第2版，具体参见`LICENSE`文件。

本项目基于`github.com/hyperledger/fabric`进行了二次开发，对应版权声明文件:`thrid_licenses/github.com/hyperledger/fabric/LICENSE`。