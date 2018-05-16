# What is DevX project? 

DevX library enables direct access from the user space area to the
mlx5 device driver by using the KABI mechanism.

The main purpose here is to make the user space driver as independent as
possible from the kernel so that future device functionality and commands
can be activated with minimal to none kernel changes.


## How to build and run tests with DevX

```
% git clone https://github.com/Mellanox/devx
% cd devx
% git submodule init
% git submodule update
% cmake .
% make
% ./test
```
