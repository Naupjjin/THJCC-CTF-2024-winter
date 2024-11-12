# It's Mygo!!!\!!🎤🎸🎸🥁🎸 Golang's Funeral 🎹
> Author: 堇姬Naup

tag: `web`、`reverse`、`pwn`、`golang`、`MyGo!!!!!`

發現的一個golang trick，順便讓各位玩看看golang逆向
## IDA分析
我沒有拔掉debug symbol(因為我發現拔掉好像會太難逆)
以下可以搭配釋出的source code跟golang官方文檔，裡面有該函數原本的樣子，比較容易看懂

golang官方文檔
https://pkg.go.dev/net/http
https://pkg.go.dev/os/exec


先從入口main.main開始看