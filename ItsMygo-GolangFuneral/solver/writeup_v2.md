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


`net_http__ptr_ServeMux_Handle` 他會設置route的handler
包括 "/mygolang"、"/itsmygo" 和"/"
https://pkg.go.dev/net/http#ServeMux.HandleFunc
ServeMux具體在golang實現會向是這樣
```go
http.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
  w.Write([]byte("Receive path foo"))
 })
```

ida如下
```c
  v9.tab = (runtime_itab *)net_http_DefaultServeMux;
  v9.data = &unk_69727F;
  v11.len = (int)&go_itab_net_http_HandlerFunc_comma_net_http_Handler;
  v11.cap = (int)&pattern;
  net_http__ptr_ServeMux_Handle(v9, (net_http_ServeMux *)9, *(string *)&v11.len);
  v9.tab = (runtime_itab *)net_http_DefaultServeMux;
  v9.data = &unk_696DD9;
  v11.len = (int)&go_itab_net_http_HandlerFunc_comma_net_http_Handler;
  v11.cap = (int)&off_6C4930;
  net_http__ptr_ServeMux_Handle(v9, (net_http_ServeMux *)8, *(string *)&v11.len);
  v9.tab = (runtime_itab *)net_http_DefaultServeMux;
  v9.data = "/";
  v11.len = (int)&go_itab_net_http_HandlerFunc_comma_net_http_Handler;
  v11.cap = (int)&off_6C4928;
  net_http__ptr_ServeMux_Handle(v9, (net_http_ServeMux *)&unk_1, *(string *)&v11.len);
```

這東西跟處理filehandler有關係的，他也創建了一個route /static/，並要求他當一個prefix
https://pkg.go.dev/net/http#StripPrefix
```c
  v9.tab = (runtime_itab *)runtime_newobject((runtime__type *)&RTYPE_http_fileHandler);
  v9.tab->inter = (runtime_interfacetype *)&go_itab_net_http_Dir_comma_net_http_FileSystem;
  v9.tab->_type = (runtime__type *)&off_70B7D0;
  v9.data = (void *)8;
  v2 = &go_itab__ptr_net_http_fileHandler_comma_net_http_Handler;
  v11.len = (int)v9.tab;
  v9.tab = (runtime_itab *)&handler;
  net_http_StripPrefix(v9, *(net_http_Handler *)&v11.len, *(string *)&v11.cap);
  v11.len = (int)v9.tab;
  v11.cap = 8LL;
  v9.tab = (runtime_itab *)net_http_DefaultServeMux;
```
off_70B7E0，應該是印出跟開在哪個host 或是 port，等等的資訊
```c
  v9.data = (void *)&handler;
  net_http__ptr_ServeMux_Handle(v9, (net_http_ServeMux *)8, *(string *)&v11.len);
  a.array = (interface_ *)&RTYPE_string_0;
  a.len = (int)&off_70B7E0;
  v9.data = os_Stdout;
  v9.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
  v11.array = (interface_ *)&a;
  v11.len = 1LL;
  v11.cap = 1LL;
  fmt_Fprintln(v9, v11);
```

off_70B7E0
```
.rodata:000000000070B7E0 off_70B7E0      dq offset aServerStartedO
.rodata:000000000070B7E0                                         ; DATA XREF: main_main+FD↑o
.rodata:000000000070B7E0                                         ; "Server started om port http://localhost"...
```

設定 listen 在哪個 port (unk_69871D) `.rodata:000000000069871D a000020000      db '0.0.0.0:20000'      ; DATA XREF: main_main+13D↑o`
```c
  p_http_Server = (http_Server *)runtime_newobject((runtime__type *)&RTYPE_http_Server);
  p_http_Server->Addr.len = 13LL;
  p_http_Server->Addr.ptr = (char *)&unk_69871D;
  p_http_Server->Handler = v1;
  v4 = net_http__ptr_Server_ListenAndServe(p_http_Server);
```
看到這邊web server setting其實差不多了，接下來去分析其他地方，這裡我們直接鎖定重點

main.mygoooHandler
這裡根據網站是處理compiler的頁面
```c
if ( r->Method.len == 4 && *(_DWORD *)r->Method.str == 'TSOP' )
```
POST會進入到if，否則直接顯示該頁面
以下是complier 透過 POST method處理邏輯
處理跟user request有關，錯誤就印出ERROR