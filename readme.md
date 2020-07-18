# brief

a websocket server demo

## build

1. apt-get install openssl
2. apt-get install libssl-dev
3. make

## test

1. ./server
2. 用浏览器打开websocket.html，复制标签得到两个窗口
3. 点击refresh刷新得到好友列表
4. Friend List选择ID 0，在输入框中输出字符串，点击send，此时对方应该打印RESPONSE
5. 预期结果：双方可以互发消息

# reference

https://github.com/lhc3538/my-websocket-server
