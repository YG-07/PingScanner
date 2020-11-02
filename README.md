# PingScanner
PingScanner
---
这是由Windows的Python编程的,扩展包和站点工具，主要功能有域名解析、IP信息、网段扫描、端口扫描.  
This is the windows python programming, expansion pack and site tools, the main functions are domain name resolution, IP information, network segment scanning, port scanning.  
  
基本原理：  
本程序是利用了Windows下的Python编写的，运用了Python的扩展包，如：tkinter,requests,scapy,random,dns,selenium.主程序有4个功能，并将程序界面封装成类可供拓展和修改.  
功    能：  
1.域名解析：利用dns库函数将域名解析成IP.  
2.IP信息：利用requests请求站点工具获取IP的详细信息,默认为空时获取本机IP信息.  
3.网段扫描：利用scapy库函数模拟ping操作来获取主机的连通性.  
4.端口扫描：利用selenium库函数模拟浏览器访问站点工具来扫描端口.  
