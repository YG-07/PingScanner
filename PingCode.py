# coding=utf-8

# import logging
# import time
import requests
from scapy.layers.inet import IP, ICMP
from scapy.all import *
from random import randint
import dns.resolver
from selenium import webdriver
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
IPRE=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"


def port_stat():
    url='https://tool.chinaz.com/port/'
    ip=input('输入域名或IP：')
    psta=int(input('输入起始端口号：'))
    pend=int(input('输入结束端口号：'))
    driver=webdriver.Chrome()
    driver.set_window_size(1520,850)
    driver.get(url)
    time.sleep(0.3)
    driver.find_element_by_xpath('//*[@id="host"]').send_keys(ip)
    port=psta
    while port<=pend:
        driver.find_element_by_xpath('//*[@id="port"]').send_keys(str(port))
        driver.find_element_by_xpath('/html/body/div[2]/div[1]/form/div/div/input').click()
        time.sleep(0.5)
        stat=driver.find_element_by_xpath('//*[@id="contenthtml"]/p[2]/span[3]').text
        if stat=='':
            stat='关闭'
        print("域名/IP：{0}\t端口：{1}\t状态:{2}".format(ip,port,stat))
        driver.find_element_by_xpath('/html/body/div[2]/div[1]/form/div/span[2]/a').click()
        port=port+1
    driver.quit()

def dnsmod(host):
    if host=='':
        return "输入为空！"
    A=dns.resolver.resolve(host,'A')
    for i in A.response.answer:
        for j in i.items:
            if j.rdtype == 1:
                print("[{0}]域名解析为：[{1}]".format(host,j.address))
                return j.address


def scapy_ping_one(host):
    id_ip = randint(1,65535)#随机产生IP_ID位
    id_ping = randint(1,65535)#随机产生Ping_ID位
    seq_ping = randint(1,65535)#随机产生Ping序列号位
    #构造Ping数据包
    packet = IP(dst = host,ttl = 64,id = id_ip)/ICMP(id = id_ping,seq = seq_ping)/b'Welcome to python'
    ping = sr1(packet,timeout = 2,verbose = False)#获取相应信息，超时为2秒，关闭详细信息
    #ping.show() #被调用来扫描整个网段时候最好注释起来，不然产生大量信息
    if ping:#如果又响应信息
        print(host+" success")
    else:
        print(host+" fail")

def ping_net():
    inp=input("输入扫描的IP或域名:")
    if len(re.findall(IPRE,inp))==0:
        inp=dnsmod(inp)
    lis=inp.split('.')
    lis.pop()
    host='.'.join(lis)+"."

    ips=int(input("输入扫描的起始数:"))
    ipe=int(input("输入扫描的结束数:"))
    i = ips
    while i <= ipe:
        scapy_ping_one(host + str(i))
        i = i + 1

def chax():
    lid = input("请输入你要查询的IP或域名:")
    start = time.time()
    print("**************************************开始获取IP信息**********************************************")
    head = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'
    }
    url="http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query&lang=zh-CN".format(lid)
    rb=requests.get(url,headers=head)
    # gf=BeautifulSoup(rb)
    # print(rb.text)
    # print("status:"+rb.content["status"])
    response = rb.text
    print(type(response))
    # print(response)
    # 把str转换到dic
    dict_response = eval(response)
    # for i in dict_response.items():
    #         print(i)
    for key,value in dict_response.items():
        print("IP信息:" + str(key) + " : " + str(value))
    end = time.time()
    print("耗时：{0:.2f}秒".format(end - start))


if __name__ == '__main__':

    # ping_net()

    # PingSoft.dnsmod('www.qq.com')

    # try:
    #     chax()
    # except:
    #     print("请求超时！")

    port_stat()


