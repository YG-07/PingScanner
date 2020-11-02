# coding=utf-8
# CMD里pyinstaller打包指令
# pyinstaller -F -i scan.ico -w PingWin.py --hidden-import tkinter,requests,scapy,random,dns,selenium
from tkinter import *
from tkinter.messagebox import showinfo
import requests
from scapy.layers.inet import IP, ICMP
from scapy.all import *
from random import randint
import dns.resolver
from selenium import webdriver
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
IPRE=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

class PingSoftMain():
    def __init__(self):
        if not os.path.exists('./扫描结果'):
            os.mkdir('扫描结果')
        self.root=Tk()
        self.root.config()
        self.root.title('PingWin')
        self.root.geometry('605x820')

        self.title = Label(self.root, text='【域名解析】')
        self.title.grid(row=0, column=0, columnspan=2, sticky=W)
        self.ym = Label(self.root, text='[域名]：')
        self.ym.grid(row=1, column=0, columnspan=2)
        self.ymin = Entry(self.root)
        self.ymin.grid(row=1, column=2)
        self.b1 = Button(self.root, text='解析域名', command=lambda:self.dnsjx(self.ymin.get()))
        self.b1.grid(row=1, column=3)

        self.ymip = Label(self.root, text='[域名/IP]：')
        self.ymip.grid(row=2, column=0, columnspan=2)
        self.ymipin = Entry(self.root)
        self.ymipin.grid(row=2, column=2)
        self.ipxx = Label(self.root, text='【IP信息】输入[域名/IP](形如x.x.x.x)获取详细信息')
        self.ipxx.grid(row=3, column=0, columnspan=3, sticky=W)
        self.b2 = Button(self.root, text='IP信息',command=lambda:self.IPxx(self.ymipin.get()))
        self.b2.grid(row=3, column=3)

        self.fww = Label(self.root, text='[范围]：')
        self.fww.grid(row=4, column=0, columnspan=2)
        self.fw1 = Entry(self.root, width=8)
        self.fw1.grid(row=4, column=2, sticky=E)
        self.fw2 = Entry(self.root, width=8)
        self.fw2.grid(row=4, column=3, sticky=W, padx=5)
        self.wdsm = Label(self.root, text='【网段扫描】请输入1-255[范围]进行网段ping扫描')
        self.wdsm.grid(row=5, column=0, columnspan=3, sticky=W)
        self.b3 = Button(self.root, text='网段扫描',command=lambda:self.pingnet(self.ymipin.get(),self.fw1.get(),self.fw2.get()))
        self.b3.grid(row=5, column=3)
        self.dksm = Label(self.root, text='【端口扫描】请输入端口号[范围]进行端口扫描')
        self.dksm.grid(row=6, column=0, columnspan=3, sticky=W)
        self.b4 = Button(self.root, text='端口扫描',command=lambda:self.portscan(self.ymipin.get(),self.fw1.get(),self.fw2.get()))
        self.b4.grid(row=6, column=3)

        self.resultvar = ''
        self.resw = Label(self.root, text='【操作结果】：')
        self.resw.grid(row=7, column=0, columnspan=2, sticky=W)
        self.result = Text(self.root, exportselection=1, height=40)
        self.result.grid(row=8, column=0, columnspan=4, padx=10, pady=15)
        self.scro = Scrollbar(self.root, orient='vertical', command=self.result.yview)
        self.result.config(yscrollcommand=self.scro.set)
        self.scro.grid(row=8, column=4, sticky=S + W + E + N)

        self.d1 = Button(self.root, text='帮助',command=self.ophelp)
        self.d1.grid(row=9, column=0)
        self.d2 = Button(self.root, text='清空结果',command=lambda:self.result.delete('0.0',END))
        self.d2.grid(row=9, column=1)
        self.scnt=1
        self.d3 = Button(self.root, text='保存结果',command=self.saveas)
        self.d3.grid(row=9, column=2)
        self.d4 = Button(self.root, text='打开文件夹',command=lambda:os.startfile('扫描结果'))
        self.d4.grid(row=9, column=3)


        self.root.mainloop()
    def ophelp(self):
        msg="软件说明\n" \
            "名    称：PingWin.exe\n" \
            "基本原理：\n" \
            "              本程序是利用了Windows下的Python编写的，运用了Python\n" \
            "         的扩展包，如：tkinter,requests,scapy,random,dns,\n" \
            "         selenium.主程序有4个功能，并将程序界面封装成类.\n" \
            "         便于修改和添加功能.\n" \
            "功    能：\n" \
            "         1.域名解析：利用dns库函数将域名解析成IP.\n" \
            "         2.IP信息：利用requests请求站点工具获取IP的详细信息,默认为空时\n" \
            "           获取本机IP信息.\n" \
            "         3.网段扫描：利用scapy库函数模拟ping操作来获取主机的连通性.\n" \
            "         4.端口扫描：利用selenium库函数模拟浏览器访问站点工具来扫描端口.\n\n" \
            "软件帮助：\n" \
            "基本操作：\n" \
            "        【域名解析】：输入[域名].\n" \
            "        【IP信息】：输入[域名/IP].（默认为空获取本机IP信息）\n" \
            "        【网段扫描】：输入[域名/IP]和[范围],IP最后一位范围1-255.\n" \
            "        【端口扫描】：输入[域名/IP]和[范围]，端口号范围.\n" \
            "        注：网段扫描和端口扫描是扫描完毕才输出的，软件可能会卡住,\n" \
            "           属于正常现象." \
            "文件操作：\n" \
            "        1.情况结果：清空输出结果文本框.\n" \
            "        2.保存文件/打开:将输出结果保存在目录\'./扫描结果/result[数字].txt\'\n" \
            "        注：每次重新运行该程序会替换文件夹的原本文件！\n" \
            ""
        showinfo('帮助及说明',msg,parent=self.root)
    def saveas(self):
        msg=self.result.get('0.0',END)
        f=open("扫描结果/result{0}.txt".format(self.scnt),'w+')
        f.write(msg)
        f.close()
        showinfo('保存', '保存成功！', parent=self.root)
        self.scnt=self.scnt+1

    def dnsjx(self,host):
        if host == '':
            self.result.insert(END,'输入为空！\n')
            return ''
        try:
            A = dns.resolver.resolve(host, 'A')
            for i in A.response.answer:
                for j in i.items:
                    if j.rdtype == 1:
                        self.resultvar="[{0}]域名解析为：[{1}]".format(host, j.address)
                        self.result.insert(END,self.resultvar+'\n')
                        return j.address
        except:
            self.result.insert(END, '[{0}]域名解析失败！\n'.format(host))
            return ''

    def IPxx(self,lid):
        start = time.time()
        if len(re.findall(IPRE, lid))==0:
            d=self.dnsjx(lid)
            if d=='':
                self.result.insert(END,'默认解析本机IP,')
                try:
                    hostname=socket.gethostname()
                    hostip=socket.gethostbyname(hostname)
                    self.result.insert(END, '主机名/IP[{0}][{1}]信息如下\n'.format(hostname,hostip))
                except:
                    self.result.insert(END, '本机名获取失败！\n')
        else:
            self.result.insert(END,'[{0}IP信息如下]\n'.format(lid))
        try:
            self.result.insert(END,"*********************开始获取IP信息************************\n")
            head = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'}
            url = "http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query&lang=zh-CN".format(lid)
            rb = requests.get(url, headers=head)
            response = rb.text
            dict_response = eval(response)
            for key, value in dict_response.items():
                self.result.insert(END,"IP信息:{0} : {1}\n".format(str(key),str(value)))
            end = time.time()
        except:
            self.result.insert(END, "操作繁忙，稍后再试！\n")
        self.result.insert(END,"耗时：{0:.2f}秒\n".format(end - start))

    def scapy_ping_one(self,host):
        id_ip = randint(1, 65535)  # 随机产生IP_ID位
        id_ping = randint(1, 65535)  # 随机产生Ping_ID位
        seq_ping = randint(1, 65535)  # 随机产生Ping序列号位
        # 构造Ping数据包
        packet = IP(dst=host, ttl=64, id=id_ip) / ICMP(id=id_ping, seq=seq_ping) / b'Welcome to python'
        ping = sr1(packet, timeout=2, verbose=False)  # 获取相应信息，超时为2秒，关闭详细信息
        # ping.show() #被调用来扫描整个网段时候最好注释起来，不然产生大量信息
        if ping:  # 如果又响应信息
            self.result.insert(END,'%*s' % (18,host) + "      开启\n")
        else:
            self.result.insert(END,'%*s' % (18,host) + "      关闭\n")
    #     000.000.000.000.000
    def chkin(self,inp,ips,ipe):
        if inp=='' or ips=='' or ipe=='':
            self.result.insert(END, '[域名/IP][范围]输入为空！\n')
            return ''
        if (not ips.isdigit()) or (not ipe.isdigit()) or int(ips)>int(ipe):
            self.result.insert(END, '输入[范围]有误！\n')
            return ''

    def pingnet(self,inp,ips,ipe):
        if self.chkin(inp,ips,ipe)=='':
            return
        start = time.time()
        self.result.insert(END, "*********************开始网段扫描************************\n")
        if len(re.findall(IPRE, inp)) == 0:
            inp = self.dnsjx(inp)
        lis = inp.split('.')
        lis.pop()
        host = '.'.join(lis) + "."
        self.result.insert(END,"正在Ping扫描网段[{0}]到[{1}]的连通状态：\n".format(host+ips,host+ipe))
        i = int(ips)
        while i <= int(ipe):
            self.scapy_ping_one(host + str(i))
            i = i + 1
        self.result.insert(END, '扫描完毕！\n')
        end = time.time()
        self.result.insert(END, "耗时：{0:.2f}秒\n".format(end - start))

    def portscan(self,ip,psta,pend):
        inp=ip
        if self.chkin(ip,psta,pend)=='':
            return
        start = time.time()
        self.result.insert(END, "*********************开始端口扫描************************\n")
        if len(re.findall(IPRE, ip)) == 0:
            inp = self.dnsjx(ip)
        self.result.insert(END, "正在扫描域名/IP[{0}][{1}]端口号[{2}]到[{3}]的连通状态：\n".format(ip,inp,psta, pend))
        url = 'https://tool.chinaz.com/port/'
        driver = webdriver.PhantomJS(executable_path='phantomjs.exe')
        # driver.set_window_size(1520, 850)
        driver.get(url)
        time.sleep(0.3)
        driver.find_element_by_xpath('//*[@id="host"]').send_keys(ip)
        port = int(psta)
        while port <= int(pend):
            driver.find_element_by_xpath('//*[@id="port"]').send_keys(str(port))
            driver.find_element_by_xpath('/html/body/div[2]/div[1]/form/div/div/input').click()
            time.sleep(0.5)
            stat = driver.find_element_by_xpath('//*[@id="contenthtml"]/p[2]/span[3]').text
            if stat == '':
                stat = '关闭'
            self.result.insert(END,"    端口：{0}      状态:{1}\n".format('%*d' % (6,port), stat))
            driver.find_element_by_xpath('/html/body/div[2]/div[1]/form/div/span[2]/a').click()
            port = port + 1
        driver.quit()
        self.result.insert(END, '扫描完毕！\n')
        end = time.time()
        self.result.insert(END, "耗时：{0:.2f}秒\n".format(end - start))

if __name__ == '__main__':
    PingSoftMain()

