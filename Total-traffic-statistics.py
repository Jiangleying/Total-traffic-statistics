from flask import Flask, render_template
from scapy.all import *
from pyecharts.charts import Bar
import webbrowser

app = Flask(__name__)

# 分别创建空的字典 保存一个五元组的流量和总长度
tuple_cnt = {}
tuple_len = {}
# 保存画图所需的y坐标
yaxis = []


def main():
    path = input("请输入包的绝对路径:")
    # 遍历获得数据
    dpkt = rdpcap(path)
    # 用于统计每10k的长度
    route_len = 0

    for cnt in range(len(dpkt)):
        # 如过不是IP协议就pass 2048:代表IP协议
        if dpkt[cnt][Ether].type != 2048:
            continue

        # 如果不是TCP和UDP就pass
        if dpkt[cnt][IP].proto != 6 and dpkt[cnt][IP].proto != 17:
            continue

        # 获得协议类型proto  6是TCP 17是UDP
        if dpkt[cnt][IP].proto == 6:
            proto = "TCP"
        if dpkt[cnt][IP].proto == 17:
            proto = "UDP"

        # 获得IP地址
        ip_src = dpkt[cnt][IP].src
        ip_dst = dpkt[cnt][IP].dst

        # 获得端口
        sport = dpkt[cnt][proto].sport
        dport = dpkt[cnt][proto].dport

        # 获得这个包的长度
        length = len(dpkt[cnt])

        # 构造字符串表示五元组 作为key
        # 如UDP 192.168.1.1:80 to 192.168.1.2:80
        tuple_key = f"{proto} {ip_src}:{sport} -> {ip_dst}:{dport}"
        # 若字典中不存在该key 则得为该key初始化
        if not tuple_cnt.get(tuple_key):
            tuple_cnt[tuple_key] = 0
            tuple_len[tuple_key] = 0
        # 每10k长度++
        route_len += length
        # 次数加一 总长度加上该包长度
        tuple_len[tuple_key] += 1
        tuple_cnt[tuple_key] += length

        if (cnt + 1) % 10_000 == 0:
            """每10k出一个坐标"""
            yaxis.append(route_len)
            # 把循环计数计为0
            route_len = 0

    # 
    print("统计结束 即将弹出网页")
    app.run("", 5000)
    webbrowser.open("127.0.0.1:5000")



@app.route("/")
def display():
    bar = (
        Bar()
        .add_xaxis(["10k", "20k", "30k", "40k", "50k", "60k", "70k", "80k", "90k", "100k"])
        .add_yaxis("总流量统计", yaxis)
    )
    return render_template('try.html', bar_options=bar.dump_options())


if __name__ == "__main__":
    main()
