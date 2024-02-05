# gh-proxy

## 简介

github release、archive 以及项目文件的加速项目，支持 clone，有 Cloudflare Workers 无服务器版本以及 Python 版本

## 演示

[https://gh.noki.eu.org/](https://gh.noki.eu.org/)

演示站为公益服务，如有大规模使用需求请自行部署

## python 版本魔改

1. 首页不再依赖于外部服务
2. 首页样式优化：自动明暗主题
3. 直链缩短：github、raw、gist 等同于 https://github.com、 https://raw.githubusercontent.com、 https://gist.githubusercontent.com
4. 简单得代理次数、代理流量统计

## python 版本和 cf worker 版本差异

- python 版本支持进行文件大小限制，超过设定返回原地址 [issue #8](https://github.com/hunshcn/gh-proxy/issues/8)

- python 版本支持特定 user/repo 封禁/白名单 以及 passby [issue #41](https://github.com/hunshcn/gh-proxy/issues/41)

## 使用

直接在 copy 出来的 url 前加`https://gh.api.99988866.xyz/`即可

也可以直接访问，在 input 输入

**_大量使用请自行部署，以上域名仅为演示使用。_**

访问私有仓库可以通过

`git clone https://user:TOKEN@ghproxy.com/https://github.com/xxxx/xxxx` [#71](https://github.com/hunshcn/gh-proxy/issues/71)

以下都是合法输入（仅示例，文件不存在）：

- 分支源码：https://github.com/hunshcn/project/archive/master.zip

- release 源码：https://github.com/hunshcn/project/archive/v0.1.0.tar.gz

- release 文件：https://github.com/hunshcn/project/releases/download/v0.1.0/example.zip

- 分支文件：https://github.com/hunshcn/project/blob/master/filename

- commit 文件：https://github.com/hunshcn/project/blob/1111111111111111111111111111/filename

- gist：https://gist.githubusercontent.com/cielpy/351557e6e465c12986419ac5a4dd2568/raw/cmd.py

## cf worker 版本部署

首页：https://workers.cloudflare.com

注册，登陆，`Start building`，取一个子域名，`Create a Worker`。

复制 [index.js](https://cdn.jsdelivr.net/gh/hunshcn/gh-proxy@master/index.js) 到左侧代码框，`Save and deploy`。如果正常，右侧应显示首页。

`ASSET_URL`是静态资源的 url（实际上就是现在显示出来的那个输入框单页面）

`PREFIX`是前缀，默认（根路径情况为"/"），如果自定义路由为 example.com/gh/\*，请将 PREFIX 改为 '/gh/'，注意，少一个杠都会错！

## Python 版本部署

### Docker 部署

```
docker run -d --name="gh-proxy-py" \
  -p 0.0.0.0:80:80 \
  --restart=always \
  hunsh/gh-proxy-py:latest
```

第一个 80 是你要暴露出去的端口

### 直接部署

安装依赖（请使用 python3）

`pip install flask requests`

按需求修改`app/main.py`的前几项配置

_注意:_ 可能需要在`return Response`前加两行

```python3
if 'Transfer-Encoding' in headers:
    headers.pop('Transfer-Encoding')
```

### 注意

python 版本的机器如果无法正常访问 github.io 会启动报错，请自行修改静态文件 url

python 版本默认走服务器（2021.3.27 更新）

## Cloudflare Workers 计费

到 `overview` 页面可参看使用情况。免费版每天有 10 万次免费请求，并且有每分钟 1000 次请求的限制。

如果不够用，可升级到 $5 的高级版本，每月可用 1000 万次请求（超出部分 $0.5/百万次请求）。

## Changelog

- 2020.04.10 增加对`raw.githubusercontent.com`文件的支持
- 2020.04.09 增加 Python 版本（使用 Flask）
- 2020.03.23 新增了 clone 的支持
- 2020.03.22 初始版本

## 链接

[我的博客](https://hunsh.net)

## 参考

[jsproxy](https://github.com/EtherDream/jsproxy/)

## 捐赠

![wx.png](https://img.maocdn.cn/img/2021/04/24/image.md.png)
![ali.png](https://www.helloimg.com/images/2021/04/24/BK9vmb.md.png)
