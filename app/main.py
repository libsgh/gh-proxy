# -*- coding: utf-8 -*-
import re

import requests
from flask import Flask, render_template, Response, redirect, request, send_from_directory
from requests.exceptions import (
    ChunkedEncodingError,
    ContentDecodingError, ConnectionError, StreamConsumedError)
from requests.utils import (
    stream_decode_response_unicode, iter_slices, CaseInsensitiveDict)
from urllib3.exceptions import (
    DecodeError, ReadTimeoutError, ProtocolError)
from datetime import datetime
from diskcache import Cache
from urllib.parse import quote
import os

# config
# 分支文件使用jsDelivr镜像的开关，0为关闭，默认关闭
jsdelivr = int(os.environ.get('JSDELIVR', 0))
size_limit = int(os.environ.get('SIZE_LIMIT', 1024 * 1024 * 1024 * 999))  # 允许的文件大小，默认999GB，相当于无限制了 https://github.com/hunshcn/gh-proxy/issues/8

"""
  先生效白名单再匹配黑名单，pass_list匹配到的会直接302到jsdelivr而忽略设置
  生效顺序 白->黑->pass，可以前往https://github.com/hunshcn/gh-proxy/issues/41 查看示例
  每个规则一行，可以封禁某个用户的所有仓库，也可以封禁某个用户的特定仓库，下方用黑名单示例，白名单同理
  user1 # 封禁user1的所有仓库
  user1/repo1 # 封禁user1的repo1
  */repo1 # 封禁所有叫做repo1的仓库
"""
white_list = str(os.environ.get('WHITE_LIST', '''
'''))
black_list = str(os.environ.get('BLACK_LIST', '''
'''))
pass_list = str(os.environ.get('PASS_LIST', '''
'''))

HOST = str(os.environ.get('HOST', '127.0.0.1'))  # 监听地址，建议监听本地然后由web服务器反代
PORT = int(os.environ.get('PORT', 80))  # 监听端口
#ASSET_URL = 'https://hunshcn.github.io/gh-proxy'  # 主页

white_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in white_list.split('\n') if i]
black_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in black_list.split('\n') if i]
pass_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in pass_list.split('\n') if i]
app = Flask(__name__, static_folder='static')
CHUNK_SIZE = 1024 * 10
# index_html = requests.get(ASSET_URL, timeout=10).text
# icon_r = requests.get(ASSET_URL + '/favicon.ico', timeout=10).content
exp1 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$')
exp2 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$')
exp3 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$')
exp4 = re.compile(r'^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$')
exp5 = re.compile(r'^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$')
exp6 = re.compile(r'^(?:https?://)?git\.io/.*$')
exp7 = re.compile(r'^(?:https?://)?api\.github\.com/.*$')
# 简单统计：代理请求次数
cache = Cache('/app/data')

requests.sessions.default_headers = lambda: CaseInsensitiveDict()


@app.route('/')
def index():
    if 'q' in request.args:
        return redirect('/' + request.args.get('q'))
    format_traffic = format_bytes(int(cache.get('proxy_traffic') or 0))
    current_year = datetime.now().year
    return render_template('index.html', current_year=current_year, proxy_count=int(cache.get('proxy_count') or 0), format_traffic=format_traffic)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder,
                               'favicon.png', mimetype='image/vnd.microsoft.icon')


def iter_content(self, chunk_size=1, decode_unicode=False):
    """rewrite requests function, set decode_content with False"""

    def generate():
        # Special case for urllib3.
        if hasattr(self.raw, 'stream'):
            try:
                for chunk in self.raw.stream(chunk_size, decode_content=False):
                    yield chunk
            except ProtocolError as e:
                raise ChunkedEncodingError(e)
            except DecodeError as e:
                raise ContentDecodingError(e)
            except ReadTimeoutError as e:
                raise ConnectionError(e)
        else:
            # Standard file-like object.
            while True:
                chunk = self.raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk

        self._content_consumed = True

    if self._content_consumed and isinstance(self._content, bool):
        raise StreamConsumedError()
    elif chunk_size is not None and not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an int, it is instead a %s." % type(chunk_size))
    # simulate reading small chunks of the content
    reused_chunks = iter_slices(self._content, chunk_size)

    stream_chunks = generate()

    chunks = reused_chunks if self._content_consumed else stream_chunks

    if decode_unicode:
        chunks = stream_decode_response_unicode(chunks, self)

    return chunks


def check_url(u):
    for exp in (exp1, exp2, exp3, exp4, exp5, exp6, exp7):
        m = exp.match(u)
        if m:
            return m
    return False

@app.route('/github/<path:u>', methods=['GET', 'POST'])
def g_handler(u):
    u =  'https://github.com/' + u
    return handler(u)

@app.route('/raw/<path:u>', methods=['GET', 'POST'])
def raw_handler(u):
    u =  'https://raw.githubusercontent.com/' + u
    return handler(u)

@app.route('/gist/<path:u>', methods=['GET', 'POST'])
def gist_handler(u):
    u =  'https://gist.githubusercontent.com/' + u
    return handler(u)


@app.route('/<path:u>', methods=['GET', 'POST'])
def handler(u):
    u = quote(u, safe='/:')
    u = u if u.startswith('http') else 'https://' + u
    if u.rfind('://', 3, 9) == -1:
        u = u.replace('s:/', 's://', 1)  # uwsgi会将//传递为/
    pass_by = False
    m = check_url(u)
    if m:
        m = tuple(m.groups())
        if white_list:
            for i in white_list:
                if m[:len(i)] == i or i[0] == '*' and len(m) == 2 and m[1] == i[1]:
                    break
            else:
                return Response('Forbidden by white list.', status=403)
        for i in black_list:
            if m[:len(i)] == i or i[0] == '*' and len(m) == 2 and m[1] == i[1]:
                return Response('Forbidden by black list.', status=403)
        for i in pass_list:
            if m[:len(i)] == i or i[0] == '*' and len(m) == 2 and m[1] == i[1]:
                pass_by = True
                break
    else:
        return Response('Invalid input.', status=403)

    if (jsdelivr or pass_by) and exp2.match(u):
        u = u.replace('/blob/', '@', 1).replace('github.com', 'cdn.jsdelivr.net/gh', 1)
        return redirect(u)
    elif (jsdelivr or pass_by) and exp4.match(u):
        u = re.sub(r'(\.com/.*?/.+?)/(.+?/)', r'\1@\2', u, 1)
        _u = u.replace('raw.githubusercontent.com', 'cdn.jsdelivr.net/gh', 1)
        u = u.replace('raw.github.com', 'cdn.jsdelivr.net/gh', 1) if _u == u else _u
        return redirect(u)
    else:
        if exp2.match(u):
            u = u.replace('/blob/', '/raw/', 1)
        if pass_by:
            url = u + request.url.replace(request.base_url, '', 1)
            if url.startswith('https:/') and not url.startswith('https://'):
                url = 'https://' + url[7:]
            return redirect(url)
        return proxy(u)
@app.after_request
def remove_content_security_policy(response):
    response.headers.pop('Content-Security-Policy', None)
    return response
def proxy(u, allow_redirects=False):
    headers = {}
    r_headers = dict(request.headers)
    if 'Host' in r_headers:
        r_headers.pop('Host')
    try:
        url = u + request.url.replace(request.base_url, '', 1)
        if url.startswith('https:/') and not url.startswith('https://'):
            url = 'https://' + url[7:]
        r = requests.request(method=request.method, url=url, data=request.data, headers=r_headers, stream=True, allow_redirects=allow_redirects)
        headers = dict(r.headers)
        content_length = 0
        if 'Content-length' in r.headers:
            content_length = int(r.headers['Content-length'])
        if 'Content-length' in r.headers and content_length > size_limit:
            return redirect(u + request.url.replace(request.base_url, '', 1))
        def generate():
            total_size = 0
            for chunk in iter_content(r, chunk_size=CHUNK_SIZE):
                total_size += len(chunk)
                yield chunk
            cache.set('proxy_traffic', int(cache.get('proxy_traffic') or 0) + total_size)
        if 'Location' in r.headers:
            _location = r.headers.get('Location')
            if check_url(_location):
                headers['Location'] = '/' + _location
            else:
                return proxy(_location, True)
        cache.set('proxy_count', int(cache.get('proxy_count') or 0) + 1)
        b = generate()
        return Response(b, headers=headers, status=r.status_code)
    except Exception as e:
        headers['content-type'] = 'text/html; charset=UTF-8'
        return Response('server error ' + str(e), status=500, headers=headers)
def format_bytes(size):
    power = 2**10
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"
app.debug = True
if __name__ == '__main__':
    cache.set('proxy_count', 0)
    cache.set('proxy_traffic', 0)
    app.run(host=HOST, port=PORT)
