# -*- coding: utf-8 -*-
import argparse
import json
import re
import shlex
from collections import OrderedDict, namedtuple

from six.moves import http_cookies as Cookie

parser = argparse.ArgumentParser()
parser.add_argument('command')
parser.add_argument('url')
parser.add_argument('-d', '--data', '--data-urlencode')
parser.add_argument('-b', '--data-binary', '--data-raw', default=None)
parser.add_argument('-X', default='')
parser.add_argument('-H', '--header', action='append', default=[])
parser.add_argument('--compressed', action='store_true')
parser.add_argument('-k', '--insecure', action='store_true')
parser.add_argument('--user', '-u', default=())
parser.add_argument('-i', '--include', action='store_true')
parser.add_argument('-s', '--silent', action='store_true')
parser.add_argument('-x', '--proxy', default={})
parser.add_argument('-U', '--proxy-user', default='')

BASE_INDENT = " " * 4

ParsedContext = namedtuple('ParsedContext', ['method', 'url', 'data', 'headers', 'cookies', 'verify', 'auth', 'proxy'])


def normalize_newlines(multiline_text):
    return multiline_text.replace(" \\\n", " ").replace("\\ ", " ")


def get_args(curl_command: str):
    tokens = shlex.split(normalize_newlines(curl_command))
    tokens_length = len(tokens)
    if tokens_length == 0:
        return tokens

    # first_arg_index = next((i for i, token in enumerate(tokens) if token.startswith("-")), None)

    arg_name_index = [index for index, token in enumerate(tokens) if token.startswith("-")]
    fix_tokens = []

    index = 0
    while True:
        token = try_get(index, tokens)
        if token is None:
            break
        if index not in arg_name_index:
            fix_tokens.append(token)
            index = index + 1
        else:
            fix_tokens.append(token)
            # 此时 应一直往下去 ，直到 结尾或者取到下一个 以 - 开头的，中间的部分都应拼接起来作为上一个的arg
            index = index + 1
            arg, index = try_get_arg(index, tokens)
            fix_tokens.append(arg)
    return fix_tokens


def has_next(index, length):
    return index + 1 < length


def try_get(index, tokens: list):
    if index >= len(tokens):
        return None
    else:
        return tokens[index]


def try_get_arg(index, tokens):
    args = []
    while True:
        arg = try_get(index, tokens)
        if arg is None or arg.startswith("-"):
            break
        else:
            args.append(arg)
            index = index + 1
    return "".join(args), index


def parse_context(curl_command: str):
    method = "get"
    tokens = get_args(curl_command)
    parsed_args = []
    try:
        parsed_args = parser.parse_args(tokens)
    except Exception as e:
        curl_command = ''.join(
            f" {token} " if token.startswith("-") else f'"{token.strip()}"' for token in tokens).strip()
        tokens = get_args(curl_command)
        parsed_args = parser.parse_args(tokens)

    post_data = parsed_args.data or parsed_args.data_binary
    if post_data:
        method = 'post'
        try:
            post_data = json.loads(post_data)
        except Exception as e:
            post_data = __get_request_data(curl_command)
            if post_data is None:
                post_data = parsed_args.data or parsed_args.data_binary

    if parsed_args.X:
        method = parsed_args.X.lower()

    cookie_dict = OrderedDict()
    quoted_headers = OrderedDict()

    for curl_header in parsed_args.header:
        if curl_header.startswith(':'):
            occurrence = [m.start() for m in re.finditer(':', curl_header)]
            header_key, header_value = curl_header[:occurrence[1]], curl_header[occurrence[1] + 1:]
        else:
            header_key, header_value = curl_header.split(":", 1)

        if header_key.lower().strip("$") == 'cookie':
            cookie = Cookie.SimpleCookie(bytes(header_value, "ascii").decode("unicode-escape"))
            for key in cookie:
                cookie_dict[key] = cookie[key].value
        else:
            quoted_headers[header_key] = header_value.strip()

    # add auth
    user = parsed_args.user
    if parsed_args.user:
        user = tuple(user.split(':'))

    # add proxy and its authentication if it's available.
    proxies = parsed_args.proxy
    # proxy_auth = parsed_args.proxy_user
    if parsed_args.proxy and parsed_args.proxy_user:
        proxies = {
            "http": "http://{}@{}/".format(parsed_args.proxy_user, parsed_args.proxy),
            "https": "http://{}@{}/".format(parsed_args.proxy_user, parsed_args.proxy),
        }
    elif parsed_args.proxy:
        proxies = {
            "http": "http://{}/".format(parsed_args.proxy),
            "https": "http://{}/".format(parsed_args.proxy),
        }

    return ParsedContext(
        method=method,
        url=parsed_args.url,
        data=post_data,
        headers=quoted_headers,
        cookies=cookie_dict,
        verify=parsed_args.insecure,
        auth=user,
        proxy=proxies,
    )


def parse(curl_command, **kargs):
    parsed_context = parse_context(curl_command)

    data_token = ''
    if parsed_context.data:
        data_token = '{}data=\'{}\',\n'.format(BASE_INDENT, parsed_context.data)

    verify_token = ''
    if parsed_context.verify:
        verify_token = '\n{}verify=False'.format(BASE_INDENT)

    requests_kargs = ''
    for k, v in sorted(kargs.items()):
        requests_kargs += "{}{}={},\n".format(BASE_INDENT, k, str(v))

    # auth_data = f'{BASE_INDENT}auth={parsed_context.auth}'
    auth_data = "{}auth={}".format(BASE_INDENT, parsed_context.auth)
    proxy_data = "\n{}proxies={}".format(BASE_INDENT, parsed_context.proxy)

    formatter = {
        'method': parsed_context.method,
        'url': parsed_context.url,
        'data_token': data_token,
        'headers_token': "{}headers={}".format(BASE_INDENT, dict_to_pretty_string(parsed_context.headers)),
        'cookies_token': "{}cookies={}".format(BASE_INDENT, dict_to_pretty_string(parsed_context.cookies)),
        'security_token': verify_token,
        'requests_kargs': requests_kargs,
        'auth': auth_data,
        'proxies': proxy_data
    }

    return """requests.{method}("{url}",
{requests_kargs}{data_token}{headers_token},
{cookies_token},
{auth},{proxies},{security_token}
)""".format(**formatter)


def __get_request_data(curl_command: str):
    data = ""
    for temp in curl_command.split(" -"):
        temp = str(temp)
        if temp.startswith("-data-binary "):
            data = temp.replace("-data-binary ", "")
            break
        if temp.startswith("b "):
            data = temp.replace("b ", "")
            break
        if temp.startswith("-data-raw "):
            data = temp.replace("-data-raw ", "")
            break
    try:
        if len(data) > 0:
            return json.loads(data[1:len(data) - 1])
        else:
            return None
    except Exception as e:
        return None


def dict_to_pretty_string(the_dict, indent=4):
    if not the_dict:
        return "{}"

    return ("\n" + " " * indent).join(
        json.dumps(the_dict, sort_keys=True, indent=indent, separators=(',', ': ')).splitlines())
