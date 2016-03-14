# -*- coding: utf-8 -*-
"""aesutil

Usage:
    aesutil.py [-d <FileOrString>][-o <Output>][-b]
    aesutil.py [-e <FileOrString>][-o <Output>][-b]
    aesutil.py [-h]
    aesutil.py [-v]

Options:
    -d --decrypto    Execute deCrypto.
    -e --encrypto    Execute enCrypto.
    -o --output      Output File. If not specified, the screen output.
    -b --binary      deCrypot: Binary Wirte. enCrypto: Binary Read.
    -h --help        Show this help message and exit.
    -v --version     Show version.

Memo:
    To run the aesutil.py to docopt,PyCrypto,chardet needs.
    pip install docopt
    pip install PyCrypto
    pip install chardet
"""
__version__ = '0.0.2'
__status__ = 'production'
__date__ = '14 March 2016'
__author__ = 'sk39kii <sk39kii@gmail.com>'

from Crypto.Cipher import AES
import base64
import chardet
from docopt import docopt
from getpass import getpass
import hashlib
import mimetypes
import os.path
from Crypto import Random


# AES ブロック暗号
# 鍵長:16, 24, 32byte
# 暗号化対象:16byteの倍数
class AESUtil(object):

    def __init__(self, mode=AES.MODE_CBC):
        u"""初期化
        """
        # パスフレーズのハッシュ化
        self.keyhash = lambda k: hashlib.sha256(k).digest()
        # ブロックサイズは16byte
        self.bs = 16
        self.pad = lambda s: s + \
            (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
        self.unpad = lambda s: s[:-ord( s[len(s)-1:] )]
        self.mode = mode
        self.output = ''
        self.binary = False

    def enc_data(self, nomal_data, passwd):
        u"""データ暗号化
        """
        # 暗号化対象:16byteの倍数
        raw = self.pad(nomal_data)
        # 初期化ベクトル(16)
        iv = Random.new().read( AES.block_size )
        # 暗号化
        key = self.keyhash(passwd)
        cipher = AES.new(key, self.mode, iv)
        encrypt_data = cipher.encrypt(raw)
        # BASE64エンコード
        return self.base64Enc( iv + encrypt_data )

    def dec_data(self, encrypt_data, passwd):
        u"""データ複合化
        """
        # BASE64のデコード
        base64data = self.base64Dec(encrypt_data)
        # 初期化ベクトルを取得
        iv = base64data[:self.bs]
        # 復号化
        key = self.keyhash(passwd)
        cipher = AES.new(key, self.mode, iv )
        decrypt_data = cipher.decrypt( base64data[self.bs:] )
        return self.unpad(decrypt_data)

    def base64Enc(self, buf):
        u"""base64エンコード変換(urlsafe)
        """
        return base64.urlsafe_b64encode(buf)

    def base64Dec(self, buf):
        u"""base64デコード変換(urlsafe)
        """
        return base64.urlsafe_b64decode(buf)

    def readdump(self, dumpname, mode='r'):
        u"""ファイルの読み込み
        """
        buf = ''
        with open(dumpname, mode) as f:
            buf = f.read()
        return buf

    def writedump(self, buf, dumpname, mode='w'):
        u"""ファイルに書き込み
        """
        with open(dumpname, mode) as f:
            f.write(buf)

    def isBinary(self, target):
        u"""バイナリファイル判定
        """
        ret = False
        m = mimetypes.guess_type(target)[0]
        if m is None:
            # MIMEで判別不能時は中身確認
            encode = chardet.detect(self.readdump(target, 'rb'))['encoding']
            if encode is None:
                # 中身も不明時はバイナリとする
                ret = True
        elif m.find('office') > -1:
            ret = True
        elif m.startswith('image'):
            ret = True
        elif m.startswith('text'):
            ret = False
        elif m.startswith('application/vnd.ms-excel'):
            # これはCSV
            ret = False
        return ret

    def enc_file(self, nomal_file, passwd):
        u"""ファイル暗号化
        """
        # 暗号化する時はオプション指定なしでも対象ファイルがバイナリがどうか判定する
        # Unix系ではバイナリ/テキストの区別しないが、
        # Windows上で動くPythonはテキストファイルとバイナリファイルを区別するので、
        # バイナリファイルを通常(テキスト)モードで読み込むとデータがおかしくなる？
        # 念のためオプション指定無しでもバイナリファイル判定する。
        mode = 'r'
        if self.binary or self.isBinary(nomal_file):
            mode = 'rb'
        return self.enc_data(self.readdump(nomal_file, mode), passwd)

    def dec_file(self, crypto_file, passwd):
        u"""ファイル復号化
        """
        # 暗号化したファイルの読込みはbase64形式なのでバイナリ判定はしない
        return self.dec_data(self.readdump(crypto_file), passwd)

    def input_pass(self):
        u"""標準入力からパスワード取得
        """
        # return raw_input('Enter pass phrase : ')
        # 入力内容を非表示
        return getpass('Enter pass phrase : ')

    def enc(self, target):
        u"""暗号化開始
        """
        passwd = self.input_pass()
        if os.path.exists(target):
            return self.enc_file(target, passwd)
        else:
            return self.enc_data(target, passwd)

    def dec(self, target):
        u"""復号化開始
        """
        passwd = self.input_pass()
        if os.path.exists(target):
            return self.dec_file(target, passwd)
        else:
            return self.dec_data(target, passwd)

    def outResult(self, result):
        u"""結果出力(オプションによって出力先を変更)
        """
        if self.output == '':
            print result,
        else:
            # ファイル書込み時はバイナリオプションを見て出力
            mode = 'w'
            if self.binary:
                mode = 'wb'
            self.writedump(result, self.output, mode)

    def cmdline_parser(self, args):
        u"""コマンドラインパラメータ(オプション)の解析
        """
        # バイナリオプションあり
        if args.get('--binary'):
            self.binary = True

        # 出力先指定あり
        if args.get('--output'):
            self.output = args.get('<Output>')

        if args.get('--encrypto'):
            self.outResult(self.enc(args.get('<FileOrString>')))
        elif args.get('--decrypto'):
            self.outResult(self.dec(args.get('<FileOrString>')))
        else:
            print __doc__

    def start(self):
        args = docopt(__doc__, version=__version__)
        self.cmdline_parser(args)


def main():
    aesutil = AESUtil()
    aesutil.start()

if __name__ == "__main__":
    main()
