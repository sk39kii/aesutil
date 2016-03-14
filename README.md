# aesutil
PythonでAES(CBC)暗号化

## 前準備
```python
pip install docopt
pip install PyCrypto
pip install chardet
```

## 使い方

```
使用方法:
    aesutil.py [-d <FileOrString>][-o <Output>][-b]
    aesutil.py [-e <FileOrString>][-o <Output>][-b]
    aesutil.py [-h]
    aesutil.py [-v]

オプション:
    -d --decrypto    復号化を実行.
    -e --encrypto    暗号化を実行.
    -o --output      結果の出力先ファイル(未指定時は標準出力).
    -b --binary      復号化時：バイナリでファイル出力. 暗号化時：バイナリでファイル読込み.
    -h --help        使い方(ヘルプ)の表示.
    -v --version     バージョン表示.
```

### 例1:テキストファイル(abc.txt)を暗号化しファイル出力
暗号化
```
$ python aesutil.py -e abc.txt -o abc_en.txt
Enter pass phrase :
```

復号化
```
$ python aesutil.py -d abc_en.txt -o abc_de.txt
Enter pass phrase :
```

### 例2:文字列を暗号化(画面に表示)
暗号化
```
$ python aesutil.py -e abcdefg
Enter pass phrase :
YvsScYUfbBrMnbwVgWc-Y5oLYykm7ZUiMxQvYcPWuLQ=
```
復号化
```
$ python aesutil.py -d YvsScYUfbBrMnbwVgWc-Y5oLYykm7ZUiMxQvYcPWuLQ=
Enter pass phrase :
abcdefg
```
