# coding: UTF-8

# 使用方法 : python block_ip [NETWORKACLID] [現在設定しているACLルールの最大値]
## python block_ip.py acl-7eadf419 100

import boto3
import sys
import mysql.connector
import time
from collections import Counter

##### 不正アクセス条件(各環境に合わせて変更してください) ######
TIMESTAMP = "600"          ##    何秒おきのログを調査するか
BLOCKWORD = "wp-login.php"  ##    監視対象ファイル
ATNUM  = "5"                ##    不正アクセスと検知する回数

##### Zabbixデータベース関連変数(各環境に合わせて変更してください) ######
DBUSER          =   "root"
DBPASS          =   ""

#####その他変数(変更の必要はございません」) ##########
argvs           =   sys.argv
client = boto3.client('ec2')
NETWORKACLID    =   argvs[1]
MAXNUMBER       =   argvs[2]



# 機能 : DBから(設定した)不正アクセス数の最大値を超えるIPアドレスを返す
def listing_ip():
    EndTime = int(time.time())
    StartTime =  EndTime - int(TIMESTAMP)

    conn = mysql.connector.connect(user=DBUSER, password=DBPASS, host='localhost', database='zabbix')
    cur = conn.cursor()

    cur.execute("SELECT * FROM history_log  WHERE clock BETWEEN " +str(StartTime)+ " AND " +str(EndTime)+ ";")

    cur.close
    conn.close

    ip_list = []
    for access_log in cur.fetchall():
       log_list = access_log[6].split(" ")
       ip_list.append(log_list[0])
    counter = Counter(ip_list)

    ips_list = []
    for ip,cnt in counter.most_common():
      if(cnt >= int(ATNUM)):
        ips_list.append(ip)

    reg_ip = ips_list[0]
    return reg_ip

# 機能 : ACLで設定されている現行の最小値から1引いたNoを返す
def get_min_acl_no():
    try:
      describeacl = client.describe_network_acls(
          DryRun=False,
          NetworkAclIds=[
              NETWORKACLID,
          ]
      )
    except Exception as e:
      import traceback
      traceback.print_exc()
      print('Faild to get ACL Information')

    RuleNumber_list = []
    for acl in describeacl['NetworkAcls']:
      for cidrblock in acl['Entries']:
          if cidrblock['Egress'] == False:
              RuleNumber_list.append(cidrblock['RuleNumber'])
      # 機能 : ACLの番号の最小値が例として100(MAXNUMBERで設定)であれば85から99の間のACLを削除して、100番のみをセットする

    if min(RuleNumber_list) == int(MAXNUMBER) - 8 :
      for rulenum in range(int(MAXNUMBER)-8 , int(MAXNUMBER)):
        try:
          client.delete_network_acl_entry(
              DryRun=False,
              Egress=False,
              NetworkAclId=NETWORKACLID,
              RuleNumber= rulenum
          )
        except Exception as e:
          import traceback
          traceback.print_exc()
    #ACLの最小値
    RuleNumber = min(RuleNumber_list)-1
    return RuleNumber


# 機能 : ACLにIPアドレスを登録する(ブロック登録) ここから未検証
def register_acl(reg_ip,RuleNumber):
    try:
       # Rule Noの最小値
        # MINNUM = min(RuleNumber_list)-1
        client.create_network_acl_entry(
            CidrBlock=reg_ip+"/32",
            DryRun=False,
            Egress=False,
            NetworkAclId=NETWORKACLID,
            Protocol='-1',
            RuleAction='deny',
            RuleNumber=RuleNumber
      )
        print('Add IP Address to ACL')
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('Failed to add IP Address to ACL')

def register_rule_main():
    register_acl(listing_ip(),get_min_acl_no())

if __name__ == '__main__':
    register_rule_main()