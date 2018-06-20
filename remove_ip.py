# coding: UTF-8

# 使用方法 : python block_ip [IPアドレス] [NETWORKACLID] [ACLルールの最大値]

import boto3
import sys
import mysql.connector
import time

##### データベース関連変数(各環境に合わせて変更してください)######
DBUSER          =   "user"
DBPASS          =   "password"
DBNAME          =   "attackblock"
TABLENAME      =    "acltable"

#####その他変数(変更の必要はございません」)##########
argvs           =   sys.argv
ec2_client      =   boto3.client('ec2')
IPADDR          =   argvs[1]
NETWORKACLID    =   argvs[2]
MAXNUMBER       =   argvs[3]


# 機能 : ACLで設定されている最小値のNoを取得する
RESULT = False
try:
    describeacl = ec2_client.describe_network_acls(
        DryRun=False,
        NetworkAclIds=[
            NETWORKACLID,
        ]
    )
    RESULT = True

except Exception as e:
    import traceback
    traceback.print_exc()
    print('Faild to get ACL Information')
    RESULT = False

if(RESULT == True):
    RuleNumber_list =[]
    for acl in describeacl['NetworkAcls']:
        for cidrblock in acl['Entries']:
            if cidrblock['Egress'] == False:
                RuleNumber_list.append(cidrblock['RuleNumber'])

    # 機能 : ACLの番号の最小値が85であれば85から99の間のACLを削除して、100番のみをセットする
    if min(RuleNumber_list) == int(MAXNUMBER) - 8 :
      for rulenum in range(int(MAXNUMBER)-8 , int(MAXNUMBER)):
        try:
          ec2_client.delete_network_acl_entry(
              DryRun=False,
              Egress=False,
              NetworkAclId=NETWORKACLID,
              RuleNumber= rulenum
          )
          RESULT = True
        except Exception as e:
          import traceback
          traceback.print_exc()
          RESULT = False
      RuleNumber_list =[int(MAXNUMBER)]

# 機能 : ACLにIPアドレスを登録する(ブロック登録)
if(RESULT == True):
    try:
        MINNUM = min(RuleNumber_list)-1
        ec2_client.create_network_acl_entry(
            CidrBlock=IPADDR+"/32",
            DryRun=False,
            Egress=False,
            NetworkAclId=NETWORKACLID,
            Protocol='-1',
            RuleAction='deny',
            RuleNumber=MINNUM
      )
        print('Add IP Address to ACL')
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('Failed to add IP Address to ACL')

# 機能 : DBにIPアドレスを登録する(ブロック登録)
if(RESULT == True):
    try:
      now_time = time.time()
      jst_now= int(now_time)

      dbconnect = mysql.connector.connect(user=DBUSER, password=DBPASS, host='localhost', port='3306',database=DBNAME)
      cur = dbconnect.cursor()
      insert_data = "INSERT INTO " +DBNAME+"."+TABLENAME+ " (blockip, blockaclno, created) VALUES ('" +IPADDR+ "'," + str(MINNUM)+ ",'"+ str(jst_now)+ "');"

      cur.execute(insert_data)
      dbconnect.commit()
      cur.close
      dbconnect.close
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('Failed to add Database')







