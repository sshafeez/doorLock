import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
import datetime

##dynamodb = boto3.client('dynamodb')
dynamodb = boto3.resource('dynamodb')
whitelistTable = dynamodb.Table('whitelist')
blacklistTable = dynamodb.Table('blacklist')
accessLogTable = dynamodb.Table('accessLog')
s3 = boto3.resource('s3')
rekognition = boto3.client('rekognition')
#---------------Helper Functions-----------------------------------------------#
def analyzeImage(source,sourcebucket,target,targetbucket):
    filename = source + '.jpg'
    targetname = target+'.jpg'
    response=rekognition.compare_faces(SimilarityThreshold=75,
                                  SourceImage={'S3Object':{'Bucket':sourcebucket,'Name':filename}},
                                  TargetImage={'S3Object':{'Bucket':targetbucket,'Name':targetname}})
    if len(response['FaceMatches']) > 0 :
        return 1
    return 0

def updateLogs(user,accessTable,time):
    accessLogTable.put_item(
    Item={
        'time': time,
        'user': user
         }
    )
    if accessTable=='whitelist':
        table = whitelistTable
    elif accessTable=='blacklist':
        table = blacklistTable
    table.update_item(
    Key={
        'username': user
    },
    UpdateExpression="set lastEntry = :date, numEntries = numEntries + :iter",
    ExpressionAttributeValues={
        ':date': time,
        ':iter': 1
    },
    ReturnValues="UPDATED_NEW"
    )

def queryRFID(tag):
    response = whitelistTable.scan(
        FilterExpression = Attr('RFID').eq(tag)
        )
    if len(response['Items'])>0:
        return (response['Items'][0]['username'])
    else:
        return 0

def matchCulprits():
    response = blacklistTable.scan(ProjectionExpression='username, lastEntry')
    response = sorted(response['Items'], key = lambda k: k['lastEntry'],reverse=True)
    i=0
    while (i<3):
        source = response[i]['username']
        if (analyzeImage(source,'blacklistedusers','test','whitelistedusers')):
            return source
        i = i+1
    return 0

def archiveCulprit(time):
    copy_source = {
    'Bucket': 'whitelistedusers',
    'Key': 'test.jpg'
    }
    intrudername = 'Intruder from '+time
    s3.meta.client.copy(copy_source, 'blacklistedusers', intrudername+'.jpg')
    blacklistTable.put_item(
    Item={
        'username': intrudername,
        'lastEntry': time,
        'numEntries': 0
         }
    )
    return intrudername
    
def deleteTest():
    s3.Object('whitelistedusers', 'test.jpg').delete()
    
#----------------------------End Helpers-----------------------------------------#
def main(time,tagID):
    print('Querying RFID')
    tagowner = queryRFID(tagID)
    if tagowner==0:
        print('Unauthorized RFID tag')
        deleteTest()
        return False
    print('Recognized RFID tag')
    usermatch = analyzeImage(tagowner,'whitelistedusers','test','whitelistedusers')
    if usermatch:
        print('User matches whitelist')
        updateLogs(tagowner,'whitelist',time)
        deleteTest()
        return True
    print('user does not match whitelist')
    culprit = matchCulprits()
    if culprit==0:
        print('new culprit detected')
        updateLogs(archiveCulprit(time),'blacklist',time)
        deleteTest()
        return False
    print('Known culprit detected')
    updateLogs(culprit,'blacklist',time)
    deleteTest()
    return False
    
    
    

def lambda_handler(event, context):
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return  main(time,'A000')

