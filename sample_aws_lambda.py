import boto3
import json

def lambda_handler(event, context):
    # Initialize AWS clients
    s3_client = boto3.client('s3')
    dynamodb = boto3.resource('dynamodb')
    
    # S3 operations
    bucket_name = 'my-app-bucket'
    s3_client.list_objects_v2(Bucket=bucket_name)
    s3_client.get_object(Bucket=bucket_name, Key='data.json')
    s3_client.put_object(Bucket=bucket_name, Key='output.json', Body=json.dumps({'result': 'success'}))
    
    # DynamoDB operations
    table = dynamodb.Table('user-data')
    table.get_item(Key={'user_id': '123'})
    table.put_item(Item={'user_id': '123', 'name': 'John Doe'})
    
    return {
        'statusCode': 200,
        'body': json.dumps('Success')
    }