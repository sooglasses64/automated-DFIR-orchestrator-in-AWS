import boto3
import gzip
import json
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
s3 = boto3.client('s3')
cloudtrail = boto3.client('cloudtrail')

def lambda_handler(event, context):
    # 이벤트에서 시간을 추출하거나 현재 시간을 설정
    event_time_str = event.get('time', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
    event_time = datetime.strptime(event_time_str, '%Y-%m-%dT%H:%M:%SZ')
    
    # 현재 시간을 기준으로 이전 30분 동안의 CloudTrail 로그 수집
    end_time = event_time
    start_time = end_time - timedelta(minutes=30)
    
    bucket_name = 'forensic-cloudtrail-bucket'
    prefix = f'filtered-logs/{end_time.strftime("%Y-%m-%d")}/'
    
    try:
        response = cloudtrail.lookup_events(
            StartTime=start_time,
            EndTime=end_time
        )
        
        # CloudTrail 이벤트를 필터링하지 않고 그대로 저장
        if response['Events']:
            # 날짜와 시간을 문자열로 변환하여 JSON 직렬화 문제 해결
            for event in response['Events']:
                if 'EventTime' in event:
                    event['EventTime'] = event['EventTime'].strftime('%Y-%m-%dT%H:%M:%SZ')
            
            log_data = {
                'Records': response['Events']
            }
            log_data_json = json.dumps(log_data, indent=2)
            s3_key = f'{prefix}{start_time.strftime("%Y-%m-%dT%H-%M-%SZ")}_to_{end_time.strftime("%Y-%m-%dT%H-%M-%SZ")}.json.gz'
            s3.put_object(
                Bucket=bucket_name,
                Key=s3_key,
                Body=gzip.compress(log_data_json.encode('utf-8'))
            )
            logging.info(f'Log saved to {s3_key}')
        else:
            logging.info('No relevant events found')
    except Exception as e:
        logging.error(f'Error processing CloudTrail logs: {e}')

    return {
        'statusCode': 200,
        'body': 'Process completed'
    }


