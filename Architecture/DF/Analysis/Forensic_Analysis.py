import boto3
import logging
import hashlib
import json
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)

def generate_hash(file_content):
    hasher = hashlib.sha256()
    hasher.update(file_content)
    return hasher.hexdigest()

def download_file_content(s3_client, bucket, file_key):
    response = s3_client.get_object(Bucket=bucket, Key=file_key)
    file_content = response['Body'].read()
    return file_content

def analyze_file(file_content, file_type, file_path, start_time=None, end_time=None):
    analysis_results = []
    lines = file_content.decode('utf-8').splitlines()
    for line in lines:
        line_str = ','.join(line.split(','))
        if file_type == 'non_volatile':
            if 'disk_usage.csv' in file_path:
                if any(keyword in line_str.lower() for keyword in ["new", "delete", "access"]):
                    analysis_results.append(f"Suspicious file activity: {line_str}")
            elif 'shadow.csv' in file_path:
                if any(keyword in line_str.lower() for keyword in ["new", "modify"]):
                    analysis_results.append(f"Suspicious account activity: {line_str}")
            elif 'bash_history.csv' in file_path:
                if any(keyword in line_str.lower() for keyword in ["rm", "chmod", "chown"]):
                    analysis_results.append(f"Suspicious command history: {line_str}")
            elif 'open_files.csv' in file_path:
                if any(keyword in line_str.lower() for keyword in ["delete", "access"]):
                    analysis_results.append(f"Suspicious file operation: {line_str}")
            elif 'group.csv' in file_path:
                if any(keyword in line_str.lower() for keyword in ["new", "modify"]):
                    analysis_results.append(f"Suspicious group change: {line_str}")
            elif 'passwd.csv' in file_path:
                if any(keyword in line_str.lower() for keyword in ["new", "modify"]):
                    analysis_results.append(f"Suspicious user change: {line_str}")
            elif 'sshd_config.csv' in file_path:
                if any(keyword in line_str.lower() for keyword in ["permitrootlogin", "passwordauthentication"]):
                    analysis_results.append(f"Suspicious SSH config change: {line_str}")
            else:
                analysis_results.append(line_str)
        elif file_type == 'http_logs':
            timestamp_str = line.split(' ')[3][1:]  # Assuming the timestamp is in the fourth element and formatted like [10/Jul/2024:11:15:45 +0000]
            try:
                log_timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
                log_timestamp = log_timestamp.replace(tzinfo=None)  # Remove timezone info for comparison
                if start_time <= log_timestamp <= end_time:
                    if any(keyword in line_str.lower() for keyword in ["error", "failed", "unauthorized", "unknown", "timeout"]):
                        analysis_results.append(f"Suspicious log entry: {line_str}")
            except ValueError:
                continue
    return analysis_results

def download_and_analyze(s3_client, bucket, file_key, file_type, start_time=None, end_time=None):
    original_content = download_file_content(s3_client, bucket, file_key)
    
    # 다운로드한 후 해시 계산
    original_hash = generate_hash(original_content)

    # 파일 분석
    analysis_results = analyze_file(original_content, file_type, file_key, start_time, end_time)
    
    # 분석 후 해시값 검증
    final_hash = generate_hash(original_content)
    if original_hash != final_hash:
        raise Exception(f"Hash mismatch after analysis for file: {file_key}")

    return analysis_results

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    source_bucket = 'forensic-collect-bucket'
    analysis_bucket = 'forensic-result-bucket'
    
    instance_id = event.get('instance_id')
    timestamp = event.get('timestamp')
    s3_key = event.get('s3_key')
    
    if not all([instance_id, timestamp, s3_key]):
        return {
            'statusCode': 400,
            'body': 'Required parameters are missing'
        }

    try:
        timestamp_dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return {
            'statusCode': 400,
            'body': 'Invalid timestamp format'
        }
    
    start_time = timestamp_dt - timedelta(hours=6)
    end_time = timestamp_dt + timedelta(hours=6)
    
    files = {
        'non_volatile': [
            'analysis_results/bash_history.csv',
            'analysis_results/disk_usage.csv',
            'analysis_results/group.csv',
            'analysis_results/open_files.csv',
            'analysis_results/passwd.csv',
            'analysis_results/shadow.csv',
            'analysis_results/sshd_config.csv'
        ],
        'http_logs': [
            'analysis_results/httpd_access_log.csv',
            'analysis_results/httpd_error_log.csv'
        ]
    }
    
    results = {
        'non_volatile': [],
        'http_logs': []
    }
    
    for file_type in ['non_volatile', 'http_logs']:
        for file_name in files[file_type]:
            file_key = f'{s3_key}/{file_name}'
            try:
                analysis_results = download_and_analyze(s3, source_bucket, file_key, file_type, start_time, end_time)
                results[file_type].extend(analysis_results)
            except Exception as e:
                logging.error(f"Error processing {file_key}: {e}")
    
    # 분석 결과 정렬
    def extract_timestamp(line):
        try:
            return datetime.strptime(line.split(' ', 1)[0], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.min

    results['non_volatile'].sort(key=extract_timestamp)
    results['http_logs'].sort(key=extract_timestamp)
    
    # 분석 결과를 JSON 형식으로 S3에 저장
    results_json = json.dumps(results, indent=4)
    s3.put_object(Bucket=analysis_bucket, Key=f'{s3_key}/forensic_results.json', Body=results_json)
    
    final_key = f"{instance_id}/{timestamp}"    
    
    return {
        'statusCode': 200,
        'body': 'Forensic results saved to S3',
        'final_key': final_key
    }
