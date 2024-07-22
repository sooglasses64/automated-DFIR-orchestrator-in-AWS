import boto3
import time
import logging

logging.basicConfig(level=logging.INFO)

def execute_command_and_wait(ssm, instance_id, command, timeout=600):
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [command]},
            TimeoutSeconds=timeout
        )
        command_id = response['Command']['CommandId']

        waiter = ssm.get_waiter('command_executed')
        waiter.wait(
            CommandId=command_id,
            InstanceId=instance_id,
            WaiterConfig={
                'Delay': 30,
                'MaxAttempts': 20  # Timeout of 10 minutes in total
            }
        )

        output = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )

        if output['Status'] != 'Success':
            logging.error(f"Command failed with status: {output['Status']}")
            logging.error(f"Error output: {output['StandardErrorContent']}")
            logging.error(f"Standard output: {output['StandardOutputContent']}")
            return None, output['StandardErrorContent']

        return output['StandardOutputContent'].strip(), None

    except Exception as e:
        logging.error(f"Error executing command '{command}': {e}")
        return None, str(e)

def lambda_handler(event, context):
    region = 'ap-northeast-2'
    ssm = boto3.client('ssm', region_name=region)
    s3 = boto3.client('s3', region_name=region)

    # 인스턴스 및 버킷 정보
    instance_id = event['instance_id']
    analysis_instance_id = event['analysis_instance_id']
    timestamp = event['timestamp']
    forensic_collect_bucket = 'forensic-collect-bucket'
    forensic_result_bucket = 'forensic-result-bucket'

    local_memory_dump_path = '/mnt/forensic/mem_dump.bin'

    # S3에서 원본 해시 값 다운로드
    download_hash_command = f"aws s3 cp s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/mem_dump.bin.sha256 /mnt/forensic/volatility_data/mem_dump.bin.sha256"
    result, error = execute_command_and_wait(ssm, analysis_instance_id, download_hash_command)
    if result is None:
        return {
            'statusCode': 500,
            'body': f"Command {download_hash_command} failed with error: {error}"
        }

    # 원본 해시 값 읽기
    read_hash_command = "cat /mnt/forensic/mem_dump.bin.sha256 | awk '{print $1}'"
    original_hash, error = execute_command_and_wait(ssm, analysis_instance_id, read_hash_command)
    if original_hash is None:
        return {
            'statusCode': 500,
            'body': f"Failed to read original hash with error: {error}"
        }

    # 분석 명령어 실행 및 결과 업로드
    analysis_commands = [
        "sudo mkdir -p /mnt/forensic/output",
        "sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.pslist > /mnt/forensic/output/pslist.csv'", 
        "sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.pstree.PsTree > /mnt/forensic/output/pstree.csv'",
        "sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.sockstat > /mnt/forensic/output/sockstat.csv'",
        "sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.bash > /mnt/forensic/output/bash.csv'",
        "sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.proc.Maps > /mnt/forensic/output/proc_maps.csv'",
        "sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.check_syscall.Check_syscall > /mnt/forensic/output/check_syscall.csv'",
        "sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.elfs.Elfs > /mnt/forensic/output/elfs.csv'"
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.check_afinfo.Check_afinfo > /mnt/forensic/output/check_afinfo.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.check_creds.Check_creds > /mnt/forensic/output/check_creds.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.check_idt.Check_idt > /mnt/forensic/output/check_idt.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.check_modules.Check_modules > /mnt/forensic/output/check_modules.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.iomem.IOMem > /mnt/forensic/output/iomem.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.keyboard_notifiers.Keyboard_notifiers > /mnt/forensic/output/keyboard_notifiers.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.kmsg.Kmsg > /mnt/forensic/output/kmsg.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.library_list.LibraryList > /mnt/forensic/output/library_list.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.lsmod.Lsmod > /mnt/forensic/output/lsmod.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.malfind.Malfind > /mnt/forensic/output/malnd.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.mountinfo.MountInfo > /mnt/forensic/output/mountinfo.csv'",
        #"sudo bash -c 'python3 /mnt/forensic/volatility3/vol.py -f /mnt/forensic/mem_dump.bin --renderer=csv linux.tty_check.tty_check > /mnt/forensic/output/tty_check.csv'",
    
        f"aws s3 cp /mnt/forensic/output/ s3://{forensic_result_bucket}/{instance_id}/{timestamp}/volatility_data/ --recursive"
    ]

    for command in analysis_commands:
        result, error = execute_command_and_wait(ssm, analysis_instance_id, command)
        if result is None:
            return {
                'statusCode': 500,
                'body': f"Command {command} failed with error: {error}"
            }

    # 메모리 덤프 해시 값 생성
    hash_command = f"sha256sum {local_memory_dump_path} > {local_memory_dump_path}.post.sha256"
    result, error = execute_command_and_wait(ssm, analysis_instance_id, hash_command)
    if result is None:
        return {
            'statusCode': 500,
            'body': f"Command {hash_command} failed with error: {error}"
        }

    # 해시 값 파일 S3에 업로드
    post_hash_s3_key = f"{instance_id}/{timestamp}/mem_dump.bin.post.sha256"
    upload_command = f"aws s3 cp {local_memory_dump_path}.post.sha256 s3://{forensic_result_bucket}/{post_hash_s3_key}"
    result, error = execute_command_and_wait(ssm, analysis_instance_id, upload_command)
    if result is None:
        return {
            'statusCode': 500,
            'body': f"Command {upload_command} failed with error: {error}"
        }

    # 해시 값 파일 다운로드 (SSM을 통해 EC2에서 수행)
    download_post_hash_command = f"aws s3 cp s3://{forensic_result_bucket}/{post_hash_s3_key} /mnt/forensic/mem_dump.bin.post.sha256"
    result, error = execute_command_and_wait(ssm, analysis_instance_id, download_post_hash_command)
    if result is None:
        return {
            'statusCode': 500,
            'body': f"Command {download_post_hash_command} failed with error: {error}"
        }

    # 해시 값 비교
    read_post_hash_command = "cat /mnt/forensic/mem_dump.bin.post.sha256 | awk '{print $1}'"
    post_analysis_hash, error = execute_command_and_wait(ssm, analysis_instance_id, read_post_hash_command)
    if post_analysis_hash is None:
        return {
            'statusCode': 500,
            'body': f"Failed to read post-analysis hash with error: {error}"
        }

    if original_hash == post_analysis_hash:
        file_key1 = f"{instance_id}/{timestamp}/volatility_data/"
        return {
            'statusCode': 200,
            'body': {
                'message': 'Hash values match: Data integrity verified',
                'file_key1': file_key1
            }
        }
    else:
        logging.error(f"Hash mismatch: {original_hash} (original) vs {post_analysis_hash} (current)")
        return {
            'statusCode': 500,
            'body': 'Hash mismatch: Data integrity verification failed'
        }
