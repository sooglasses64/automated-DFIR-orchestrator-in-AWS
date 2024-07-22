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
                'MaxAttempts': 60
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
            return None

        return output['StandardOutputContent'].strip()

    except Exception as e:
        logging.error(f"Error executing command '{command}': {e}")
        return None

def lambda_handler(event, context):
    region = 'ap-northeast-2'
    ec2 = boto3.client('ec2', region_name=region)
    ssm = boto3.client('ssm', region_name=region)
    s3 = boto3.client('s3', region_name=region)

    # 이벤트 데이터에서 인스턴스 ID 추출
    instance_id = event['detail']['resource']['instanceDetails']['instanceId']
    
    forensic_collect_bucket = 'forensic-collect-bucket'
    analysis_ami_id = 'ami-06962e66203cd554c'  
    analysis_instance_type = 'm5.xlarge'
    security_group_id = 'sg-08a7c6f0047091082'
    subnet_id = 'subnet-0dd9975ba001e5024'
    iam_instance_profile_arn = 'arn:aws:iam::654654611672:instance-profile/s3-access-profile' 
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # 침해사고 인스턴스에서 메모리 덤프 및 네트워크 캡처
    capture_commands = [
        "sudo rmmod lime",
        "insmod /mnt/forensic/LiME/src/lime-$(uname -r).ko 'path=/mnt/forensic/mem_dump.bin format=lime'", 
        "sudo timeout 10 tcpdump -i ens -c 20 -w /mnt/forensic/network_traffic.pcap",
        f"aws s3 cp /mnt/forensic/mem_dump.bin s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/mem_dump.bin", 
        f"aws s3 cp /mnt/forensic/network_traffic.pcap s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/network_traffic.pcap",
        # 해시 값 생성 및 S3에 업로드
        f"sha256sum /mnt/forensic/mem_dump.bin > /mnt/forensic/mem_dump.bin.sha256",
        f"aws s3 cp /mnt/forensic/mem_dump.bin.sha256 s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/mem_dump.bin.sha256"
    ]

    for command in capture_commands:
        try:
            result = execute_command_and_wait(ssm, instance_id, command)
            logging.debug(result)
            if result is None:
                return {
                    'statusCode': 500,
                    'body': f"Command {command} failed"
                }
        except Exception as e:
            logging.error(f'Error: {str(e)}')
            return {
                'statusCode': 500,
                'body': str(e)
            }

    # 새로운 분석 인스턴스 시작
    try:
        response = ec2.run_instances(
            ImageId=analysis_ami_id,
            InstanceType=analysis_instance_type,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[security_group_id],
            SubnetId=subnet_id,
            IamInstanceProfile={
                'Arn' : iam_instance_profile_arn
            },
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/xvda',
                    'Ebs': {
                        'VolumeSize': 64,  
                        'DeleteOnTermination': True,
                        'VolumeType': 'gp3'  
                    }
                }
            ]
        )
        analysis_instance_id = response['Instances'][0]['InstanceId']
        logging.info(f'New analysis instance ID: {analysis_instance_id}')

        # 인스턴스가 running 상태가 될 때까지 대기
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[analysis_instance_id])
        
        time.sleep(60)

        # 메모리 덤프 파일을 분석 인스턴스로 다운로드
        memory_dump_key = f'{instance_id}/{timestamp}/mem_dump.bin'
        local_memory_dump_path = '/mnt/forensic/mem_dump.bin'
        download_command = f"aws s3 cp s3://{forensic_collect_bucket}/{memory_dump_key} {local_memory_dump_path}"
        result = execute_command_and_wait(ssm, analysis_instance_id, download_command)
        if result is None:
            return {
                'statusCode': 500,
                'body': f"Command {download_command} failed"
            }

        return {
            'statusCode': 200,
            'body': f'Analysis instance {analysis_instance_id} started and memory dump downloaded',
            'instance_id': instance_id,
            'analysis_instance_id': analysis_instance_id,
            'timestamp': timestamp
        }
    except Exception as e:
        logging.error(f'Error: {str(e)}')
        return {
            'statusCode': 500,
            'body': str(e)
        }
