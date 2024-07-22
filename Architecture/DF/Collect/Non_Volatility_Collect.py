import boto3
import logging
import hashlib
import time

logging.basicConfig(level=logging.INFO)

def execute_command_and_wait(ssm, instance_id, command, timeout=600):
    try:
        logging.info(f"Executing command: {command}")
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [command]},
            TimeoutSeconds=timeout
        )
        command_id = response['Command']['CommandId']
        logging.info(f"Command ID: {command_id}")
        
        waiter = ssm.get_waiter('command_executed')
        try:
            waiter.wait(
                CommandId=command_id,
                InstanceId=instance_id,
                WaiterConfig={
                    'Delay': 10,
                    'MaxAttempts': 60
                }
            )
        except Exception as e:
            logging.error(f"Waiter failed: {e}")
            return None, str(e)
        
        for attempt in range(10):
            try:
                output = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                logging.info(f"Command output: {output['StandardOutputContent']}")
                logging.info(f"Command error output: {output['StandardErrorContent']}")
                if output['Status'] == 'Success':
                    return output['StandardOutputContent'].strip(), output['StandardErrorContent'].strip()
                else:
                    logging.error(f"Command failed with status: {output['Status']}")
                    logging.error(f"Standard output: {output['StandardOutputContent']}")
                    logging.error(f"Error output: {output['StandardErrorContent']}")
                    return None, output['StandardErrorContent'].strip()
            except ssm.exceptions.InvocationDoesNotExist:
                logging.warning(f"Invocation does not exist yet, retrying... ({attempt + 1}/10)")
                time.sleep(5)
        
        raise Exception(f"Failed to get command invocation for Command ID: {command_id}")
        
    except Exception as e:
        logging.error(f"Error executing command '{command}': {e}")
        return None, str(e)

def generate_hash_locally(file_content):
    hasher = hashlib.sha256()
    hasher.update(file_content)
    return hasher.hexdigest()

def lambda_handler(event, context):
    backup_instance_id = event.get('backup_instance_id')
    instance_id = event.get('instance_id')
    timestamp = event.get('timestamp')

    region = 'ap-northeast-2'
    
    ec2 = boto3.client('ec2', region_name=region)
    ssm = boto3.client('ssm', region_name=region)
    s3 = boto3.client('s3', region_name=region)
    forensic_collect_bucket = 'forensic-collect-bucket'
    
    try:
        # Check instance status and start if necessary
        instance_status = ec2.describe_instance_status(InstanceIds=[backup_instance_id])
        if not instance_status['InstanceStatuses']:
            raise Exception(f"Instance {backup_instance_id} not found")
        
        state = instance_status['InstanceStatuses'][0]['InstanceState']['Name']
        if state != 'running':
            ec2.start_instances(InstanceIds=[backup_instance_id])
            waiter = ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[backup_instance_id])
        
        # Create directory if it does not exist
        check_directory_command = "test -d /mnt/forensic/non_volatility && echo 'Directory exists' || sudo mkdir -p /mnt/forensic/non_volatility"
        directory_check_result, error_output = execute_command_and_wait(ssm, backup_instance_id, check_directory_command)
        
        if directory_check_result is None:
            logging.error(f"Failed to check or create directory /mnt/forensic/non_volatility: {error_output}")
            raise Exception("Failed to check or create directory /mnt/forensic/non_volatility")
        
        # Execute commands to collect forensic data
        commands = [
            "sudo df -h > /mnt/forensic/non_volatility/disk_usage.csv",
            "sudo lsof > /mnt/forensic/non_volatility/open_files.csv",
            "sudo cat /var/log/httpd/access_log > /mnt/forensic/non_volatility/httpd_access_log.csv",
            "sudo cat /var/log/httpd/error_log > /mnt/forensic/non_volatility/httpd_error_log.csv",
            "sudo cat /etc/passwd > /mnt/forensic/non_volatility/passwd.csv",
            "sudo cat /etc/shadow > /mnt/forensic/non_volatility/shadow.csv",
            "sudo cat /etc/group > /mnt/forensic/non_volatility/group.csv",
            "sudo cat /etc/ssh/sshd_config > /mnt/forensic/non_volatility/sshd_config.csv",
            "sudo cat ~/.bash_history > /mnt/forensic/non_volatility/bash_history.csv"
        ]
        
        for command in commands:
            result, error_output = execute_command_and_wait(ssm, backup_instance_id, command)
            if result is None:
                logging.error(f"Command failed: {command}, Error: {error_output}")
        
        # Upload files and generate hashes
        forensic_files_to_upload = [
            "disk_usage.csv",
            "open_files.csv",
            "passwd.csv",
            "shadow.csv",
            "group.csv",
            "sshd_config.csv",
            "bash_history.csv",
            "httpd_access_log.csv",
            "httpd_error_log.csv"
        ]
        
        for file_name in forensic_files_to_upload:
            file_path = f"/mnt/forensic/non_volatility/{file_name}"
            check_file_command = f"cat {file_path}"
            file_check_result, _ = execute_command_and_wait(ssm, backup_instance_id, check_file_command)
            
            if file_check_result:
                file_content = file_check_result.encode()
                file_hash = generate_hash_locally(file_content)
                
                upload_command = f"aws s3 cp {file_path} s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/non_volatility_data/{file_name}"
                logging.info(f"Uploading file {file_path} to s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/non_volatility_data/{file_name}")
                result, error_output = execute_command_and_wait(ssm, backup_instance_id, upload_command)
                if result is None:
                    logging.error(f"Failed to upload {file_name} from instance {backup_instance_id}: {error_output}")
                else:
                    logging.info(f"Successfully uploaded {file_name} from instance {backup_instance_id}: {result}")
                
                hash_file_path = f"/mnt/forensic/non_volatility/{file_name}.sha256"
                create_hash_file_command = f"echo '{file_hash}' > {hash_file_path}"
                execute_command_and_wait(ssm, backup_instance_id, create_hash_file_command)
                upload_hash_command = f"aws s3 cp {hash_file_path} s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/non_volatility_data/{file_name}.sha256"
                logging.info(f"Uploading hash file {hash_file_path} to s3://{forensic_collect_bucket}/{instance_id}/{timestamp}/non_volatility_data/{file_name}.sha256")
                execute_command_and_wait(ssm, backup_instance_id, upload_hash_command)
                
            else:
                logging.error(f"{file_name} does not exist on instance {backup_instance_id}")
        
        logging.info(f"Commands executed and files uploaded successfully on instance {backup_instance_id}")
        
    except Exception as e:
        logging.error(f"Error executing commands: {e}")
        return {
            'statusCode': 500,
            'body': str(e)
        }
    
    # Construct s3_key and return it in the response
    s3_key = f"{instance_id}/{timestamp}/non_volatility_data"
    
    return {
        'statusCode': 200,
        'instance_id': instance_id,
        'timestamp': timestamp,
        's3_key': s3_key
    }
