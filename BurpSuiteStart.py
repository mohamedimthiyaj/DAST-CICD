import subprocess
from datetime import datetime
import sys
import os
import argparse

def replace_value_in_temp_file(input_value, file_path):
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()

        # Replace occurrences of "1337" with the input value
        modified_content = file_content.replace("1337", input_value)

        # Create a temporary file with a timestamp in its name
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        temp_file_path = f"temp_config_{timestamp}.json"

        # Write the modified content to the temporary file
        with open(temp_file_path, 'w') as temp_file:
            temp_file.write(modified_content)

        return temp_file_path
    except Exception as e:
        print(f"An error occurred while replacing value in temp file: {e}")
        sys.exit(1)

def run_java(port, user_config_file, abs_path):
    try:
        java_command = [
            "java",
            "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED",
            f"-javaagent:{ABS_PATH}burploader.jar",
            "-noverify",
            "-cp",
            f"{ABS_PATH}burp-rest-api-2.2.0.jar:{ABS_PATH}burploader.jar:{ABS_PATH}burpsuite_pro.jar",
            "org.springframework.boot.loader.JarLauncher",
            "--headless.mode=true",
            "--address=0.0.0.0",
            "--server.port=" + str(port),
            "--unpause-spider-and-scanner",
            "--user-config-file=" + user_config_file
        ]

        #print(f"Running command: {' '.join(java_command)}")
        
        # Redirect stdout and stderr to log files
        stdout_log = open('stdout_.log', 'w')
        stderr_log = open('stderr_.log', 'w')
        
        # Use subprocess.Popen to execute the command in the background
        process = subprocess.Popen(java_command, stdout=stdout_log, stderr=stderr_log)
        
        print(f"Java process started with PID: {process.pid}")
        
        return process
    except subprocess.CalledProcessError as e:
        print(f"Error while running Java command: {e}")
        os.remove(user_config_file)
    except KeyboardInterrupt:
        print("Keyboard interrupt detected, terminating Java subprocess...")
        os.remove(user_config_file)
        sys.exit(1)  # or perform other cleanup as needed

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Send a scan request and save the response.')
        parser.add_argument('--rest_port', type=int, help='Enter a port number')
        parser.add_argument('--exet_port', type=str, help='Enter a port number')
        args = parser.parse_args()

        ABS_PATH = "/home/rizwan/Burpsuite/"
        file_path = f"{ABS_PATH}test_random.json"

        temp_config = replace_value_in_temp_file(str(args.rest_port), file_path)
        process = run_java(args.exet_port, temp_config, ABS_PATH)
        
        print("Burp Suite is Starting in the background")
    except Exception as e:
        print(f"An error occurred in the main function: {e}")
        if 'temp_config' in locals():
            os.remove(temp_config)
        sys.exit(1)

#python3 Docker_burp.py --rest_port=1377 --exet_port=9091