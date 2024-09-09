import subprocess
import random
import os
from datetime import datetime
import time
import requests
from urllib.parse import urlparse

import argparse
import json
import sys
#chrome --headless --remote-debugging-port=0
current_time = datetime.now()
timestamp_str = current_time.strftime("%Y-%m-%d_%H-%M-%S")

def generate_random_port_for_ext_api():
    return random.randint(1024, 65535)

def generate_random_port_for_rest_api():
    return random.randint(1024, 65535)

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

port_for_rest_api = generate_random_port_for_rest_api()
#Need to add full path 
file_path = '/root/app/test_random.json'
temp_config = replace_value_in_temp_file(str(port_for_rest_api), file_path)

def run_java(port, user_config_file):
    try:
        #Need to add full path in line 61 and change all the semicolon to colon in same line and line 58 Need to add full path
        java_command = [
            "java", "-Xmx1g",
            "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED",
            "-javaagent:/root/app/burploader.jar",
            "-noverify",
            "-cp",
            "/root/app/burp-rest-api-2.2.0.jar:/root/app/burploader.jar:/root/app/burpsuite_pro_v2024.4.5.jar",
            "org.springframework.boot.loader.JarLauncher",
            "--headless.mode=true",
            "--address=0.0.0.0",
            "--server.port=" + str(port),
            "--unpause-spider-and-scanner",
            "--user-config-file=" + user_config_file
        ]

        subprocess.Popen(java_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"An error occurred while running Java: {e}")
        sys.exit(1)

def stop_burp_proxy(port):
    try:
        url = f"http://localhost:{port}/burp/stop"
        response = requests.get(url)
        if response.status_code == 200:
            print("Burp Suite stopped successfully")
        else:
            print(f"Failed to stop Burp Suite. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"An error occurred: {e}")

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        if 'the following arguments are required' in message:
            self.print_help()
            print("\nError: URL argument is missing. Please provide a URL to scan.")
            stop_burp_proxy(port_for_ext_api)
            os.remove(temp_config)
            sys.exit(1)
        else:
            stop_burp_proxy(port_for_ext_api)
            os.remove(temp_config)
            super().error(message)

#def get_protocol_and_domain(url):
#    parsed_url = urlparse(url)
#    protocol = parsed_url.scheme
#    domain = parsed_url.netloc
#    return f"{protocol}://{domain}"

def get_protocol_and_domain(urls):
    protocol_and_domains = set()  # Use a set to ensure uniqueness
    for url in urls:
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme
        domain = parsed_url.netloc
        protocol_and_domains.add(f"{protocol}://{domain}")
    return list(protocol_and_domains)  # Convert set back to list


def config_read(config_file_path):
    with open(config_file_path, 'r') as file:
        file_content = file.read()
    return file_content

def send_scan_request(url_input, port_for_rest_api,config_file_path):
    try:
        url = f'http://localhost:{port_for_rest_api}/v0.1/scan'
        #payload = {"scan_configurations":[{"config":config_read(config_file_path),"type":"CustomConfiguration"}],"urls":url_input}
        payload = {"scan_configurations":[{"name":"Crawl and Audit - Fast","type":"NamedConfiguration"}],"urls":url_input}
        data = json.dumps(payload)
        response = requests.post(url, data=data)
        return response.text, response.headers.get('Location')
    except Exception as e:
        print(f"An error occurred while sending the scan request: {e}")
        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        sys.exit(1)

def parse_json(response_json):
    parsed_data = {'overall_total': 0, 'severity_totals': {}}
    severities = ['high', 'medium', 'low', 'information']
    confidences = ['certain', 'firm', 'tentative']

    for severity in severities:
        if severity not in parsed_data['severity_totals']:
            parsed_data['severity_totals'][severity] = {confidence: 0 for confidence in confidences}

    for issue in response_json.get('issues', []):
        severity = issue.get('severity').lower()
        confidence = issue.get('confidence').lower()

        if severity not in parsed_data['severity_totals']:
            parsed_data['severity_totals'][severity] = {confidence: 0 for confidence in confidences}

        if confidence in parsed_data['severity_totals'][severity]:
            parsed_data['severity_totals'][severity][confidence] += 1

        parsed_data['overall_total'] += 1

    return parsed_data


def fetch_and_print_new_results(previous_results, port_for_rest_api, port_for_ext_api, scan_id, url_inputs):
    try:
        url = f"http://localhost:{port_for_rest_api}/v0.1/scan/{scan_id}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # Check if scan status is succeeded
        if 'scan_status' in data and data['scan_status'] == 'succeeded':
            print("")
            return None  # Returning None to indicate the loop should be stopped

        all_new_results = []

        for url_input in url_inputs:
            url_scan = f"http://localhost:{port_for_ext_api}/burp/scanner/issues?urlPrefix={url_input}"
            headers = {"accept": "*/*"}
            
            try:
                response1 = requests.get(url_scan, headers=headers)
                response1.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"Request error for {url_input}: {e}")
                continue

            try:
                response_json = response1.json()
            except json.JSONDecodeError as e:
                print(f"JSON decode error for {url_input}: {e}")
                continue

            # Grouping issue events by issue name
            grouped_issues = {}
            for issue_event in response_json['issues']:
                issue_name = issue_event['issueName']
                if issue_name not in grouped_issues:
                    grouped_issues[issue_name] = []
                grouped_issues[issue_name].append(issue_event)

            # Converting to the desired format
            formatted_issues = []
            for issue_name, events in grouped_issues.items():
                formatted_issue = {
                    "Vulnerability name": issue_name,
                    "severity": events[0]['severity'],
                    "confidence": events[0]['confidence']
                }
                formatted_issues.append(formatted_issue)

            # Find new results
            new_results = [issue for issue in formatted_issues if issue not in previous_results]

            # Print only if new results are present
            if new_results:
                for issue in new_results:
                    print(f"Issue found ({issue['severity']} {issue['confidence']}) - {issue['Vulnerability name']}")
                    sys.stdout.flush()

            # Collect all new results
            all_new_results.extend(new_results)

        # Return the updated results
        return previous_results + all_new_results

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        sys.exit(1)

    return previous_results  # In case of error, return the previous results to continue the loop


def save_scan_response(scan_id, output_folder, url_inputs, port_for_rest_api, port_for_ext_api, filename, severity, confidential, count):
    url = f'http://localhost:{port_for_rest_api}/v0.1/scan/{scan_id}'
    print("############# Vulnerability Found #############")
    sys.stdout.flush()
    severity_user = severity
    count_user = count
    confidential_user = confidential
    while True:
        try:
            response = requests.get(url)
            response_json = response.json()
            scan_status = response_json.get('scan_status')

            if scan_status == 'succeeded':
                os.makedirs(output_folder, exist_ok=True)

                for url_input in url_inputs:
                    #issueSeverity - All, High, Medium, Low and Information
                    #issueConfidence - All, Certain, Firm and Tentative
                    result_html = f'http://localhost:{port_for_ext_api}/burp/report?urlPrefix={url_input}&reportType=HTML&issueSeverity=All&issueConfidence=All'
                    response_html = requests.get(result_html)
                    
                    # Extracting filename from URL
                    parsed_url = urlparse(url_input)
                    domain_name = parsed_url.netloc.replace('.', '_')

                    save_filename = f'scan_{filename}_{domain_name}.html'
                    # Perform DB operations
                    output_file = os.path.join(output_folder, save_filename)
                    
                    if response_html.status_code == 200:
                        with open(output_file, "w") as html_file:
                            html_file.write(response_html.text)
                            print(f"Report created successfully and file saved to {output_file}")
                    else:
                        print(f"Failed to fetch data from the API for {url_input}.")

                # Aggregate JSON data
                aggregate_data = {'overall_total': 0, 'severity_totals': {}}
                for url_input in url_inputs:
                    url = f"http://localhost:{port_for_ext_api}/burp/scanner/issues?urlPrefix={url_input}"
                    headers = {"accept": "*/*"}
                    response = requests.get(url, headers=headers)

                    if response.status_code != 200:
                        print("Error:", response.status_code)
                        sys.exit(1)

                    response_json = response.json()
                    data = parse_json(response_json)


                    # Perform DB operations
                    # Buildid = filename
                    # url = url_inputs
                    # Accumulate the data
                    aggregate_data['overall_total'] += data['overall_total']
                    for severity, confidence_data in data['severity_totals'].items():
                        if severity not in aggregate_data['severity_totals']:
                            aggregate_data['severity_totals'][severity] = confidence_data.copy()
                        else:
                            for confidence, count in confidence_data.items():
                                aggregate_data['severity_totals'][severity][confidence] += count

                # Print the aggregated total
                high = aggregate_data['severity_totals']['high']['firm'] + aggregate_data['severity_totals']['high']['tentative'] + aggregate_data['severity_totals']['high']['certain']
                medium = aggregate_data['severity_totals']['medium']['firm'] + aggregate_data['severity_totals']['medium']['tentative'] + aggregate_data['severity_totals']['medium']['certain']
                low = aggregate_data['severity_totals']['low']['firm'] + aggregate_data['severity_totals']['low']['tentative'] + aggregate_data['severity_totals']['low']['certain']
                information = aggregate_data['severity_totals']['information']['firm'] + aggregate_data['severity_totals']['information']['tentative'] + aggregate_data['severity_totals']['information']['certain']
                
                print("############### Report Summary ################")
                print("High count: ",high)
                print("Medium count: ",medium)
                print("Low count: ",low)
                print("Information count: ",information)
                print("Overall count: ",aggregate_data['overall_total'])
                print("###############################################")
                check_issues(aggregate_data, severity_user, confidential_user, count_user)
                break

            previous_results = []

            # Infinite loop to fetch and print new results every 30 second
            while True:
                # Call the function and update previous results
                previous_results = fetch_and_print_new_results(previous_results, port_for_rest_api, port_for_ext_api, scan_id, url_inputs)
                # Check if the loop should be stopped
                if previous_results is None:
                    break
                # Wait for every 30 second
                time.sleep(30)  # 30 seconds

            #print("Scan is still in progress. Waiting for 30 seconds before checking again...")
            #sys.stdout.flush()
            #time.sleep(30)
        except Exception as e:
            print(f"An error occurred while saving scan response: {e}")
            stop_burp_proxy(port_for_ext_api)
            os.remove(temp_config)
            sys.exit(1)

def check_issues(data, severity, confidential, count):
    try:
        if severity not in data['severity_totals'] or confidential not in data['severity_totals'][severity]:
            stop_burp_proxy(port_for_ext_api)
            os.remove(temp_config)
            print("Enter Correct input")
            sys.exit(1)
            return

        if data['severity_totals'][severity][confidential] >= count:
            stop_burp_proxy(port_for_ext_api)
            os.remove(temp_config)
            print(f"fail with {data['severity_totals'][severity][confidential]} count {severity} {confidential}")
            print(f"The {severity} {confidential} confidence count is {data['severity_totals'][severity][confidential]}. So, the scan was failed")
            sys.exit(1)
            return

        severity_levels = ["information", "low", "medium", "high"]
        for sev in severity_levels[severity_levels.index(severity)+1:]:
            for conf in ['firm', 'tentative', 'certain']:
                if data['severity_totals'][sev][conf] >= 1:
                    stop_burp_proxy(port_for_ext_api)
                    os.remove(temp_config)
                    print(f"fail because of {sev} severity issue is found")
                    sys.exit(1)
                    return

        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        print("Scan Complete")
    except Exception as e:
        print(f"An error occurred while checking issues: {e}")
        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        sys.exit(1)

def main():
    parser = CustomArgumentParser(description='Send a scan request and save the response.')
    parser.add_argument('--url', type=str, help='URL to scan')
    parser.add_argument('--output-folder', type=str, default='.', help='Output folder path')
    parser.add_argument('--filename', type=str, help='Filename to save')
    parser.add_argument('--severity', type=str, help='Enter a severity (high, medium, low, information)')
    parser.add_argument('--confidential', type=str, help='Enter a confidential (firm, tentative, certain)')
    parser.add_argument('--count', type=int, help='Enter a count')

    args = parser.parse_args()

    userinput = args.url
    url_list = userinput.split(',')
    config_file_path = '/root/app/CrawlandAudit_DeepCustom.json'
    result, location_header = send_scan_request(url_list, port_for_rest_api,config_file_path)

    print(result)

    if location_header:
        #print("Task ID : ", location_header)
        sys.stdout.flush()
        result = get_protocol_and_domain(url_list)
        save_scan_response(location_header, args.output_folder, result, port_for_rest_api, port_for_ext_api, args.filename, args.severity, args.confidential, args.count)
        sys.stdout.flush()
    else:
        print("Task ID not found in the response.")
        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        sys.exit(1)

if __name__ == "__main__":
    port_for_ext_api = generate_random_port_for_ext_api()
    print(f"Debug Port for Extension API: {port_for_ext_api}")
    print(f"Debug Port for Rest API: {port_for_rest_api}")
    #print(f"temporary file: {temp_config}")
    sys.stdout.flush()
    run_java(port_for_ext_api, temp_config)
    print("Burp Suite is Starting")
    sys.stdout.flush()
    time.sleep(30)
    try:
        main()
    except Exception as e:
        print(f"An error occurred in the main function: {e}")
        stop_burp_proxy(port_for_ext_api)
        os.remove(temp_config)
        sys.exit(1)

#python3 Web_DAST_Linux.py --url=http://testphp.vulnweb.com/ --output-folder=/root/app/ --filename=1 --severity=medium --confidential=certain --count=5

#java -jar agent.jar -url https://uatnovacjenkins.novactech.in/ -secret e18696036d049fcae8e0b4c6cb7068886336812dbede7c4e4edd1c4d972588be -name Burp -webSocket  -workDir "/home/kali/Documents/uatjenkins"
