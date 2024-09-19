import argparse
import json
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BugBountyTool:
    def __init__(self, config_file: str = 'config.json'):
        self.config = self.load_config(config_file)
        self.results: Dict[str, Any] = {}

    def load_config(self, config_file: str) -> Dict[str, Any]:
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            self.validate_config(config)
            return config
        except FileNotFoundError:
            logging.error(f"Config file '{config_file}' not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON in config file '{config_file}'.")
            sys.exit(1)

    def validate_config(self, config: Dict[str, Any]) -> None:
        required_keys = ['tasks', 'tools']
        for key in required_keys:
            if key not in config:
                logging.error(f"Missing required key '{key}' in config.")
                sys.exit(1)

    def run_task(self, task_name: str, target: str, tool_name: str = None) -> None:
        if task_name not in self.config['tasks']:
            logging.error(f"Task '{task_name}' not found in config.")
            return

        task_config = self.config['tasks'][task_name]
        tools_to_run = [tool_name] if tool_name else task_config.get('tools', [])

        if not tools_to_run:
            logging.error(f"No tools specified for task '{task_name}'.")
            return

        with ThreadPoolExecutor() as executor:
            futures = []
            for tool in tools_to_run:
                if tool not in self.config['tools']:
                    logging.warning(f"Tool '{tool}' not found in config, skipping.")
                    continue
                futures.append(executor.submit(self.run_tool, task_name, tool, target))

            for future in as_completed(futures):
                tool, result = future.result()
                self.results.setdefault(task_name, {})[tool] = result

        self.analyze_results(task_name)

    def run_tool(self, task_name: str, tool_name: str, target: str) -> tuple:
        tool_config = self.config['tools'][tool_name]
        command = [tool_config['command']] + tool_config.get('default_args', []) + [target]

        logging.info(f"Running {tool_name} for task {task_name}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return tool_name, result.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running {tool_name} for task {task_name}: {e}")
            return tool_name, e.stderr

    def analyze_results(self, task_name: str) -> None:
        task_results = self.results.get(task_name, {})
        if not task_results:
            logging.warning(f"No results to analyze for task '{task_name}'.")
            return

        # Implement task-specific result analysis here
        if task_name == 'subdomain_enumeration':
            self.analyze_subdomains(task_results)
        elif task_name == 'port_scanning':
            self.analyze_ports(task_results)
        # Add more task-specific analysis as needed

    def analyze_subdomains(self, results: Dict[str, str]) -> None:
        all_subdomains = set()
        for tool, output in results.items():
            subdomains = set(line.strip() for line in output.splitlines() if line.strip())
            all_subdomains.update(subdomains)
            logging.info(f"{tool} found {len(subdomains)} subdomains")
        
        logging.info(f"Total unique subdomains found: {len(all_subdomains)}")
        self.results['subdomain_enumeration']['aggregated'] = list(all_subdomains)

    def analyze_ports(self, results: Dict[str, str]) -> None:
        open_ports = set()
        for tool, output in results.items():
            # This is a simplified parser and should be adapted based on the actual output format of your tools
            ports = set(line.split()[0] for line in output.splitlines() if 'open' in line.lower())
            open_ports.update(ports)
            logging.info(f"{tool} found {len(ports)} open ports")
        
        logging.info(f"Total unique open ports found: {len(open_ports)}")
        self.results['port_scanning']['aggregated'] = list(open_ports)

    def chain_tasks(self, tasks: List[str], target: str) -> None:
        for task in tasks:
            self.run_task(task, target)
            if task == 'subdomain_enumeration' and 'port_scanning' in tasks:
                # Use discovered subdomains as targets for port scanning
                subdomains = self.results.get('subdomain_enumeration', {}).get('aggregated', [])
                if subdomains:
                    logging.info(f"Using {len(subdomains)} discovered subdomains for port scanning")
                    for subdomain in subdomains:
                        self.run_task('port_scanning', subdomain)
                else:
                    logging.warning("No subdomains found for port scanning")

    def generate_report(self) -> str:
        report = "Bug Bounty Scan Report\n"
        report += "=====================\n\n"

        for task, task_results in self.results.items():
            report += f"{task.capitalize()} Results:\n"
            report += "-----------------\n"
            for tool, result in task_results.items():
                if tool == 'aggregated':
                    report += f"Aggregated results: {len(result)} items found\n"
                else:
                    report += f"{tool}: {len(result.splitlines())} results\n"
            report += "\n"

        return report

    def list_tasks(self) -> None:
        print("Available tasks:")
        for task in self.config['tasks']:
            print(f"- {task}")
            for tool in self.config['tasks'][task].get('tools', []):
                print(f"  - {tool}")

def main():
    parser = argparse.ArgumentParser(description="All-in-One Bug Bounty Tool")
    parser.add_argument('task', nargs='?', help="Name of the task to run")
    parser.add_argument('--target', required=True, help="Target for the bug bounty tasks")
    parser.add_argument('--tool', help="Specific tool to use for the task")
    parser.add_argument('--chain', nargs='+', help="Chain multiple tasks")
    parser.add_argument('--list-tasks', action='store_true', help="List available tasks and tools")
    parser.add_argument('--output', help="Output file for the report")

    args = parser.parse_args()

    bug_bounty_tool = BugBountyTool()

    if args.list_tasks:
        bug_bounty_tool.list_tasks()
    elif args.chain:
        bug_bounty_tool.chain_tasks(args.chain, args.target)
    elif args.task:
        bug_bounty_tool.run_task(args.task, args.target, args.tool)
    else:
        parser.print_help()
        sys.exit(1)

    if bug_bounty_tool.results:
        report = bug_bounty_tool.generate_report()
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            logging.info(f"Report written to {args.output}")
        else:
            print(report)

if __name__ == "__main__":
    main()
