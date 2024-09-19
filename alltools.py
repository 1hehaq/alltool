import argparse
import json
import subprocess
import sys
import os
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Union
import re
import requests
import shutil
from colorama import Fore, Back, Style, init
from halo import Halo
import pyfiglet
import textwrap
import random

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'INFO': Fore.CYAN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE,
        'DEBUG': Fore.BLUE
    }

    def format(self, record):
        log_message = super().format(record)
        return f"{self.COLORS.get(record.levelname, '')}{log_message}{Style.RESET_ALL}"

# Remove default handlers to prevent double logging
logger.handlers = []

# Add our custom handler
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(message)s'))
logger.addHandler(handler)

TIPS = [
    "Always keep your tools and systems updated!",
    "Remember to get proper authorization before scanning any target.",
    "Use a VPN for added anonymity during your scans.",
    "Regularly backup your findings and configurations.",
    "Combine multiple tools for more comprehensive results.",
    "Don't forget to verify your findings manually!",
    "Respect the scope of your engagement at all times.",
    "Learn to read and understand the raw output of your tools.",
    "Automate repetitive tasks to save time and reduce errors.",
    "Stay curious and keep learning about new vulnerabilities and techniques!"
]

class ColoredHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=100)

    def _format_action_invocation(self, action):
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ', '.join(action.option_strings) + ' ' + args_string

    def _get_help_string(self, action):
        help = action.help
        if '%(default)' not in action.help:
            if action.default is not argparse.SUPPRESS:
                defaulting_nargs = [argparse.OPTIONAL, argparse.ZERO_OR_MORE]
                if action.option_strings or action.nargs in defaulting_nargs:
                    help += ' (default: %(default)s)'
        return help

    def _fill_text(self, text, width, indent):
        return ''.join(indent + line for line in text.splitlines(keepends=True))

    def _split_lines(self, text, width):
        return textwrap.wrap(text, width)

def create_parser():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}alltools - All-in-One security scanning tool{Style.RESET_ALL}",
        formatter_class=ColoredHelpFormatter,
        add_help=False
    )

    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help=f'{Fore.GREEN}Show this help message and exit{Style.RESET_ALL}')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Subdomain enumeration parser
    subenum_parser = subparsers.add_parser('subenum', help=f'{Fore.YELLOW}Perform subdomain enumeration{Style.RESET_ALL}')
    subenum_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    subenum_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    subenum_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude{Style.RESET_ALL}')

    # Port scanning parser
    portscan_parser = subparsers.add_parser('portscan', help=f'{Fore.YELLOW}Perform port scanning{Style.RESET_ALL}')
    portscan_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    portscan_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    portscan_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude{Style.RESET_ALL}')

    # Probe parser
    probe_parser = subparsers.add_parser('probe', help=f'{Fore.YELLOW}Probe for alive domains{Style.RESET_ALL}')
    probe_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    probe_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')
    probe_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude{Style.RESET_ALL}')

    # Vulnerability scanning parser
    vulnscan_parser = subparsers.add_parser('vulnscan', help=f'{Fore.YELLOW}Perform vulnerability scanning{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--target', required=True, help=f'{Fore.LIGHTCYAN_EX}Target domain or file with list of targets{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--type', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Types of vulnerabilities to scan for{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--tool', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Specific tools to use{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--isolate', action='store_true', help=f'{Fore.LIGHTCYAN_EX}Run only one tool per vulnerability type{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--exclude', nargs='+', help=f'{Fore.LIGHTCYAN_EX}Tools to exclude{Style.RESET_ALL}')
    vulnscan_parser.add_argument('--output', help=f'{Fore.LIGHTCYAN_EX}Output file for results{Style.RESET_ALL}')

    return parser

def gradient_print(text, start_color, end_color):
    for i, char in enumerate(text):
        r = int(start_color[0] + (end_color[0] - start_color[0]) * i / len(text))
        g = int(start_color[1] + (end_color[1] - start_color[1]) * i / len(text))
        b = int(start_color[2] + (end_color[2] - start_color[2]) * i / len(text))
        print(f"\033[38;2;{r};{g};{b}m{char}", end="")
    print(Style.RESET_ALL)

def print_banner():
    banner = pyfiglet.figlet_format("alltools", font="slant")
    gradient_print(banner, (0, 255, 255), (255, 0, 255))
    
    print(f"{Fore.LIGHTGREEN_EX}All-in-One security scanning tool Created by - {Style.RESET_ALL} "
      f"\033]8;;https://github.com/1hehaq\033\\{Fore.LIGHTGREEN_EX}@1hehaq\033]8;;\033\\ {Style.RESET_ALL}\n")

    tip = random.choice(TIPS)
    wrapped_tip = textwrap.wrap(tip, width=60)
    max_length = max(len(line) for line in wrapped_tip)
    
    print(f"{Fore.YELLOW}┌─ Tip of the Day {'─' * (max_length - 14)}┐{Style.RESET_ALL}")
    for line in wrapped_tip:
        print(f"{Fore.YELLOW}│ {Fore.CYAN}{line:<{max_length}} {Fore.YELLOW}│{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}└{'─' * (max_length + 2)}┘{Style.RESET_ALL}\n")

def print_completion_banner(results):
    completion_banner = pyfiglet.figlet_format("Scan Complete!", font="small")
    print(f"\n{Fore.GREEN}{completion_banner}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Summary of findings:{Style.RESET_ALL}")
    for key, value in results.items():
        if isinstance(value, list):
            print(f"{Fore.CYAN}{key.capitalize()}: {Fore.WHITE}{len(value)} found")
        elif isinstance(value, dict):
            print(f"{Fore.CYAN}{key.capitalize()}:")
            for subkey, subvalue in value.items():
                print(f"  {Fore.LIGHTCYAN_EX}{subkey}: {Fore.WHITE}{len(subvalue) if isinstance(subvalue, list) else subvalue} found")
    print(f"\n{Fore.YELLOW}Detailed results are stored in the 'results' attribute of the scanner object.{Style.RESET_ALL}")

class SecurityScanner:
    def __init__(self, config_file: str = 'config.json'):
        self.config = self.load_config(config_file)
        self.results: Dict[str, Any] = {}
        self.spinner = Halo(spinner='dots')

    def load_config(self, config_file: str) -> Dict[str, Any]:
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            self.validate_config(config)
            return config
        except FileNotFoundError:
            logger.error(f"Config file '{config_file}' not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in config file '{config_file}'.")
            sys.exit(1)

    def validate_config(self, config: Dict[str, Any]) -> None:
        required_keys = ['subdomain_enum', 'port_scan', 'probe', 'vuln_scan']
        for key in required_keys:
            if key not in config:
                logger.error(f"Missing required key '{key}' in config.")
                sys.exit(1)

    def run_command(self, command: List[str], silent: bool = False) -> str:
        try:
            if silent:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
            else:
                result = subprocess.run(command, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running command {' '.join(command)}: {e}")
            return e.stderr

    def run_tool(self, tool, command, target):
        try:
            if tool == "oneliners":
                # Handle oneliners differently
                formatted_command = command.format(target=target)
                output = subprocess.run(formatted_command, shell=True, capture_output=True, text=True, check=True)
            else:
                # Check if the tool is available
                if not shutil.which(command[0]):
                    return tool, target, set(), f"Tool '{command[0]}' not found. Please install it or add it to your PATH."

                formatted_command = [arg.format(target=target) for arg in command]
                output = subprocess.run(formatted_command, capture_output=True, text=True, check=True)

            subdomains = set(line.strip() for line in output.stdout.splitlines() if line.strip())
            return tool, target, subdomains, None
        except subprocess.CalledProcessError as e:
            return tool, target, set(), f"Command '{formatted_command if isinstance(formatted_command, str) else ' '.join(formatted_command)}' returned non-zero exit status {e.returncode}."

    def subdomain_enumeration(self, targets: List[str], args: argparse.Namespace) -> None:
        self.spinner.start(f"{Fore.CYAN}Performing Subdomain Enumeration{Style.RESET_ALL}")
        all_subdomains = set()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for target in targets:
                for tool, command in self.config['subdomain_enum'].items():
                    if args.exclude and tool in args.exclude:
                        continue
                    if tool == "oneliners":
                        for oneliner in command:
                            futures.append(executor.submit(self.run_tool, "oneliners", oneliner, target))
                    else:
                        futures.append(executor.submit(self.run_tool, tool, command, target))

            for future in as_completed(futures):
                tool, target, subdomains, error = future.result()
                if error:
                    self.spinner.fail(f"{Fore.LIGHTRED_EX}Error running {tool} for {target}: {error}{Style.RESET_ALL}")
                    continue
                
                all_subdomains.update(subdomains)
                
                self.spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(subdomains)} subdomains for {target}{Style.RESET_ALL}")
                for subdomain in subdomains:
                    logger.info(f"  {Fore.LIGHTYELLOW_EX}{subdomain}{Style.RESET_ALL}")
                
                self.spinner.start(f"{Fore.CYAN}Performing Subdomain Enumeration{Style.RESET_ALL}")

        self.spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Total unique subdomains found: {len(all_subdomains)}{Style.RESET_ALL}")
        self.results['subdomains'] = list(all_subdomains)

        if args.output:
            with open(args.output, 'w') as f:
                for subdomain in all_subdomains:
                    f.write(f"{subdomain}\n")
            logger.info(f"{self.get_timestamp()} Subdomains saved to {args.output}")
        print(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        self.spinner.succeed(f"{Fore.GREEN}Subdomain Enumeration Complete{Style.RESET_ALL}")

    def get_timestamp(self) -> str:
        return f"{Fore.LIGHTMAGENTA_EX}[{time.strftime('%H:%M:%S')}]{Style.RESET_ALL}"

    def port_scanning(self, targets: List[str], args: argparse.Namespace) -> None:
        self.spinner.start(f"{Fore.CYAN}Performing Port Scanning{Style.RESET_ALL}")
        logger.info(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Starting port scanning...{Style.RESET_ALL}")
        open_ports = {}

        for target in targets:
            open_ports[target] = []
            for tool, command in self.config['port_scan'].items():
                if args.exclude and tool in args.exclude:
                    continue
                logger.info(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}Running {tool} for {target}{Style.RESET_ALL}")
                formatted_command = [arg.format(target=target) for arg in command]
                output = self.run_command(formatted_command, silent=True)
                ports = self.parse_port_scan_output(tool, output)
                open_ports[target].extend(ports)
                
                logger.info(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(ports)} open ports for {target}{Style.RESET_ALL}")
                for port in ports:
                    logger.info(f"  {Fore.LIGHTYELLOW_EX}{port}{Style.RESET_ALL}")

        self.results['open_ports'] = open_ports

        if args.output:
            with open(args.output, 'w') as f:
                for target, ports in open_ports.items():
                    f.write(f"{target}:\n")
                    for port in ports:
                        f.write(f"  {port}\n")
            logger.info(f"{self.get_timestamp()} Open ports saved to {args.output}")

        self.spinner.succeed(f"{Fore.GREEN}Port Scanning Complete{Style.RESET_ALL}")

    def parse_port_scan_output(self, tool: str, output: str) -> List[int]:
        # Implement parsing logic for different tools
        # This is a simplified example
        ports = []
        for line in output.splitlines():
            if 'open' in line.lower():
                port = re.search(r'\d+', line)
                if port:
                    ports.append(int(port.group()))
        return ports

    def probe_alive_domains(self, targets: List[str], args: argparse.Namespace) -> None:
        self.spinner.start(f"{Fore.CYAN}Probing for Alive Domains{Style.RESET_ALL}")
        logger.info(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Probing for alive domains...{Style.RESET_ALL}")
        alive_domains = set()

        for tool, command in self.config['probe'].items():
            if args.exclude and tool in args.exclude:
                continue
            logger.info(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}Running {tool}{Style.RESET_ALL}")
            formatted_command = command + targets
            output = self.run_command(formatted_command, silent=True)
            domains = set(line.strip() for line in output.splitlines() if line.strip())
            alive_domains.update(domains)
            
            logger.info(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(domains)} alive domains{Style.RESET_ALL}")
            for domain in domains:
                logger.info(f"  {Fore.LIGHTYELLOW_EX}{domain}{Style.RESET_ALL}")

        logger.info(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Total alive domains found: {len(alive_domains)}{Style.RESET_ALL}")
        self.results['alive_domains'] = list(alive_domains)

        if args.output:
            with open(args.output, 'w') as f:
                for domain in alive_domains:
                    f.write(f"{domain}\n")
            logger.info(f"{self.get_timestamp()} Alive domains saved to {args.output}")

        self.spinner.succeed(f"{Fore.GREEN}Probing Complete{Style.RESET_ALL}")

    def vulnerability_scanning(self, targets: List[str], args: argparse.Namespace) -> None:
        self.spinner.start(f"{Fore.CYAN}Performing Vulnerability Scanning{Style.RESET_ALL}")
        logger.info(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Starting vulnerability scanning...{Style.RESET_ALL}")
        vulnerabilities = {}

        vuln_types = args.type if args.type else ['all']
        if 'all' in vuln_types:
            vuln_types = list(self.config['vuln_scan'].keys())

        for target in targets:
            vulnerabilities[target] = {}
            for vuln_type in vuln_types:
                if vuln_type not in self.config['vuln_scan']:
                    logger.warning(f"{self.get_timestamp()} {Fore.LIGHTYELLOW_EX}Unknown vulnerability type: {vuln_type}{Style.RESET_ALL}")
                    continue

                self.spinner.text = f"Scanning for {vuln_type} vulnerabilities on {target}"
                for tool, command in self.config['vuln_scan'][vuln_type].items():
                    if args.exclude and tool in args.exclude:
                        continue
                    if args.tool and tool not in args.tool:
                        continue
                    self.spinner.text = f"Running {tool} for {vuln_type} on {target}"
                    formatted_command = [arg.format(target=target) for arg in command]
                    output = self.run_command(formatted_command, silent=True)
                    vulns = self.parse_vulnerability_output(tool, output)
                    vulnerabilities[target][vuln_type] = vulns
                    
                    self.spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(vulns)} {vuln_type} vulnerabilities on {target}{Style.RESET_ALL}")
                    for vuln in vulns:
                        logger.info(f"  {Fore.LIGHTYELLOW_EX}{vuln['description']}{Style.RESET_ALL}")
                    self.spinner.start(f"{Fore.CYAN}Performing Vulnerability Scanning{Style.RESET_ALL}")

                if args.isolate:
                    break

        self.results['vulnerabilities'] = vulnerabilities

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            logger.info(f"{self.get_timestamp()} Vulnerabilities saved to {args.output}")

        self.spinner.succeed(f"{Fore.GREEN}Vulnerability Scanning Complete{Style.RESET_ALL}")

    def parse_vulnerability_output(self, tool: str, output: str) -> List[Dict[str, str]]:
        # Implement parsing logic for different vulnerability scanning tools
        # This is a simplified example
        vulnerabilities = []
        for line in output.splitlines():
            if 'vulnerability' in line.lower():
                vuln = {
                    'type': 'Unknown',
                    'severity': 'Unknown',
                    'description': line.strip()
                }
                vulnerabilities.append(vuln)
        return vulnerabilities

def main():
    parser = create_parser()
    args = parser.parse_args()

    print_banner()

    scanner = SecurityScanner()

    targets = []
    if os.path.isfile(args.target):
        with open(args.target, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [args.target]

    try:
        if args.command == 'subenum':
            scanner.subdomain_enumeration(targets, args)
        elif args.command == 'portscan':
            scanner.port_scanning(targets, args)
        elif args.command == 'probe':
            scanner.probe_alive_domains(targets, args)
        elif args.command == 'vulnscan':
            scanner.vulnerability_scanning(targets, args)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        scanner.spinner.fail(f"{Fore.YELLOW}Scan interrupted by user. Exiting...{Style.RESET_ALL}")
    except Exception as e:
        scanner.spinner.fail(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")
    finally:
        print_completion_banner(scanner.results)

if __name__ == "__main__":
    main()
