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
import sys
import traceback

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

# Remove all handlers associated with the root logger object
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

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
    
    logger.info(f"{Fore.LIGHTGREEN_EX}All-in-One security scanning tool Created by - {Style.RESET_ALL} "
                f"\033]8;;https://github.com/1hehaq\033\\{Fore.LIGHTGREEN_EX}@1hehaq\033]8;;\033\\ {Style.RESET_ALL}")

    tip = random.choice(TIPS)
    wrapped_tip = textwrap.wrap(tip, width=60)
    max_length = max(len(line) for line in wrapped_tip)
    
    logger.info(f"{Fore.YELLOW}┌─ Tip of the Day {'─' * (max_length - 15)}┐{Style.RESET_ALL}")
    for line in wrapped_tip:
        logger.info(f"{Fore.YELLOW}│ {Fore.CYAN}{line:<{max_length}} {Fore.YELLOW}│{Style.RESET_ALL}")
    logger.info(f"{Fore.YELLOW}└{'─' * (max_length + 2)}┘{Style.RESET_ALL}")

def print_completion_banner(results):
    logger.info(f"{Fore.YELLOW}Summary of findings:{Style.RESET_ALL}")
    for key, value in results.items():
        if isinstance(value, list):
            logger.info(f"{Fore.CYAN}{key.capitalize()}: {Fore.WHITE}{len(value)} found")
        elif isinstance(value, dict):
            logger.info(f"{Fore.CYAN}{key.capitalize()}:")
            for subkey, subvalue in value.items():
                logger.info(f"  {Fore.LIGHTCYAN_EX}{subkey}: {Fore.WHITE}{len(subvalue) if isinstance(subvalue, list) else subvalue} found")
    logger.info(f"\n{Fore.YELLOW}Detailed results are stored in the 'results' attribute of the scanner object.{Style.RESET_ALL}")

# Custom Exceptions
class AllToolsError(Exception):
    """Base exception for AllTools"""
    pass

class ConfigurationError(AllToolsError):
    """Raised when there's an issue with the configuration"""
    pass

class ToolExecutionError(AllToolsError):
    """Raised when a tool fails to execute properly"""
    pass

class InputError(AllToolsError):
    """Raised when there's an issue with user input"""
    pass

# Global Error Handler
def global_exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.error("An unexpected error occurred:", exc_info=(exc_type, exc_value, exc_traceback))
    logger.error(f"\n{Fore.RED}An unexpected error occurred. Please check the log file for details.{Style.RESET_ALL}")

sys.excepthook = global_exception_handler

from halo import Halo
import sys

class NonInterferenceSpinner(Halo):
    def start(self, text=None):
        if sys.stdout.isatty():
            super().start(text)

    def stop(self):
        if sys.stdout.isatty():
            super().stop()

spinner = NonInterferenceSpinner(spinner='dots')

# Enhance the SecurityScanner class
class SecurityScanner:
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
            raise ConfigurationError(f"Config file '{config_file}' not found.")
        except json.JSONDecodeError:
            raise ConfigurationError(f"Invalid JSON in config file '{config_file}'.")

    def validate_config(self, config: Dict[str, Any]) -> None:
        required_keys = ['subdomain_enum', 'port_scan', 'probe', 'vuln_scan']
        for key in required_keys:
            if key not in config:
                raise ConfigurationError(f"Missing required key '{key}' in config.")

    def run_command(self, command: List[str], silent: bool = False) -> str:
        try:
            if silent:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
            else:
                result = subprocess.run(command, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise ToolExecutionError(f"Error running command {' '.join(command)}: {e}")

    def run_tool(self, tool, command, target):
        try:
            if tool == "oneliners":
                formatted_command = command.format(target=target)
                output = subprocess.run(formatted_command, shell=True, capture_output=True, text=True, check=True)
            else:
                if not shutil.which(command[0]):
                    raise ToolExecutionError(f"Tool '{command[0]}' not found. Please install it or add it to your PATH.")

                formatted_command = [arg.format(target=target) for arg in command]
                output = subprocess.run(formatted_command, capture_output=True, text=True, check=True)

            # Use regex to extract valid subdomains
            subdomain_pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
            subdomains = set(subdomain_pattern.findall(output.stdout))

            # Filter subdomains to include only those related to the target domain
            target_subdomains = {subdomain for subdomain in subdomains if subdomain.endswith(target)}

            return tool, target, target_subdomains, None
        except subprocess.CalledProcessError as e:
            error_msg = f"Command '{formatted_command if isinstance(formatted_command, str) else ' '.join(formatted_command)}' returned non-zero exit status {e.returncode}."
            return tool, target, set(), error_msg

    def subdomain_enumeration(self, targets: List[str], args: argparse.Namespace) -> None:
        spinner.start(f"{Fore.CYAN}Performing Subdomain Enumeration{Style.RESET_ALL}")
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
                    spinner.fail(f"{self.get_timestamp()} {Fore.LIGHTRED_EX}Error running {tool} for {target}: {error}{Style.RESET_ALL}")
                    continue
                
                all_subdomains.update(subdomains)
                
                if subdomains:
                    spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(subdomains)} subdomains for {target}{Style.RESET_ALL}")
                    for subdomain in sorted(subdomains):
                        logger.info(f"  {Fore.LIGHTYELLOW_EX}{subdomain}{Style.RESET_ALL}")
                else:
                    spinner.warn(f"{self.get_timestamp()} {Fore.YELLOW}{tool} found no subdomains for {target}{Style.RESET_ALL}")

        spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Total unique subdomains found: {len(all_subdomains)}{Style.RESET_ALL}")
        self.results['subdomains'] = list(all_subdomains)

        if args.output:
            with open(args.output, 'w') as f:
                for subdomain in sorted(all_subdomains):
                    f.write(f"{subdomain}\n")
            logger.info(f"{self.get_timestamp()} Subdomains saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        spinner.succeed(f"{Fore.GREEN}Subdomain Enumeration Complete{Style.RESET_ALL}")

    def get_timestamp(self) -> str:
        return f"{Fore.LIGHTMAGENTA_EX}[{time.strftime('%H:%M:%S')}]{Style.RESET_ALL}"

    def port_scanning(self, targets: List[str], args: argparse.Namespace) -> None:
        logger.info(f"{Fore.CYAN}Performing Port Scanning{Style.RESET_ALL}")
        all_open_ports = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for target in targets:
                for tool, command in self.config['port_scan'].items():
                    if args.exclude and tool in args.exclude:
                        continue
                    futures.append(executor.submit(self.run_port_scan, tool, command, target))

            for future in as_completed(futures):
                tool, target, open_ports, error = future.result()
                if error:
                    spinner.fail(f"{self.get_timestamp()} {Fore.LIGHTRED_EX}Error running {tool} for {target}: {error}{Style.RESET_ALL}")
                    continue
                
                if target not in all_open_ports:
                    all_open_ports[target] = set()
                all_open_ports[target].update(open_ports)
                
                if open_ports:
                    spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(open_ports)} open ports for {target}{Style.RESET_ALL}")
                    for port in sorted(open_ports):
                        logger.info(f"  {Fore.LIGHTYELLOW_EX}Port {port} is open{Style.RESET_ALL}")
                else:
                    spinner.warn(f"{self.get_timestamp()} {Fore.YELLOW}{tool} found no open ports for {target}{Style.RESET_ALL}")

        logger.info(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Total targets scanned: {len(all_open_ports)}{Style.RESET_ALL}")
        self.results['open_ports'] = all_open_ports

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(all_open_ports, f, indent=2)
            logger.info(f"{self.get_timestamp()} Port scan results saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Port Scanning Complete{Style.RESET_ALL}")

    def run_port_scan(self, tool, command, target):
        try:
            formatted_command = [arg.format(target=target) for arg in command]
            output = subprocess.run(formatted_command, capture_output=True, text=True, check=True)
            
            # Parse the output to extract open ports (this will depend on the tool used)
            open_ports = self.parse_port_scan_output(tool, output.stdout)
            
            return tool, target, open_ports, None
        except subprocess.CalledProcessError as e:
            error_msg = f"Command '{' '.join(formatted_command)}' returned non-zero exit status {e.returncode}."
            return tool, target, set(), error_msg

    def parse_port_scan_output(self, tool, output):
        # Implement parsing logic for different port scanning tools
        # This is a simplified example and may need to be adapted for each tool
        open_ports = set()
        for line in output.splitlines():
            if 'open' in line.lower():
                port = re.search(r'\d+', line)
                if port:
                    open_ports.add(int(port.group()))
        return open_ports

    def probe_alive_domains(self, targets: List[str], args: argparse.Namespace) -> None:
        logger.info(f"{Fore.CYAN}Probing for Alive Domains{Style.RESET_ALL}")
        all_alive_domains = set()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for tool, command in self.config['probe'].items():
                if args.exclude and tool in args.exclude:
                    continue
                futures.append(executor.submit(self.run_probe, tool, command, targets))

            for future in as_completed(futures):
                tool, alive_domains, error = future.result()
                if error:
                    spinner.fail(f"{self.get_timestamp()} {Fore.LIGHTRED_EX}Error running {tool}: {error}{Style.RESET_ALL}")
                    continue
                
                all_alive_domains.update(alive_domains)
                
                if alive_domains:
                    spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(alive_domains)} alive domains{Style.RESET_ALL}")
                    for domain in sorted(alive_domains):
                        logger.info(f"  {Fore.LIGHTYELLOW_EX}{domain}{Style.RESET_ALL}")
                else:
                    spinner.warn(f"{self.get_timestamp()} {Fore.YELLOW}{tool} found no alive domains{Style.RESET_ALL}")

        logger.info(f"{self.get_timestamp()} {Fore.LIGHTGREEN_EX}Total alive domains found: {len(all_alive_domains)}{Style.RESET_ALL}")
        self.results['alive_domains'] = list(all_alive_domains)

        if args.output:
            with open(args.output, 'w') as f:
                for domain in sorted(all_alive_domains):
                    f.write(f"{domain}\n")
            logger.info(f"{self.get_timestamp()} Alive domains saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Probing Complete{Style.RESET_ALL}")

    def run_probe(self, tool, command, targets):
        try:
            formatted_command = command + targets
            output = subprocess.run(formatted_command, capture_output=True, text=True, check=True)
            
            # Parse the output to extract alive domains
            alive_domains = set(line.strip() for line in output.stdout.splitlines() if line.strip())
            
            return tool, alive_domains, None
        except subprocess.CalledProcessError as e:
            error_msg = f"Command '{' '.join(formatted_command)}' returned non-zero exit status {e.returncode}."
            return tool, set(), error_msg

    def vulnerability_scanning(self, targets: List[str], args: argparse.Namespace) -> None:
        logger.info(f"{Fore.CYAN}Performing Vulnerability Scanning{Style.RESET_ALL}")
        all_vulnerabilities = {}

        vuln_types = args.type if args.type else ['all']
        if 'all' in vuln_types:
            vuln_types = list(self.config['vuln_scan'].keys())

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for target in targets:
                for vuln_type in vuln_types:
                    if vuln_type not in self.config['vuln_scan']:
                        logger.warning(f"{self.get_timestamp()} {Fore.LIGHTYELLOW_EX}Unknown vulnerability type: {vuln_type}{Style.RESET_ALL}")
                        continue
                    for tool, command in self.config['vuln_scan'][vuln_type].items():
                        if args.exclude and tool in args.exclude:
                            continue
                        if args.tool and tool not in args.tool:
                            continue
                        futures.append(executor.submit(self.run_vuln_scan, tool, command, target, vuln_type))

            for future in as_completed(futures):
                tool, target, vuln_type, vulnerabilities, error = future.result()
                if error:
                    spinner.fail(f"{self.get_timestamp()} {Fore.LIGHTRED_EX}Error running {tool} for {vuln_type} on {target}: {error}{Style.RESET_ALL}")
                    continue
                
                if target not in all_vulnerabilities:
                    all_vulnerabilities[target] = {}
                if vuln_type not in all_vulnerabilities[target]:
                    all_vulnerabilities[target][vuln_type] = []
                all_vulnerabilities[target][vuln_type].extend(vulnerabilities)
                
                if vulnerabilities:
                    spinner.succeed(f"{self.get_timestamp()} {Fore.LIGHTCYAN_EX}{tool} found {len(vulnerabilities)} {vuln_type} vulnerabilities on {target}{Style.RESET_ALL}")
                    for vuln in vulnerabilities:
                        logger.info(f"  {Fore.LIGHTYELLOW_EX}{vuln['description']}{Style.RESET_ALL}")
                else:
                    spinner.warn(f"{self.get_timestamp()} {Fore.YELLOW}{tool} found no {vuln_type} vulnerabilities on {target}{Style.RESET_ALL}")

                if args.isolate:
                    break

        self.results['vulnerabilities'] = all_vulnerabilities

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(all_vulnerabilities, f, indent=2)
            logger.info(f"{self.get_timestamp()} Vulnerabilities saved to {args.output}")
        logger.info(f"{Fore.LIGHTBLACK_EX}-----------------------------------------------------------{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}Vulnerability Scanning Complete{Style.RESET_ALL}")

    def run_vuln_scan(self, tool, command, target, vuln_type):
        try:
            formatted_command = [arg.format(target=target) for arg in command]
            output = subprocess.run(formatted_command, capture_output=True, text=True, check=True)
            
            # Parse the output to extract vulnerabilities
            vulnerabilities = self.parse_vulnerability_output(tool, output.stdout)
            
            return tool, target, vuln_type, vulnerabilities, None
        except subprocess.CalledProcessError as e:
            error_msg = f"Command '{' '.join(formatted_command)}' returned non-zero exit status {e.returncode}."
            return tool, target, vuln_type, [], error_msg

    def parse_vulnerability_output(self, tool, output):
        # Implement parsing logic for different vulnerability scanning tools
        # This is a simplified example and may need to be adapted for each tool
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

    try:
        scanner = SecurityScanner()

        if not args.command:
            parser.print_help()
            return

        targets = []
        if hasattr(args, 'target'):
            if os.path.isfile(args.target):
                with open(args.target, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            else:
                targets = [args.target]

        scan_performed = False
        if args.command == 'subenum':
            scanner.subdomain_enumeration(targets, args)
            scan_performed = True
        elif args.command == 'portscan':
            scanner.port_scanning(targets, args)
            scan_performed = True
        elif args.command == 'probe':
            scanner.probe_alive_domains(targets, args)
            scan_performed = True
        elif args.command == 'vulnscan':
            scanner.vulnerability_scanning(targets, args)
            scan_performed = True

        if scan_performed:
            print_completion_banner(scanner.results)

    except AllToolsError as e:
        logger.error(f"{type(e).__name__}: {str(e)}")
    except KeyboardInterrupt:
        spinner.stop()
        logger.warning("\nScan interrupted by user. Exiting...")
    except Exception as e:
        spinner.stop()
        logger.error(f"An unexpected error occurred: {str(e)}")
        logger.debug("", exc_info=True)
    finally:
        spinner.stop()

if __name__ == "__main__":
    main()
