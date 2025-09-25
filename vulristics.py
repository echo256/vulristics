from vulristics_code import functions_report_vulnerabilities, functions_report_ms_patch_tuesday, functions_profile
from vulristics_code.functions_cpe_search import validate_cpe, search_cves_by_cpe, get_cpe_candidates
import re
import requests
import json
import time
from urllib.parse import quote
import argparse

current_version = "1.0.10"

parser = argparse.ArgumentParser(description='An extensible framework for analyzing publicly available information about vulnerabilities')
const = ""

parser.add_argument('--report-type', help='Report type (ms_patch_tuesday, ms_patch_tuesday_extended, cve_list, cpe_search, product_search or custom_profile)')
parser.add_argument('--mspt-year', help='Microsoft Patch Tuesday year')
parser.add_argument('--mspt-month', help='Microsoft Patch Tuesday month')
parser.add_argument('--mspt-comments-links-path', help='Microsoft Patch Tuesday comments links file. Format: "Qualys|Description|URL"')
parser.add_argument('--cve-project-name', help='Name of the CVE Project')
parser.add_argument('--cve-list-path', help='Path to the list of CVE IDs (each per line)')
parser.add_argument('--cve-comments-path', help='Path to the CVE comments file (optional)')
parser.add_argument('--cve-data-sources', help='Data sources for analysis, e.g. "ms,nvd,bdu,epss,vulners,attackerkb,bdu,custom" (default: "ms,nvd,epss,vulners,attackerkb,bdu,custom")', default='ms,nvd,epss,vulners,attackerkb,bdu,custom')
parser.add_argument('--cpe', help='[DEPRECATED] Single CPE identifier for vulnerability search')
parser.add_argument('--cpe-list', help='[DEPRECATED] Path to file with CPE identifiers (one per line)')
parser.add_argument('--product', help='Single product name with optional version (e.g., "nginx 1.20.1")')
parser.add_argument('--product-list', help='Path to file with product names (one per line)')
parser.add_argument('--profile-json-path', help='Custom profile for analysis')
parser.add_argument('--result-formats', help='Result formats, e.g. "html,json", Default - "html"')
parser.add_argument('--result-html-path', help='Path to the results file in html format (Default - will be created in reports directory)')
parser.add_argument('--result-html-label', help='Additional optional banner for HTML report ("lpw" for the Linux Patch Wednesday banner, "mspt" for the Microsoft Patch Tuesday banner or custom image URL)')
parser.add_argument('--result-json-path', help='Path to the results file in json format')
parser.add_argument('--rewrite-flag', help='Rewrite Flag (True/False, Default - True)', default='False')
parser.add_argument('--vulners-use-github-exploits-flag', help='Use Vulners Github exploits data Flag (True/False, Default - True)')
parser.add_argument('--bdu-use-product-names-flag', help='Use BDU product names Flag (True/False, Default - False)', default='False')
parser.add_argument('--bdu-use-vulnerability-descriptions-flag', help='Use BDU vulnerability descriptions data Flag (True/False, Default - False)', default='False')
parser.add_argument('-v', '--version', action='version', version=current_version)

args = parser.parse_args()
banner = r'''
                      /$$           /$$             /$$     /$$                    
                     | $$          |__/            | $$    |__/                    
 /$$    /$$ /$$   /$$| $$  /$$$$$$  /$$  /$$$$$$$ /$$$$$$   /$$  /$$$$$$$  /$$$$$$$
|  $$  /$$/| $$  | $$| $$ /$$__  $$| $$ /$$_____/|_  $$_/  | $$ /$$_____/ /$$_____/
 \  $$/$$/ | $$  | $$| $$| $$  \__/| $$|  $$$$$$   | $$    | $$| $$      |  $$$$$$ 
  \  $$$/  | $$  | $$| $$| $$      | $$ \____  $$  | $$ /$$| $$| $$       \____  $$
   \  $/   |  $$$$$$/| $$| $$      | $$ /$$$$$$$/  |  $$$$/| $$|  $$$$$$$ /$$$$$$$/
    \_/     \______/ |__/|__/      |__/|_______/    \___/  |__/ \_______/|_______/ '''

print("\n", re.sub("^\n","",banner), "\n")


def process_cpe_search():
    """Process CPE search and generate CVE report"""
    cpe_list = []
    
    # Collect CPEs from arguments
    if args.cpe:
        validated_cpe = validate_cpe(args.cpe)
        if validated_cpe:
            cpe_list.append(validated_cpe)
    
    if args.cpe_list:
        try:
            with open(args.cpe_list, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        validated_cpe = validate_cpe(line)
                        if validated_cpe:
                            cpe_list.append(validated_cpe)
        except FileNotFoundError:
            print(f"Error: CPE list file not found: {args.cpe_list}")
            return
        except Exception as e:
            print(f"Error reading CPE list file: {e}")
            return
    
    if not cpe_list:
        print("Error: No valid CPEs provided")
        return
    
    print(f"Processing {len(cpe_list)} CPE(s)...")
    
    # Search CVEs for all CPEs
    all_cves = set()
    for cpe in cpe_list:
        cves = search_cves_by_cpe(cpe)
        all_cves.update(cves)
        print(f"CPE {cpe}: found {len(cves)} CVEs")
    
    if not all_cves:
        print("No CVEs found for provided CPE(s)")
        return
    
    print(f"Total unique CVEs found: {len(all_cves)}")
    
    # Generate project name
    if args.cve_project_name:
        project_name = args.cve_project_name
    else:
        if len(cpe_list) == 1:
            # Extract vendor and product from CPE for project name
            parts = cpe_list[0].split(':')
            if len(parts) >= 4:
                vendor = parts[2] if parts[2] != '*' else 'unknown'
                product = parts[3] if parts[3] != '*' else 'product'
                project_name = f"{vendor}_{product}_cpe_analysis"
            else:
                project_name = "cpe_analysis"
        else:
            project_name = f"multiple_cpe_analysis_{len(cpe_list)}_cpes"
    
    # Create temporary CVE list file
    import tempfile
    import os
    
    temp_cve_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    try:
        temp_cve_file.write('\n'.join(sorted(all_cves)))
        temp_cve_file.close()
        
        # Create comments with CPE information
        comments = {
            'CPE Analysis': f"Analysis based on {len(cpe_list)} CPE identifier(s):\n" + '\n'.join(f"- {cpe}" for cpe in cpe_list) + f"\n\nTotal CVEs found: {len(all_cves)}"
        }
        
        # Generate report using existing functionality
        name = project_name
        report_name = name + ' report'
        file_name_prefix = re.sub(" ","_",name).lower()
        
        cve_list_text = '\n'.join(sorted(all_cves))
        products_text = ""
        
        file_name = name + "_profile.json"
        report_id = name + "_report"
        
        profile_file_path = "data/profiles/" + file_name
        functions_profile.save_profile(profile_file_path=profile_file_path,
                                       report_id=report_id,
                                       report_name=report_name,
                                       file_name_prefix=file_name_prefix,
                                       cve_list_text=cve_list_text,
                                       products_text=products_text,
                                       data_sources=source_config['data_sources'],
                                       comments=comments)
        
        functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path=profile_file_path,
                                                                               source_config=source_config,
                                                                               result_config=result_config)
        
    finally:
        # Clean up temporary file
        if os.path.exists(temp_cve_file.name):
            os.unlink(temp_cve_file.name)


def process_product_search():
    """Process product search and generate CVE report"""
    product_list = []
    
    # Collect products from arguments
    if args.product:
        product_list.append(args.product.strip())
    
    if args.product_list:
        try:
            with open(args.product_list, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        product_list.append(line)
        except FileNotFoundError:
            print(f"Error: Product list file not found: {args.product_list}")
            return
        except Exception as e:
            print(f"Error reading product list file: {e}")
            return
    
    if not product_list:
        print("Error: No products provided")
        return
    
    print(f"Processing {len(product_list)} product(s)...")
    
    # Convert products to CPEs and search CVEs
    all_cves = set()
    product_to_cpes = {}
    
    for product_name in product_list:
        try:
            cpe_candidates = get_cpe_candidates(product_name)
            product_to_cpes[product_name] = cpe_candidates
            
            if not cpe_candidates:
                print(f"Warning: No CPEs found for product '{product_name}'")
                continue
            
            print(f"Product '{product_name}': found {len(cpe_candidates)} CPE(s)")
            
            # Search CVEs for all CPE candidates
            product_cves = set()
            for cpe in cpe_candidates:
                cves = search_cves_by_cpe(cpe)
                product_cves.update(cves)
            
            all_cves.update(product_cves)
            print(f"Product '{product_name}': found {len(product_cves)} unique CVEs")
            
        except Exception as e:
            print(f"Error processing product '{product_name}': {e}")
            continue
    
    if not all_cves:
        print("No CVEs found for provided product(s)")
        return
    
    print(f"Total unique CVEs found across all products: {len(all_cves)}")
    
    # Generate project name
    if args.cve_project_name:
        project_name = args.cve_project_name
    else:
        if len(product_list) == 1:
            # Use product name for project name
            clean_product_name = re.sub(r'[^a-zA-Z0-9_\s]', '', product_list[0])
            project_name = re.sub(r'\s+', '_', clean_product_name.strip()).lower() + "_product_analysis"
        else:
            project_name = f"multiple_product_analysis_{len(product_list)}_products"
    
    # Create comments with product and CPE information
    comments = {
        'Product Analysis': f"Analysis based on {len(product_list)} product(s):\n"
    }
    
    for product_name, cpes in product_to_cpes.items():
        if cpes:
            comments['Product Analysis'] += f"\n• {product_name}:\n"
            for cpe in sorted(cpes):
                comments['Product Analysis'] += f"  - {cpe}\n"
        else:
            comments['Product Analysis'] += f"\n• {product_name}: No CPEs found\n"
    
    comments['Product Analysis'] += f"\nTotal unique CVEs found: {len(all_cves)}"
    
    # Generate report using existing functionality
    name = project_name
    report_name = name + ' report'
    file_name_prefix = re.sub(" ","_",name).lower()
    
    cve_list_text = '\n'.join(sorted(all_cves))
    products_text = ""
    
    file_name = name + "_profile.json"
    report_id = name + "_report"
    
    profile_file_path = "data/profiles/" + file_name
    functions_profile.save_profile(profile_file_path=profile_file_path,
                                   report_id=report_id,
                                   report_name=report_name,
                                   file_name_prefix=file_name_prefix,
                                   cve_list_text=cve_list_text,
                                   products_text=products_text,
                                   data_sources=source_config['data_sources'],
                                   comments=comments)
    
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path=profile_file_path,
                                                                           source_config=source_config,
                                                                           result_config=result_config)

source_config = dict()

source_config['rewrite_flag'] = False
if args.rewrite_flag == "True" or args.rewrite_flag == "true":
    source_config['rewrite_flag'] = True

source_config['vulners_use_github_exploits_flag'] = True
if args.vulners_use_github_exploits_flag == "False" or args.vulners_use_github_exploits_flag == "false":
    source_config['vulners_use_github_exploits_flag'] = False

source_config['bdu_use_product_names_flag'] = True
if args.bdu_use_product_names_flag == "False" or args.bdu_use_product_names_flag == "false":
    source_config['bdu_use_product_names_flag'] = False

source_config['bdu_use_vulnerability_descriptions_flag'] = True
if args.bdu_use_vulnerability_descriptions_flag == "False" or args.bdu_use_vulnerability_descriptions_flag == "false":
    source_config['bdu_use_vulnerability_descriptions_flag'] = False

source_config['data_sources'] = []
if args.cve_data_sources:
    source_config['data_sources'] = args.cve_data_sources.split(",")

result_config = dict()

if args.result_formats:
    result_config['result_formats'] = set(args.result_formats.split(","))
else:
    result_config['result_formats'] = {'html'}

if args.result_json_path:
    result_config['result_json_path'] = args.result_json_path
    result_config['result_formats'].add('json')
else:
    result_config['result_json_path'] = False

if args.result_html_path:
    result_config['result_html_path'] = args.result_html_path
    result_config['result_formats'].add('html')
else:
    result_config['result_html_path'] = False

if args.result_html_label:
    result_config['result_html_label'] = args.result_html_label
else:
    result_config['result_html_label'] = False

if args.report_type == "ms_patch_tuesday" or args.report_type == "ms_patch_tuesday_extended":
    year = str(args.mspt_year) # 2021
    month = args.mspt_month # September
    if not result_config['result_html_label']:
        result_config['result_html_label'] = "mspt"

    comments_links_path = False
    if args.mspt_comments_links_path:
        comments_links_path = args.mspt_comments_links_path

    if args.report_type == "ms_patch_tuesday":
        pt_type = "Normal"
    elif args.report_type == "ms_patch_tuesday_extended":
        pt_type = "Extended"

    functions_report_ms_patch_tuesday.make_ms_patch_tuesday_report(pt_type=pt_type,
                                                                   year=year,
                                                                   month=month,
                                                                   comments_links_path = comments_links_path,
                                                                   source_config=source_config,
                                                                   result_config=result_config)

elif args.report_type == "cpe_search":
    # Check for deprecated CPE parameter usage and show warnings
    if args.cpe or args.cpe_list:
        print("[DEPRECATION WARNING] The --cpe and --cpe-list parameters are deprecated.")
        print("Please use --product and --product-list instead for better usability.")
        print("Example: Instead of --cpe 'cpe:/a:nginx:nginx:1.20.1', use --product 'nginx 1.20.1'")
        print("")
    process_cpe_search()

elif args.report_type == "product_search":
    process_product_search()

elif args.report_type == "cve_list":

    name = args.cve_project_name
    report_name = name + ' report'
    file_name_prefix = re.sub(" ","_",name).lower()

    cve_list_text = ""
    with open(args.cve_list_path, 'r') as file:
        cve_list_text = file.read()

    comments = dict()
    if args.cve_comments_path:
        with open(args.cve_comments_path, 'r') as file:
            cve_comments_text = file.read()
            if cve_comments_text != "":
                for line in cve_comments_text.split("\n"):
                    if "|" in line:
                        group = line.split("|")[0]
                        line = re.sub(r"[^\|]*\|","",line)
                    else:
                        group = "Comment"
                    if not group in comments:
                        comments[group] = ""
                    comments[group] += line + "\n"

    products_text = ""

    file_name = name + "_profile.json"
    report_id = name + "_report"

    profile_file_path = "data/profiles/" + file_name
    functions_profile.save_profile(profile_file_path=profile_file_path,
                                   report_id=report_id,
                                   report_name=report_name,
                                   file_name_prefix=file_name_prefix,
                                   cve_list_text=cve_list_text,
                                   products_text=products_text,
                                   data_sources=source_config['data_sources'],
                                   comments=comments)
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path=profile_file_path,
                                                                           source_config=source_config,
                                                                           result_config=result_config)

elif args.report_type == "custom_profile":
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path=args.profile_json_path,
                                                                           source_config=source_config,
                                                                           result_config=result_config)
else:
    parser.print_help()
    print('\nExamples:')
    print('# Simple CVE list analysis (with improved defaults):')
    print('$ python3 vulristics.py --report-type "cve_list" --cve-project-name "New Project" --cve-list-path "cves.txt"')
    print('')
    print('# Microsoft Patch Tuesday analysis:')
    print('$ python3 vulristics.py --report-type "ms_patch_tuesday" --mspt-year 2024 --mspt-month "August"')
    print('')
    print('# CPE-based vulnerability search (deprecated, use product_search instead):')
    print('$ python3 vulristics.py --report-type "cpe_search" --cpe "cpe:/a:apache:tomcat:9.0.0"')
    print('$ python3 vulristics.py --report-type "cpe_search" --cpe-list "cpe_list.txt" --cve-project-name "My CPE Analysis"')
    print('')
    print('# Product-based vulnerability search (recommended):')
    print('$ python3 vulristics.py --report-type "product_search" --product "nginx 1.20.1"')
    print('$ python3 vulristics.py --report-type "product_search" --product "apache http server"')
    print('$ python3 vulristics.py --report-type "product_search" --product-list "products.txt" --cve-project-name "My Product Analysis"')