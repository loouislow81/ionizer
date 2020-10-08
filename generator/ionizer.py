#!/usr/bin/env python3

import argparse
import fnmatch
import json
import locale
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from glob import glob

PY3 = sys.version_info >= (3, 0)

if not PY3:
    raise Exception("Python 2.x not supported! Use 3.x instead.")


try:
    import requests
except ImportError:
    raise ImportError("The requests library (https://requests.readthedocs.io/en/master/).")


if platform.system() == "OpenBSD":
    SUDO = ["/usr/bin/doas"]
else:
    SUDO = ["/usr/bin/env", "sudo"]


BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))


class Colors(object):
    PROMPT = "\033[94m"
    SUCCESS = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"


def default_settings():

    return {
        "numberofrules": 0,
        "datageneralpath": path_join_robust(BASEDIR_PATH, "data/general"),
        "freshen": True,
        "replace": False,
        "backup": False,
        "skipstatichosts": False,
        "keepdomaincomments": True,
        "dataclasspath": path_join_robust(BASEDIR_PATH, "data/class"),
        "classextensions": [],
        "compress": False,
        "minimise": False,
        "outputsubfolder": "build",
        "hostfilename": "filters",
        "targetip": "0.0.0.0",
        "sourcedatafilename": "update.json",
        "sourcesdata": [],
        "exclusionpattern": r"([a-zA-Z\d-]+\.){0,}",
        "exclusionregexs": [],
        "exclusions": [],
        "commonexclusions": [
            "hulu.com"
        ],
        "datablacklist": path_join_robust(BASEDIR_PATH, "data/exclusions/blacklist"),
        "datawhitelist": path_join_robust(BASEDIR_PATH, "data/exclusions/whitelist"),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Creates a unified hosts file from hosts stored in the data subfolders."
    )
    parser.add_argument(
        "--auto",
        "-a",
        dest="auto",
        default=False,
        action="store_true",
        help="Run without prompting.",
    )
    parser.add_argument(
        "--backup",
        "-b",
        dest="backup",
        default=False,
        action="store_true",
        help="Backup the hosts files before they are overridden.",
    )
    parser.add_argument(
        "--classextensions",
        "-e",
        dest="classextensions",
        default=[],
        nargs="*",
        help="Host classextensions to include in the final hosts file.",
    )
    parser.add_argument(
        "--ip",
        "-i",
        dest="targetip",
        default="0.0.0.0",
        help="Mask IP address. Default is 0.0.0.0.",
    )
    parser.add_argument(
        "--keepdomaincomments",
        "-k",
        dest="keepdomaincomments",
        action="store_false",
        default=True,
        help="Do not keep domain line comments.",
    )
    parser.add_argument(
        "--noupdate",
        "-n",
        dest="noupdate",
        default=False,
        action="store_true",
        help="Don't update from host data sources.",
    )
    parser.add_argument(
        "--skipstatichosts",
        "-s",
        dest="skipstatichosts",
        default=False,
        action="store_true",
        help="Skip static localhost entries in the final hosts file.",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="outputsubfolder",
        default="build",
        help="Output subfolder for generated hosts file.",
    )
    parser.add_argument(
        "--replace",
        "-r",
        dest="replace",
        default=False,
        action="store_true",
        help="Replace your active hosts file with this new hosts file.",
    )
    parser.add_argument(
        "--flush-dns-cache",
        "-f",
        dest="flushdnscache",
        default=False,
        action="store_true",
        help="Attempt to flush DNS cache after replacing the hosts file.",
    )
    parser.add_argument(
        "--compress",
        "-c",
        dest="compress",
        default=False,
        action="store_true",
        help="Compress the hosts file ignoring non-necessary lines "
        "(empty lines and comments) and putting multiple domains in "
        "each line. Improve the performance under Windows.",
    )
    parser.add_argument(
        "--minimise",
        "-m",
        dest="minimise",
        default=False,
        action="store_true",
        help="Minimise the hosts file ignoring non-necessary lines "
        "(empty lines and comments).",
    )
    parser.add_argument(
        "--whitelist",
        "-w",
        dest="datawhitelist",
        default=path_join_robust(BASEDIR_PATH, "whitelist"),
        help="Whitelist file to use while generating hosts files.",
    )
    parser.add_argument(
        "--blacklist",
        "-x",
        dest="datablacklist",
        default=path_join_robust(BASEDIR_PATH, "blacklist"),
        help="Blacklist file to use while generating hosts files.",
    )

    global settings

    options = vars(parser.parse_args())

    options["outputpath"] = path_join_robust(BASEDIR_PATH, options["outputsubfolder"])
    options["freshen"] = not options["noupdate"]

    settings = default_settings()
    settings.update(options)

    data_path = settings["datageneralpath"]
    classextensions_path = settings["dataclasspath"]

    settings["sources"] = list_dir_no_hidden(data_path)
    settings["classextensionsources"] = list_dir_no_hidden(classextensions_path)

    # set classextensions dir...
    settings["classextensions"] = [
        os.path.basename(item) for item in list_dir_no_hidden(classextensions_path)
    ]
    # ... intersected with the classextensions passed-in as arguments, then sorted.
    settings["classextensions"] = sorted(
        list(set(options["classextensions"]).intersection(settings["classextensions"]))
    )

    auto = settings["auto"]
    exclusion_regexes = settings["exclusionregexs"]
    source_data_filename = settings["sourcedatafilename"]

    update_sources = update_data_source(freshen=settings["freshen"], update_auto=auto)
    if update_sources:
        update_all_sources(source_data_filename, settings["hostfilename"])

    gather_exclusions = update_exclusions_data(skip_prompt=auto)

    if gather_exclusions:
        common_exclusions = settings["commonexclusions"]
        exclusion_pattern = settings["exclusionpattern"]
        exclusion_regexes = exclusion_options(
            common_exclusions=common_exclusions,
            exclusion_pattern=exclusion_pattern,
            exclusion_regexes=exclusion_regexes,
        )

    classextensions = settings["classextensions"]
    sources_data = update_sources_data(
        settings["sourcesdata"],
        datageneralpath=data_path,
        classextensions=classextensions,
        dataclasspath=classextensions_path,
        sourcedatafilename=source_data_filename,
    )

    merge_file = create_initial_file()
    remove_old_hosts_file(
        path_join_robust(settings["outputpath"], "hosts"), settings["backup"]
    )
    if settings["compress"]:
        final_file = open(path_join_robust(settings["outputpath"], "hosts"), "w+b")
        compressed_file = tempfile.NamedTemporaryFile()
        remove_dups_and_excl(merge_file, exclusion_regexes, compressed_file)
        compress_file(compressed_file, settings["targetip"], final_file)
    elif settings["minimise"]:
        final_file = open(path_join_robust(settings["outputpath"], "hosts"), "w+b")
        minimised_file = tempfile.NamedTemporaryFile()
        remove_dups_and_excl(merge_file, exclusion_regexes, minimised_file)
        minimise_file(minimised_file, settings["targetip"], final_file)
    else:
        final_file = remove_dups_and_excl(merge_file, exclusion_regexes)

    number_of_rules = settings["numberofrules"]
    output_subfolder = settings["outputsubfolder"]
    skip_static_hosts = settings["skipstatichosts"]

    write_opening_header(
        final_file,
        classextensions=classextensions,
        numberofrules=number_of_rules,
        outputsubfolder=output_subfolder,
        skipstatichosts=skip_static_hosts,
    )
    final_file.close()

    print_success(
        "Success! The hosts file has been saved in folder "
        + output_subfolder
        + "\nIt contains "
        + "{:,}".format(number_of_rules)
        + " unique entries."
    )

    move_file = replace_hosts_file(
        final_file,
        auto=auto,
        replace=settings["replace"],
        skipstatichosts=skip_static_hosts,
    )

    # flush the DNS cache if have moved a new hosts file into place.
    if move_file:
        prompt_for_flush_dns_cache(
            flush_cache=settings["flushdnscache"], prompt_flush=not auto
        )


def update_data_source(freshen, update_auto):

    # create a hosts file if it doesn't exist.
    hosts_file = path_join_robust(BASEDIR_PATH, "hosts")

    if not os.path.isfile(hosts_file):
        try:
            open(hosts_file, "w+").close()
        except (IOError, OSError):
            print_failure("ERROR: No 'hosts' file in the folder. Try creating one manually.")

    if not freshen:
        return

    prompt = "Do you want to update all data from source servers?"

    if update_auto or query_yes_no(prompt):
        return True
    elif not update_auto:
        print("Ignored. Use existing hosts file locally.")

    return False


def update_exclusions_data(skip_prompt):

    prompt = ("Do you want to exclude any domains?")

    if not skip_prompt:
        if query_yes_no(prompt):
            return True
        else:
            print("Ignored. Right now is exclude only domains in the whitelist.")

    return False


def prompt_for_flush_dns_cache(flush_cache, prompt_flush):

    if flush_cache:
        flush_dns_cache()
    elif prompt_flush:
        if query_yes_no("Attempt to flush the DNS cache?"):
            flush_dns_cache()


def replace_hosts_file(final_file, **move_params):

    skip_static_hosts = move_params["skipstatichosts"]

    if move_params["replace"] and not skip_static_hosts:
        move_file = True
    elif move_params["auto"] or skip_static_hosts:
        move_file = False
    else:
        prompt = "Do you want to replace existing hosts file with the newly generated?"
        move_file = query_yes_no(prompt)

    if move_file:
        move_hosts_file_into_place(final_file)

    return move_file


def sort_sources(sources):

    result = sorted(
        sources.copy(),
        key=lambda x: x.lower().replace("-", "").replace("_", "").replace(" ", ""),
    )

    # set ionizer's repositories/files/lists should be on top!
    ionizer_positions = [
        x for x, y in enumerate(result) if "ionizer" in y.lower()
    ]

    for index in ionizer_positions:
        result.insert(0, result.pop(index))

    return result


def exclusion_options(common_exclusions, exclusion_pattern, exclusion_regexes):

    for exclusion_option in common_exclusions:
        prompt = "Do you want to exclude the domain " + exclusion_option + " ?"

        if query_yes_no(prompt):
            exclusion_regexes = exclude_domain(
                exclusion_option, exclusion_pattern, exclusion_regexes
            )
        else:
            continue

    if query_yes_no("Do you want to exclude any other domains?"):
        exclusion_regexes = gather_custom_exclusions(
            exclusion_pattern, exclusion_regexes
        )

    return exclusion_regexes


def gather_custom_exclusions(exclusion_pattern, exclusion_regexes):

    # continue running this while-loop until the user
    # have no more domains to exclude.
    while True:
        domain_prompt = "Enter the domain you want to exclude (e.g. youtube.com): "
        user_domain = input(domain_prompt)

        if is_valid_domain_format(user_domain):
            exclusion_regexes = exclude_domain(
                user_domain, exclusion_pattern, exclusion_regexes
            )

        continue_prompt = "Do you want to add more domains?"
        if not query_yes_no(continue_prompt):
            break

    return exclusion_regexes


def exclude_domain(domain, exclusion_pattern, exclusion_regexes):

    exclusion_regex = re.compile(exclusion_pattern + domain)
    exclusion_regexes.append(exclusion_regex)

    return exclusion_regexes


def matches_exclusions(stripped_rule, exclusion_regexes):

    stripped_domain = stripped_rule.split()[1]

    for exclusionRegex in exclusion_regexes:
        if exclusionRegex.search(stripped_domain):
            return True

    return False


def update_sources_data(sources_data, **sources_params):

    source_data_filename = sources_params["sourcedatafilename"]

    for source in sort_sources(
        recursive_glob(sources_params["datageneralpath"], source_data_filename)
    ):
        update_file = open(source, "r", encoding="UTF-8")
        update_data = json.load(update_file)
        sources_data.append(update_data)
        update_file.close()

    for source in sources_params["classextensions"]:
        source_dir = path_join_robust(sources_params["dataclasspath"], source)
        for update_file_path in sort_sources(
            recursive_glob(source_dir, source_data_filename)
        ):
            update_file = open(update_file_path, "r")
            update_data = json.load(update_file)

            sources_data.append(update_data)
            update_file.close()

    return sources_data


def jsonarray(json_array_string):

    temp_list = json.loads(json_array_string)
    hostlines = "127.0.0.1 " + "\n127.0.0.1 ".join(temp_list)
    return hostlines


def update_all_sources(source_data_filename, host_filename):

    transform_methods = {"jsonarray": jsonarray}

    all_sources = sort_sources(recursive_glob("*", source_data_filename))

    for source in all_sources:
        update_file = open(source, "r", encoding="UTF-8")
        update_data = json.load(update_file)
        update_file.close()
        update_url = update_data["url"]
        update_transforms = []
        if update_data.get("transforms"):
            update_transforms = update_data["transforms"]

        print("Updating source " + os.path.dirname(source) + " from " + update_url)

        try:
            updated_file = get_file_by_url(update_url)

            # spin the transforms as required
            for transform in update_transforms:
                updated_file = transform_methods[transform](updated_file)

            # get rid of carriage-return symbols
            updated_file = updated_file.replace("\r", "")

            hosts_file = open(
                path_join_robust(BASEDIR_PATH, os.path.dirname(source), host_filename),
                "wb",
            )
            write_data(hosts_file, updated_file)
            hosts_file.close()
        except Exception:
            print("Error in updating source: ", update_url)


def create_initial_file():

    merge_file = tempfile.NamedTemporaryFile()

    # iterate the sources for the base file
    for source in sort_sources(
        recursive_glob(settings["datageneralpath"], settings["hostfilename"])
    ):

        start = "# Start {}\n\n".format(os.path.basename(os.path.dirname(source)))
        end = "# End {}\n\n".format(os.path.basename(os.path.dirname(source)))

        with open(source, "r", encoding="UTF-8") as curFile:
            write_data(merge_file, start + curFile.read() + end)

    # iterate the sources for classextensions to the base file
    for source in settings["classextensions"]:
        for filename in sort_sources(
            recursive_glob(
                path_join_robust(settings["dataclasspath"], source),
                settings["hostfilename"],
            )
        ):
            with open(filename, "r") as curFile:
                write_data(merge_file, curFile.read())

    maybe_copy_example_file(settings["datablacklist"])

    if os.path.isfile(settings["datablacklist"]):
        with open(settings["datablacklist"], "r") as curFile:
            write_data(merge_file, curFile.read())

    return merge_file


def compress_file(input_file, target_ip, output_file):

    input_file.seek(0)  # reset file pointer
    write_data(output_file, "\n")

    target_ip_len = len(target_ip)
    lines = [target_ip]
    lines_index = 0
    for line in input_file.readlines():
        line = line.decode("UTF-8")

        if line.startswith(target_ip):
            if lines[lines_index].count(" ") < 9:
                lines[lines_index] += (
                    " " + line[target_ip_len : line.find("#")].strip()  # noqa: E203
                )
            else:
                lines[lines_index] += "\n"
                lines.append(line[: line.find("#")].strip())
                lines_index += 1

    for line in lines:
        write_data(output_file, line)

    input_file.close()


def minimise_file(input_file, target_ip, output_file):

    input_file.seek(0)  # reset file pointer
    write_data(output_file, "\n")

    lines = []
    for line in input_file.readlines():
        line = line.decode("UTF-8")

        if line.startswith(target_ip):
            lines.append(line[: line.find("#")].strip() + "\n")

    for line in lines:
        write_data(output_file, line)

    input_file.close()


def remove_dups_and_excl(merge_file, exclusion_regexes, output_file=None):

    number_of_rules = settings["numberofrules"]
    maybe_copy_example_file(settings["datawhitelist"])

    if os.path.isfile(settings["datawhitelist"]):
        with open(settings["datawhitelist"], "r") as ins:
            for line in ins:
                line = line.strip(" \t\n\r")
                if line and not line.startswith("#"):
                    settings["exclusions"].append(line)

    if not os.path.exists(settings["outputpath"]):
        os.makedirs(settings["outputpath"])

    if output_file is None:
        final_file = open(path_join_robust(settings["outputpath"], "hosts"), "w+b")
    else:
        final_file = output_file

    merge_file.seek(0)  # reset file pointer
    hostnames = {"localhost", "localhost.localdomain", "local", "broadcasthost"}
    exclusions = settings["exclusions"]

    for line in merge_file.readlines():
        write_line = True

        # explicit encoding
        line = line.decode("UTF-8")

        # replace tabs with space
        line = line.replace("\t+", " ")

        # trim trailing whitespace, periods
        line = line.rstrip(" .")

        # testing the first character doesn't require startswith
        if line[0] == "#" or re.match(r"^\s*$", line[0]):
            write_data(final_file, line)
            continue
        if "::1" in line:
            continue

        stripped_rule = strip_rule(line)  # strip comments
        if not stripped_rule or matches_exclusions(stripped_rule, exclusion_regexes):
            continue

        # Normalize rule
        hostname, normalized_rule = normalize_rule(
            stripped_rule,
            target_ip=settings["targetip"],
            keep_domain_comments=settings["keepdomaincomments"],
        )

        for exclude in exclusions:
            if re.search(r"[\s\.]" + re.escape(exclude) + r"\s", line):
                write_line = False
                break

        if normalized_rule and (hostname not in hostnames) and write_line:
            write_data(final_file, normalized_rule)
            hostnames.add(hostname)
            number_of_rules += 1

    settings["numberofrules"] = number_of_rules
    merge_file.close()

    if output_file is None:
        return final_file


def normalize_rule(rule, target_ip, keep_domain_comments):

    regex = r"^\s*(\d{1,3}\.){3}\d{1,3}\s+([\w\.-]+[a-zA-Z])(.*)"
    result = re.search(regex, rule)

    if result:
        hostname, suffix = result.group(2, 3)

        # explicitly lowercase and trim the hostname.
        hostname = hostname.lower().strip()
        rule = "%s %s" % (target_ip, hostname)

        if suffix and keep_domain_comments:
            if not suffix.strip().startswith("#"):
                rule += " #%s" % suffix
            else:
                rule += " %s" % suffix

        return hostname, rule + "\n"

    regex = r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(.*)"
    result = re.search(regex, rule)

    if result:
        ip_host, suffix = result.group(2, 3)
        # explicitly trim the ip host.
        ip_host = ip_host.strip()
        rule = "%s %s" % (target_ip, ip_host)

        if suffix and keep_domain_comments:
            if not suffix.strip().startswith("#"):
                rule += " #%s" % suffix
            else:
                rule += " %s" % suffix

        return ip_host, rule + "\n"

    print("==>%s<==" % rule)
    return None, None


def strip_rule(line):

    split_line = line.split()
    if len(split_line) < 2:
        # return blank
        return ""
    else:
        return " ".join(split_line)


def write_opening_header(final_file, **header_params):

    final_file.seek(0)  # reset file pointer
    file_contents = final_file.read()  # save content

    final_file.seek(0)  # write at the top

    if header_params["classextensions"]:
        if len(header_params["classextensions"]) > 1:
            write_data(
                final_file,
                "# Title: loouislow81/ionizer with the {0} and {1} classextensions\n#\n".format(
                    ", ".join(header_params["classextensions"][:-1]),
                    header_params["classextensions"][-1],
                ),
            )
        else:
            write_data(
                final_file,
                "# Title: loouislow81/ionizer with the {0} extension\n#\n".format(
                    ", ".join(header_params["classextensions"])
                ),
            )
    else:
        write_data(final_file, "# Title: loouislow81/ionizer\n#\n")

    write_data(
        final_file,
        "# This hosts file is a merged collection "
        "of hosts from reputable sources,\n",
    )
    write_data(final_file, "# with a dash of crowd sourcing via GitHub\n#\n")
    write_data(
        final_file,
        "# Date: " + time.strftime("%d %B %Y %H:%M:%S (%Z)", time.gmtime()) + "\n",
    )

    if header_params["classextensions"]:
        write_data(
            final_file,
            "# Extensions added to this file: "
            + ", ".join(header_params["classextensions"])
            + "\n",
        )

    write_data(
        final_file,
        (
            "# Number of unique domains: {:,}\n#\n".format(
                header_params["numberofrules"]
            )
        ),
    )
    write_data(
        final_file,
        "# Fetch the latest version of this file: "
        "https://raw.githubusercontent.com/loouislow81/ionizer/master/"
        + path_join_robust(header_params["outputsubfolder"], "").replace("\\", "/")
        + "hosts\n",
    )
    write_data(
        final_file, "# Project home page: https://github.com/loouislow81/ionizer\n"
    )
    write_data(
        final_file,
        "# Project releases: https://github.com/loouislow81/ionizer/releases\n#\n",
    )
    write_data(
        final_file,
        "# ---------------------------------------------------------------\n",
    )
    write_data(final_file, "\n")

    if not header_params["skipstatichosts"]:
        write_data(final_file, "127.0.0.1 localhost\n")
        write_data(final_file, "127.0.0.1 localhost.localdomain\n")
        write_data(final_file, "127.0.0.1 local\n")
        write_data(final_file, "255.255.255.255 broadcasthost\n")
        write_data(final_file, "::1 localhost\n")
        write_data(final_file, "::1 ip6-localhost\n")
        write_data(final_file, "::1 ip6-loopback\n")
        write_data(final_file, "fe80::1%lo0 localhost\n")
        write_data(final_file, "ff00::0 ip6-localnet\n")
        write_data(final_file, "ff00::0 ip6-mcastprefix\n")
        write_data(final_file, "ff02::1 ip6-allnodes\n")
        write_data(final_file, "ff02::2 ip6-allrouters\n")
        write_data(final_file, "ff02::3 ip6-allhosts\n")
        write_data(final_file, "0.0.0.0 0.0.0.0\n")

        if platform.system() == "Linux":
            write_data(final_file, "127.0.1.1 " + socket.gethostname() + "\n")
            write_data(final_file, "127.0.0.53 " + socket.gethostname() + "\n")

        write_data(final_file, "\n")

    preamble = path_join_robust(BASEDIR_PATH, "myhosts")
    maybe_copy_example_file(preamble)

    if os.path.isfile(preamble):
        with open(preamble, "r") as f:
            write_data(final_file, f.read())

    final_file.write(file_contents)


def move_hosts_file_into_place(final_file):

    filename = os.path.abspath(final_file.name)

    if os.name == "posix":
        print(
            "Moving the file requires administrative privileges. You might need to enter your password."
        )
        if subprocess.call(SUDO + ["cp", filename, "/etc/hosts"]):
            print_failure("Moving the file failed.")
    elif os.name == "nt":
        print("Automatically moving the hosts file in place is not yet supported.")
        print(
            "Please move the generated file to %SystemRoot%\\system32\\drivers\\etc\\hosts"
        )


def flush_dns_cache():

    print("Flushing the DNS cache to utilize new hosts file...")
    print("Flushing the DNS cache requires administrative privileges. You might need to enter your password.")

    dns_cache_found = False

    if platform.system() == "Darwin":
        if subprocess.call(SUDO + ["killall", "-HUP", "mDNSResponder"]):
            print_failure("Flushing the DNS cache failed.")
    elif os.name == "nt":
        print("Automatically flushing the DNS cache is not yet supported.")
        print(
            "Please copy and paste the command 'ipconfig /flushdns' in "
            "administrator command prompt after running this script."
        )
    else:
        nscd_prefixes = ["/etc", "/etc/rc.d"]
        nscd_msg = "Flushing the DNS cache by restarting nscd {result}"

        for nscd_prefix in nscd_prefixes:
            nscd_cache = nscd_prefix + "/init.d/nscd"

            if os.path.isfile(nscd_cache):
                dns_cache_found = True

                if subprocess.call(SUDO + [nscd_cache, "restart"]):
                    print_failure(nscd_msg.format(result="failed"))
                else:
                    print_success(nscd_msg.format(result="succeeded"))

        centos_file = "/etc/init.d/network"
        centos_msg = "Flushing the DNS cache by restarting network {result}"

        if os.path.isfile(centos_file):
            if subprocess.call(SUDO + [centos_file, "restart"]):
                print_failure(centos_msg.format(result="failed"))
            else:
                print_success(centos_msg.format(result="succeeded"))

        system_prefixes = ["/usr", ""]
        service_types = ["NetworkManager", "wicd", "dnsmasq", "networking"]
        restarted_services = []

        for system_prefix in system_prefixes:
            systemctl = system_prefix + "/bin/systemctl"
            system_dir = system_prefix + "/lib/systemd/system"

            for service_type in service_types:
                service = service_type + ".service"
                if service in restarted_services:
                    continue

                service_file = path_join_robust(system_dir, service)
                service_msg = (
                    "Flushing the DNS cache by restarting " + service + " {result}"
                )

                if os.path.isfile(service_file):
                    if 0 != subprocess.call([systemctl, "status", service],
                                            stdout=subprocess.DEVNULL):
                        continue
                    dns_cache_found = True

                    if subprocess.call(SUDO + [systemctl, "restart", service]):
                        print_failure(service_msg.format(result="failed"))
                    else:
                        print_success(service_msg.format(result="succeeded"))
                    restarted_services.append(service)

        dns_clean_file = "/etc/init.d/dns-clean"
        dns_clean_msg = "Flushing the DNS cache via dns-clean executable {result}"

        if os.path.isfile(dns_clean_file):
            dns_cache_found = True

            if subprocess.call(SUDO + [dns_clean_file, "start"]):
                print_failure(dns_clean_msg.format(result="failed"))
            else:
                print_success(dns_clean_msg.format(result="succeeded"))

        if not dns_cache_found:
            print_failure("Unable to determine DNS management tool.")


def remove_old_hosts_file(old_file_path, backup):

    # create new if already removed, so remove won't raise an error.
    open(old_file_path, "a").close()

    if backup:
        backup_file_path = old_file_path + "-{}".format(
            time.strftime("%Y-%m-%d-%H-%M-%S")
        )

        # make a backup copy, marking the date in which the list was updated
        shutil.copy(old_file_path, backup_file_path)

    os.remove(old_file_path)

    # create new empty hosts file
    open(old_file_path, "a").close()


def domain_to_idna(line):

    if not line.startswith("#"):
        tabs = "\t"
        space = " "

        tabs_position, space_position = (line.find(tabs), line.find(space))

        if tabs_position > -1 and space_position > -1:
            if space_position < tabs_position:
                separator = space
            else:
                separator = tabs
        elif not tabs_position == -1:
            separator = tabs
        elif not space_position == -1:
            separator = space
        else:
            separator = ""

        if separator:
            splited_line = line.split(separator)

            try:
                index = 1
                while index < len(splited_line):
                    if splited_line[index]:
                        break
                    index += 1

                if "#" in splited_line[index]:
                    index_comment = splited_line[index].find("#")

                    if index_comment > -1:
                        comment = splited_line[index][index_comment:]

                        splited_line[index] = (
                            splited_line[index]
                            .split(comment)[0]
                            .encode("IDNA")
                            .decode("UTF-8")
                            + comment
                        )

                splited_line[index] = splited_line[index].encode("IDNA").decode("UTF-8")
            except IndexError:
                pass
            return separator.join(splited_line)
        return line.encode("IDNA").decode("UTF-8")
    return line.encode("UTF-8").decode("UTF-8")


def maybe_copy_example_file(file_path):

    if not os.path.isfile(file_path):
        example_file_path = file_path + ".example"
        if os.path.isfile(example_file_path):
            shutil.copyfile(example_file_path, file_path)


def get_file_by_url(url, params=None, **kwargs):

    try:
        req = requests.get(url=url, params=params, **kwargs)
    except requests.exceptions.RequestException:
        print("Error retrieving data from {}".format(url))
        return None

    req.encoding = req.apparent_encoding
    res_text = "\n".join([domain_to_idna(line) for line in req.text.split("\n")])
    return res_text


def write_data(f, data):

    f.write(bytes(data, "UTF-8"))


def list_dir_no_hidden(path):

    return glob(os.path.join(path, "*"))


def query_yes_no(question, default="yes"):

    valid = {"yes": "yes", "y": "yes", "ye": "yes", "no": "no", "n": "no"}
    prompt = {None: " [y/n] ", "yes": " [Y/n] ", "no": " [y/N] "}.get(default, None)

    if not prompt:
        raise ValueError("invalid default answer: '%s'" % default)

    reply = None

    while not reply:
        sys.stdout.write(colorize(question, Colors.PROMPT) + prompt)

        choice = input().lower()
        reply = None

        if default and not choice:
            reply = default
        elif choice in valid:
            reply = valid[choice]
        else:
            print_failure("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

    return reply == "yes"


def is_valid_domain_format(domain):

    if domain == "":
        print("You didn't enter a domain. Try again.")
        return False

    domain_regex = re.compile(r"www\d{0,3}[.]|https?")

    if domain_regex.match(domain):
        print(
            "The domain " + domain + " is not valid. Do not include "
            "www.domain.com or http(s)://domain.com. Try again."
        )
        return False
    else:
        return True


def recursive_glob(stem, file_pattern):

    if sys.version_info >= (3, 5):
        return glob(stem + "/**/" + file_pattern, recursive=True)
    else:
        # this will avoid invalid unicode comparisons in Python 2.x
        if stem == str("*"):
            stem = "."
        matches = []
        for root, dirnames, filenames in os.walk(stem):
            for filename in fnmatch.filter(filenames, file_pattern):
                matches.append(path_join_robust(root, filename))
    return matches


def path_join_robust(path, *paths):

    try:
        # joining unicode and str can be saddening in Python 2.x
        path = str(path)
        paths = [str(another_path) for another_path in paths]

        return os.path.join(path, *paths)
    except UnicodeDecodeError as e:
        raise locale.Error("Unable to construct path. This is likely a LOCALE issue:\n\n" + str(e))


def supports_color():
    sys_platform = sys.platform
    supported = sys_platform != "Pocket PC" and (
        sys_platform != "win32" or "ANSICON" in os.environ
    )

    atty_connected = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    return supported and atty_connected


def colorize(text, color):
    if not supports_color():
        return text

    return color + text + Colors.ENDC


def print_success(text):
    print(colorize(text, Colors.SUCCESS))


def print_failure(text):
    print(colorize(text, Colors.FAIL))



if __name__ == "__main__":
    main()
