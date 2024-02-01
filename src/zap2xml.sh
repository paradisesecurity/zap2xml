#!/bin/bash
# Script to collect guide data in xml format from zap2it.com
# Dependencies:
# * jq: http://stedolan.github.io/jq/
# * getopt: https://github.com/util-linux/util-linux
# * logger: https://github.com/util-linux/util-linux
# * bc: https://www.gnu.org/software/bc/
#
# Author: Paradise Studios
#

# ----------------- #
# === Constants === #
# ----------------- #

declare -r VERSION="0.2"
declare -r DIRECTORY_CONFIG="$HOME/.config/zap2xml"
declare -r DIRECTORY_CACHE="$DIRECTORY_CONFIG/Cache"
declare -r DIRECTORY_LOGS="$DIRECTORY_CONFIG/logs"
declare -r DIRECTORY_APP="$DIRECTORY_CONFIG/storage"
declare -r DIRECTORY_TEMPORARY="$DIRECTORY_CONFIG/tmp"
declare -r DIRECTORY_SCRIPT="/usr/local/bin"
declare -r CONFIG_NAME="config.json"
declare -r CONFIG_PATH="$DIRECTORY_CONFIG/$CONFIG_NAME"
declare -r PERL_SCRIPT_NAME="zap2xml.pl"
declare -r PERL_SCRIPT_PATH="$DIRECTORY_CONFIG/$PERL_SCRIPT_NAME"
declare -r FILTER_SCRIPT_NAME="category-filter.pl"
declare -r FILTER_SCRIPT_PATH="$DIRECTORY_CONFIG/$FILTER_SCRIPT_NAME"
declare -r MERGE_SCRIPT_NAME="merge.pl"
declare -r MERGE_SCRIPT_PATH="$DIRECTORY_CONFIG/$MERGE_SCRIPT_NAME"
declare -a -r DEPENDENCIES=("/usr/bin/jq" "/usr/bin/getopt" "/usr/bin/bc" "/usr/bin/logger")

SCRIPT_PATH=$(/usr/bin/realpath "${BASH_SOURCE[0]}") || exit 100
SCRIPT_NAME=$(/usr/bin/basename "${BASH_SOURCE[0]}") || exit 100

declare -rA LOG_LEVEL_PRIORITY=([DEBUG]=7 [INFO]=6 [NOTICE]=5 [WARNING]=4 [ERROR]=3 [CRITICAL]=2 [ALERT]=1 [EMERGENCY]=0)

# ----------------- #
# === Variables === #
# ----------------- #

mode_debug=false
mode_config=false

declare -a configured_accounts=()
declare command
declare -a command_arguments=()
declare -a command_keys=()
declare -a command_values=()
declare xml_file_to_merge_into
declare -a available_command_functions=()
declare -a available_flag_functions=()
declare -a callable_functions=()
declare configuration
declare -a xml_files_to_merge=()
declare temp_directory
declare -i errors=0

# ----------------------- #
# === Basic Functions === #
# ----------------------- #

# Arguments : variable_name|uppercase_log_level_priority
# Returns : A numerical priority log level
# Usage : return_numerical_priority --variable variable_name --priority "INFO"
# Description : Searches an array for a given log level
function return_numerical_priority {
    local priority="INFO"
    local named_reference=false
    local -i number=6

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n log_level="${1}"
                ;;
            --priority)
                shift;
                priority="${1}"
                ;;
        esac
        shift
    done

    if [[ -v LOG_LEVEL_PRIORITY["${priority}"] ]] ; then
        number="${LOG_LEVEL_PRIORITY["${priority}"]}"
    fi

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        log_level="${number}"
        return 0
    fi

    echo "${number}"
}

# Arguments : variable_name|timestamp_in_seconds
# Returns : A human readable time
# Usage : return_human_readable_time --variable variable_name -- seconds "1234"
# Description : Calculates hours, minutes and seconds from a timestamp
function return_human_readable_time {
    local -i seconds="${SECONDS}"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n human_time="${1}"
                ;;
            --seconds)
                shift;
                if [[ "${1}" =~ ^[0-9]+$ ]]; then
                    seconds="${1}"
                fi
                ;;
        esac
        shift
    done

    local -i hours
    local -i minutes
    hours=$(( seconds / 3600 ))
    minutes=$(( (seconds - hours * 3600) / 60 ))
    seconds=$(( seconds - hours * 3600 - minutes * 60 ))

    local time
    [[ $hours -gt 0 ]] && time="${hours}hrs"
    [[ $minutes -gt 0 ]] && time="${time} ${minutes}min"
    [[ $seconds -gt 0 ]] && time="${time} ${seconds}sec"
    [[ $time ]] || time="0sec"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        human_time="${time}"
        return 0
    fi

    echo "${time}"
}

# Arguments : variable_name|filesize_in_bytes
# Returns : A human readable file size
# Usage : return_human_readable_bytes --variable variable_name --bytes "1234"
# Description : Calculates file size in MB or GB
# shellcheck disable=SC2317
function return_human_readable_bytes {
    local -i bytes=0
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n human_bytes="${1}"
                ;;
            --bytes)
                shift;
                if [[ "${1}" =~ ^[0-9]+$ ]]; then
                    bytes="${1}"
                fi
                ;;
        esac
        shift
    done

    bytes="${bytes/-/}"

    my_bytes="$(echo "${bytes}" | /usr/bin/numfmt --from=iec | /usr/bin/awk 'BEGIN {sum=0} {sum=sum+$1} END {printf "%.0f\n", sum}' | /usr/bin/numfmt --to=iec)"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        human_bytes="${my_bytes}"
        return 0
    fi

    echo "${my_bytes}"
}

# Arguments : variable_name|number_of_characters|allowable_character_set
# Returns : A string of characters
# Usage : return_random_string --variable variable_name --bits "32" --characters "a-zA-Z0-9"
# Description : Creates a random string of known length
# shellcheck disable=SC2317
function return_random_string {
    local -i bits=32
    local characters="'a-zA-Z0-9'"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n random_string="${1}"
                ;;
            --bits)
                shift;
                if [[ "${1}" =~ ^[0-9]+$ ]]; then
                    bits="${1}"
                fi
                ;;
            --characters)
                shift;
                characters="'${1}'"
                ;;
        esac
        shift
    done

    local random
    # shellcheck disable=SC2002
    random="$(/bin/cat /dev/urandom | /usr/bin/tr --delete --complement "${characters}" | /usr/bin/fold --width "${bits}" | /usr/bin/head --lines 1)"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        random_string="${random}"
        return 0
    fi

    echo "${random}"
}

# Arguments : variable_name|full_text_blob|find_this|divider|section_to_return
# Returns : The given section of a text seperated by a divider
# Usage : return_section_sliced_by_divider --variable variable_name --text "Full Text" --find "Find This Line" --divider "|" --section "2"
# Description : Finds a line in a blob of text then seperates it by a divider
function return_section_sliced_by_divider {
    local text="Oh no!! You forgot to feed text into the divider function!"
    local find="*"
    local divider=":"
    local -i section=2
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n sliced_section="${1}"
                ;;
            --text)
                shift;
                text="${1}"
                ;;
            --find)
                shift;
                find="${1}"
                ;;
            --divider)
                shift;
                divider="${1}"
                ;;
            --section)
                shift;
                if [[ "${1}" =~ ^[0-9]+$ ]]; then
                    section="${1}"
                fi
                ;;
        esac
        shift
    done

    local sliced
    sliced="$(echo "${text}" | /bin/grep --extended-regexp "${find}" | /usr/bin/cut --delimiter "${divider}" --fields "${section}")"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        sliced_section="${sliced}"
        return 0
    fi

    echo "${sliced}"
}

# Arguments : annotation_string
# Returns : A clean description of each function with an annotation 
# Usage : print_list_of_callable_functions_by_annotation "@command"
# Requires : Global variables `callable_functions` and `SCRIPT_PATH`
# Description : Looks for functions tagged with a given annotation
function print_list_of_callable_functions_by_annotation {
    local lookup="@command"
    if [[ -n "${1}" ]]; then
        lookup="${1}"
    fi

    for cmd in "${callable_functions[@]}"; do
        local annotation
        annotation=$(/bin/grep --extended-regexp --after-context 3 "^# ${lookup} ${cmd}" "${SCRIPT_PATH}" | /usr/bin/tail --lines 3)

        if [[ "${annotation}" == \#* ]]; then
            local command
            return_section_sliced_by_divider "--variable" command "--text" "${annotation}" "--find" "^# Commands :" "--divider" ":"

            local arguments
            return_section_sliced_by_divider "--variable" arguments "--text" "${annotation}" "--find" "^# Arguments :" "--divider" ":"

            local description
            return_section_sliced_by_divider "--variable" description "--text" "${annotation}" "--find" "^# Description :" "--divider" ":"

            echo -e "# ${command} ${arguments}\t# ${description}" | /usr/bin/expand --tabs 35
        fi
    done

    return 0
}

# Arguments : variable_name|annotation_string
# Returns : Everything after the lookup value on a single line
# Usage : return_annotations_by_type --variable "variable_name" --annotation "@command"
# Requires : Global variable `SCRIPT_PATH`
# Description : Finds annotations by search parameter
function return_annotations_by_type {
    local annotation_type="@command"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n annotation="${1}"
                ;;
            --annotation)
                shift;
                annotation_type="${1}"
                ;;
        esac
        shift
    done

    readarray -t annotation_array <<< "$(/bin/grep --extended-regexp "^# ${annotation_type}" "${SCRIPT_PATH}" | /bin/sed "s/^# ${annotation_type} \(.*\)/\1/")"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        annotation=("${annotation_array[@]}")
        return 0
    fi

    echo "${annotation_array[@]}"
}

# Attention : This function modifies a global script variable!
# Description : Fill global array variables with all command function names
function create_command_function_variables {
    local -a command_functions
    return_annotations_by_type "--variable" command_functions "--annotation" "@command"
    available_command_functions=("${command_functions[@]}")
    callable_functions+=("${available_command_functions[@]}")

    local -a flag_functions
    return_annotations_by_type "--variable" flag_functions "--annotation" "@flag"
    available_flag_functions=("${flag_functions[@]}")
    callable_functions+=("${available_flag_functions[@]}")

    return 0
}

# Attention : This function modifies a global script variable!
# Requires : Global variable `command_arguments`
# Description : Breaks up command line arguments into seperate key / value arrays
function prepare_command_arguments {
    command_keys=()
    command_values=()

    for argument in "${command_arguments[@]}"; do
        command_keys+=("$(cut -d '=' -f1 <<< "${argument}")")
        command_values+=("$(cut -d '=' -f2 <<< "${argument}")")
    done

    return 0
}

# TODO
# Arguments : json_array|key_name|value_to_find
# Returns : The entire section your search was within
# Usage : find_section_in_json --lookup "json_array" --where "key_name" --equals "value"
# Description : Searches for something given a key / value pair
# shellcheck disable=SC2317
function find_section_in_json {
    local json="${configuration}"
    local equals="*"
    local lookup="."
    local where=".name"

    while [[ "${1}" ]]; do
        case "${1}" in
            --equals)
                shift;
                equals="${1}"
                ;;
            --lookup)
                shift;
                lookup="${1}"
                ;;
            --where)
                shift;
                where="${1}"
                ;;
            --json)
                shift;
                json="${1}"
                ;;
        esac
        shift
    done

    /usr/bin/jq --arg search_value "${equals}" --raw-output ''"${lookup}"' | select ('"${where}"'==$search_value)' <<< "${json}"
}

# Arguments : variable_name|key_name|json_array
# Returns : All or section of json array
# Usage : return_config_section_from_json --variable "variable_name" --read "key_name" --json "json_array"
# Requires : Global variable `configuration`
# Description : Searches for a section of a json array
# shellcheck disable=SC2317
function return_config_section_from_json {
    local json="${configuration}"
    local read="."
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n config_section_from_json="${1}"
                ;;
            --json)
                shift;
                json="${1}"
                ;;
            --read)
                shift;
                read="${1}"
                ;;
        esac
        shift
    done

    local section
    section="$(/usr/bin/jq --raw-output "${read}" <<< "${json}")"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        config_section_from_json="${section}"
        return 0
    fi

    echo "${section}"
}

# Arguments : variable_name|account_name|section_to_return
# Returns : All or section of json array you asked for
# Usage : return_config_for_account --variable "variable_name" --account "unique_name" --return ".login[]"
# Requires : Global variable `CONFIG_PATH` or `configuration`
# Description : Finds a config for a given account name
# shellcheck disable=SC2317
function return_config_for_account {
    local account="this_account_should_never_be_found"
    local return="."
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n config_for_account="${1}"
                ;;
            --account)
                shift;
                account="${1}"
                ;;
            --return)
                shift;
                return="${1}"
                ;;
        esac
        shift
    done

    if [[ -z ${configuration} ]]; then
        load_configuration
    fi

    local json_config
    return_config_section_from_json "--variable" json_config "--read" "." "--json" "${configuration}"

    local section
    section="$(/usr/bin/jq --raw-output "." <<< "${json_config}" | /usr/bin/jq --arg search_value "${account}" --raw-output '.accounts[]? | select (.name==$search_value)' | /usr/bin/jq "${return}")"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        config_for_account="${section}"
        return 0
    fi

    echo "${section}"
}

# Arguments : variable_name|key_name
# Returns : All or section of json array you specified
# Usage : return_json_if_found --variable "variable_name" --lookup ".login[]"
# Requires : Global variable `CONFIG_PATH` or `configuration`
# Description : Returns a json array with a simple key lookup
# shellcheck disable=SC2317
function return_json_if_found {
    local lookup="."
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n found_json="${1}"
                ;;
            --lookup)
                shift;
                lookup="${1}"
                ;;
        esac
        shift
    done

    if [[ -z ${configuration} ]]; then
        load_configuration
    fi

    local json_config
    return_config_section_from_json "--variable" json_config "--read" "." "--json" "${configuration}"

    local section
    section="$(/usr/bin/jq --raw-output "." <<< "${json_config}" | /usr/bin/jq "${lookup}")"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        found_json="${section}"
        return 0
    fi

    echo "${section}"
}

# Arguments : variable_name
# Returns : An array of account names
# Usage : return_account_names --variable "variable_name"
# Description : Find all accounts in the config
# shellcheck disable=SC2317
function return_account_names {
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n list_of_accounts="${1}"
                ;;
        esac
        shift
    done

    local my_account_names
    return_json_if_found "--variable" my_account_names "--lookup" ".accounts[].name"
    readarray -t my_accounts <<< "$(/bin/sed --expression 's/^"//' --expression 's/"$//' <<< "${my_account_names}")"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        list_of_accounts=("${my_accounts[@]}")
        return 0
    fi

    echo "${my_accounts[@]}"
}

# Arguments : variable_name|key_name|json_array
# Returns : True or false
# Usage : does_json_contain_key --variable "variable_name" --key "key_name" --json "json_array"
# Requires : Global variable `configuration`
# Description : Determine if a json array contains a key
# shellcheck disable=SC2317
function does_json_contain_key {
    local key="this_key_name_should_never_be_found"
    local json="$configuration"
    local named_reference=false
    local true_or_false=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n contains_key="${1}"
                ;;
            --key)
                shift;
                key="${1}"
                ;;
            --json)
                shift;
                json="${1}"
                ;;
        esac
        shift
    done

    local status
    # shellcheck disable=SC2034
    if status="$(/usr/bin/jq --exit-status --arg key "${key}" 'has($key)' <<< "${json}")" ; then
        true_or_false=true
    fi

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        contains_key="${true_or_false}"
        return 0
    fi

    echo "${true_or_false}"
}

# Arguments : variable_name|json_array
# Returns : Each variable as a string on a new line
# Usage : return_config_data_as_string --variable "variable_name" --json "json_array"
# Requires : Global variable `configuration`
# Description : Converts a json array into a string
# shellcheck disable=SC2317
function return_config_data_as_string {
    local json="$configuration"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n config_data="${1}"
                ;;
            --json)
                shift;
                json="${1}"
                ;;
        esac
        shift
    done

    local mapped_data
    mapped_data="$(/usr/bin/jq --raw-output "." <<< "${json}" | /usr/bin/jq --raw-output "to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]")"

    if ${named_reference} ; then
        # shellcheck disable=SC2034
        config_data="${mapped_data}"
        return 0
    fi

    echo "${mapped_data}"
}

# Attention : This function modifies a global script variable!
# Requires : Global variable `CONFIG_PATH` and `configuration`
# Description : Reads the json config file into the global configuration variable
function load_configuration {
    configuration="$(/bin/cat < "${CONFIG_PATH}" | /usr/bin/jq --raw-output ".")"

    return 0
}

# Attention : This function modifies a global script variable!
# Requires : Global variable `temp_directory` and `SCRIPT_NAME`
# Description : Makes a temporary directory
# shellcheck disable=SC2317
function create_temporary_directory {
    local temp_prefix="$SCRIPT_NAME"
    local my_directory_name
    my_directory_name="$(/bin/mktemp --directory -t "${temp_prefix}".XXXXXXXXXX)" || exit 100

    if ! [[ -d "${my_directory_name}" ]]; then
        die "Could not create temporary directory: '${my_directory_name}'" "${FUNCNAME[0]}"
    fi

    if [[ "$(echo "${my_directory_name}" | /usr/bin/cut --delimiter "/" --fields 2)" != "tmp" ]]; then
        die "Unexpected root directory path for: '${my_directory_name}'" "${FUNCNAME[0]}"
    fi

    temp_directory="${my_directory_name}"
    message "INFO: Setting trap to remove this directory: '${my_directory_name}'"
    #trap '/bin/rm --recursive -- "${my_directory_name}"' EXIT

    return 0
}

# Attention : This function modifies a global script variable!
# Arguments : variable_name
# Returns : The full path to the temporary directory
# Usage : return_temporary_directory --variable "variable_name"
# Requires : Global variable `temp_directory` and `DIRECTORY_TEMPORARY`
# Description : Finds the currently set temporary directory
# shellcheck disable=SC2317
function return_temporary_directory {
    local my_directory="${DIRECTORY_TEMPORARY}"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n my_temp_dir_path="${1}"
                ;;
        esac
        shift
    done


    if ${mode_debug}; then
        temp_directory="${my_directory}"
    fi

    if [[ -z "${temp_directory}" ]]; then
        create_temporary_directory
    fi

    if ${named_reference}; then
        # shellcheck disable=SC2034
        my_temp_dir_path="${temp_directory}"
        return 0
    fi

    echo "${temp_directory}"
}

# Attention : This function modifies a global script variable!
# Requires : Global variables `configuration`
# Description : Writes the data from the configuration variable to a temporary file, then checks if the file is empty. If not, it is written to the config file.
# shellcheck disable=SC2317
function write_changes_to_config {
    if ! ${mode_debug}; then
        local temporary_directory
        return_temporary_directory "--variable" temporary_directory

        local temporary_file
        temporary_file="$(/bin/mktemp --tmpdir="${temporary_directory}")" || exit 100

        /usr/bin/jq --raw-output "." <<< "${configuration}" > "${temporary_file}"

        if [[ -s "${temporary_file}" ]]; then
            /bin/cat < "${temporary_file}" | /usr/bin/jq --raw-output "." > "${CONFIG_PATH}"

            load_configuration
        fi
    fi

    return 0
}

# Arguments : log_name
# Returns : The full path of the log file
# Usage : return_log_file_path --variable "variable_name" --name "unique_name"
# Requires : Global variable `DIRECTORY_LOGS`
# Description : Creates a log file with a specified name and the date
# shellcheck disable=SC2317
function return_log_file_path {
    local my_log_name="default"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n my_log_file_path="${1}"
                ;;
            --name)
                shift;
                my_log_name="${1}"
                ;;
        esac
        shift
    done

    local log_file_name_and_path
    log_file_name_and_path="${DIRECTORY_LOGS}/$(/bin/date '+%Y-%m-%d')-${my_log_name}.log"

    if ${named_reference}; then
        # shellcheck disable=SC2034
        my_log_file_path="${log_file_name_and_path}"
        return 0
    fi

    echo "${log_file_name_and_path}"
}

# Arguments : variable_name|secret_key|plaintext_string
# Returns : An encrypted string
# Usage : return_encrypted_data --variable "variable_name" --secret "key" --plaintext "text"
# Description : Encrypts a plain text string with your secret key
# shellcheck disable=SC2317
function return_encrypted_data {
    local encryption_key
    return_random_string "--variable" encryption_key "--bits" 64 "--characters" "/a-zA-Z0-9+"
    local my_plaintext_data="This string should never be seen unless something bad happened."
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n my_encrypted_data="${1}"
                ;;
            --secret)
                shift;
                encryption_key="${1}"
                ;;
            --plaintext)
                shift;
                my_plaintext_data="${1}"
                ;;
        esac
        shift
    done

    local my_new_encrypted_string
    my_new_encrypted_string="$(echo "${my_plaintext_data}" | /usr/bin/openssl enc -e -aes-256-cbc -pbkdf2 -iter 20000 -pass pass:"${encryption_key}" | /usr/bin/base64 --wrap 0)"

    if ${named_reference}; then
        # shellcheck disable=SC2034
        my_encrypted_data="${my_new_encrypted_string}"
        return 0
    fi

    echo "${my_new_encrypted_string}"
}

# Arguments : variable_name|secret_key|encrypted_string
# Returns : The decrypted plain text string
# Usage : return_decrypted_data --variable "variable_name" --secret "key" --encrypted "****"
# Description : Decrypts an encrypted string with your secret key
# shellcheck disable=SC2317
function return_decrypted_data {
    local decryption_key
    return_random_string "--variable" decryption_key "--bits" 64 "--characters" "/a-zA-Z0-9+"
    local encrypted_data_holder
    return_encrypted_data "--variable" encrypted_data_holder "--secret" "${decryption_key}"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n my_decrypted_data="${1}"
                ;;
            --secret)
                shift;
                decryption_key="${1}"
                ;;
            --encrypted)
                shift;
                encrypted_data_holder="${1}"
                ;;
        esac
        shift
    done

    local my_new_plaintext_data
    my_new_plaintext_data="$(echo "${encrypted_data_holder}" | /usr/bin/openssl enc -d -aes-256-cbc -pbkdf2 -iter 20000 -base64 -pass pass:"${decryption_key}")"

    if ${named_reference}; then
        # shellcheck disable=SC2034
        my_decrypted_data="${my_new_plaintext_data}"
        return 0
    fi

    echo "${my_new_plaintext_data}"
}

# shellcheck disable=SC2317
function return_default_cache_directory_path {
    local account
    return_random_string "--variable" account "--bits" 32 "--characters" "a-zA-Z"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n my_default_cache_directory_path="${1}"
                ;;
            --account)
                shift;
                account="${1}"
                ;;
        esac
        shift
    done

    local my_cache_path="${DIRECTORY_CACHE}/cache_${account}"

    if ${named_reference}; then
        # shellcheck disable=SC2034
        my_default_cache_directory_path="${my_cache_path}"
        return 0
    fi

    echo "${my_cache_path}"
}

# shellcheck disable=SC2317
function return_default_xmltv_output_file_path {
    local account
    return_random_string "--variable" account "--bits" 32 "--characters" "a-zA-Z"
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n my_default_xmltv_output_file_path="${1}"
                ;;
            --account)
                shift;
                account="${1}"
                ;;
        esac
        shift
    done

    local my_outfile_path="${DIRECTORY_APP}/xmltv_${account}.xml"

    if ${named_reference}; then
        # shellcheck disable=SC2034
        my_default_xmltv_output_file_path="${my_outfile_path}"
        return 0
    fi

    echo "${my_outfile_path}"
}

# -------------------- #
# === Option Flags === #
# -------------------- #

# @flag debug
# Commands : -d|--debug
# Arguments :
# Description : Run in debug mode
function debug {
    if ${mode_debug}; then
        function debug {
            echo -e "[$(/bin/date "+%Y-%m-%d %H:%M:%S")] $*" >&2
        }
        debug "$@"
    else
        function debug {
            true
        }
    fi
}

# @flag config
# Commands : -c|--config
# Arguments :
# Description : Enter configuration mode
# shellcheck disable=SC2317
function config {
    true
}

# @flag account
# Commands : -a|--account
# Arguments : unique_name
# Description : Set account
# shellcheck disable=SC2317
function account {
    true
}

# @flag merge
# Commands : -m|--merge
# Arguments : /path/to/file.xml
# Description : Combine all fetches into a single file
# shellcheck disable=SC2317
function merge {
    true
}

# @flag version
# Commands : -v|--version
# Arguments :
# Description : Show the version number
# shellcheck disable=SC2317
function version {
    true
}

# @flag help
# Commands : -h|--help
# Arguments :
# Description : Show the help reference
function help {
    echo "## zap2xml (version ${VERSION}) help reference:"
    echo ""
    echo -e "#  option flag [ARG1]\t#  Description" | /usr/bin/expand --tabs 35
    print_list_of_callable_functions_by_annotation "@flag"
    echo ""
    echo -e "#  command [ARG1] [ARG2]\t#  Description" | /usr/bin/expand --tabs 35
    print_list_of_callable_functions_by_annotation "@command"
    echo ""
    echo "#  Examples:"
    echo "#  zap2xml -a cable -a directv -m combined.xml fetch"
    echo "#  zap2xml -c -a ota add user=\"jim@mail.com\" pass=\"123$%\""
    echo "#  zap2xml -c -a directv remove"
    echo "#  zap2xml -c -a directv modify user=\"jim@mail.com\" pass=\"123$%\""
}

# --------------- #
# === Actions === #
# --------------- #

# Arguments : log_name|log_level_priority|log_message
# Usage : log --level "INFO" --name "unique_name" --message "Something failed."
# Description : Logs a message into a named log file
# shellcheck disable=SC2317
function log {
    local name="default"
    local level="INFO"
    local message="Failed to pass error message to log file."

    while [[ "${1}" ]]; do
        case "${1}" in
            --name)
                shift;
                name="${1}"
                ;;
            --level)
                shift;
                level="${1}^^"
                ;;
            --message)
                shift;
                message="${1}"
                ;;
        esac
        shift
    done

    local log_file
    return_log_file_path "--variable" log_file "--name" "${name}"

    echo -e "[$(/bin/date "+%Y-%m-%d %H:%M:%S")] [${level}] [${message}]" >> "${log_file}" >&2
}

# Arguments : A formatted message (see usage), a function name
# Usage : message "[INFO]: I failed trying to execute function." "function_name"
# Requires : Global variables `SCRIPT_NAME` and `SCRIPT_PATH`
# Description : If the debug flag is set, it prints an error on the screen
# If no debug flag is set, it sends all log messages to the journal on the system
function message {
    local priority="INFO"
    local message="${1}"

    [[ "${1}" =~ ^([A-Za-z]*):\ (.*) ]] && {
        priority="${BASH_REMATCH[1]}"
        message="${BASH_REMATCH[2]}"
    }

    local function_name="${2-unknown}"
    local -i numerical_priority
    return_numerical_priority "--variable" numerical_priority "--priority" "${priority}"

    if [ -n "${2}" ]; then
        debug "[${priority}] An error occured while executing the function '${function_name}'."
    fi
    debug "[${priority}] ${message}"

    if ! ${mode_debug}; then
        /usr/bin/logger --journald <<EOF
MESSAGE_ID=${SCRIPT_NAME}
MESSAGE=${message}
PRIORITY=${numerical_priority}
CODE_FILE=${SCRIPT_PATH}
CODE_FUNC=${function_name}
EOF
    fi

    return 0
}

# Arguments : A non-formatted message
# Usage : error "I failed trying to execute function."
# Description : Adds error formatting to an error message
function error {
    local message="ERROR: ${1}"
    shift

    if [ -z "${1}" ]; then
        message "${message}"
    else
        message "${message}" "$@"
    fi

    ((errors++))

    return 0
}

# Arguments : A non-formatted message
# Usage : error "I failed trying to execute function."
# Description : Forwards an error message and kills the script
function die {
    error "$@"

    exit "${errors}"
}

# -------------------------- #
# === Advanced Functions === #
# -------------------------- #

# Description : Logs the length of time it took for the script to run
function log_command_running_duration {
    local human_readable_time
    return_human_readable_time "--variable" human_readable_time "--seconds" "${SECONDS}"

    message "zap2xml script (${VERSION}) finished in ${human_readable_time}"
}

# Arguments : variable_name|file_size_in_bytes|file_size_in_bytes
# Returns : File size in MB or GB
# Usage : return_return_human_readable_file_size_difference --variable "variable_name" --before "123" --after "234"
# Description : Calculates a human readable difference between two file sizes
# shellcheck disable=SC2317
function return_human_readable_file_size_difference {
    local -i before=0
    local -i after=0
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n human_readable_file_size="${1}"
                ;;
            --before)
                shift;
                before="${1}"
                ;;
            --after)
                shift;
                after="${1}"
                ;;
        esac
        shift
    done

    local difference="$(( after - before ))"
    local human
    return_human_readable_bytes "--variable" human "--bytes" "${difference}"
    local plus_minus="-"

    if [[ ${difference} -gt -1 ]]; then
        plus_minus="+"
    fi

    local file_size_difference="${plus_minus}${human}"

    if ${named_reference}; then
        # shellcheck disable=SC2034
        human_readable_file_size="${file_size_difference}"
        return 0
    fi

    echo "${file_size_difference}"
}

# Requires : Global variables `SCRIPT_PATH`, `DIRECTORY_SCRIPT`, `SCRIPT_NAME` and `PATH`
# Description : Check this script is located in the preferred directory and is callable on the users environmental $PATH
function check_script_path {
    if [[ "$(/usr/bin/dirname "${SCRIPT_PATH}")" != "${DIRECTORY_SCRIPT}" ]]; then
        message "INFO: Consider placing '${SCRIPT_NAME}' inside the '${DIRECTORY_SCRIPT}' directory."
    fi

    if [[ ":${PATH}:" != *":$(/usr/bin/dirname "${SCRIPT_PATH}"):"* ]]; then
        message "INFO: Your PATH is missing the '${DIRECTORY_SCRIPT}' directory."
    fi

    return 0
}

# Requires : Global variables `mode_debug`, `DEPENDENCIES` and `FUNCNAME`
# Description : Check for missing package dependencies required to run this script
function check_script_for_package_dependencies {
    for dependency in "${DEPENDENCIES[@]}"; do
        if ! command -v "${dependency}" > /dev/null 2>&1; then
            die "Missing ${dependency}." "${FUNCNAME[0]}"
        fi
    done

    return 0
}

# Requires : Global variables `DIRECTORY_CONFIG`, `CONFIG_PATH`, `PERL_SCRIPT_PATH`, `FILTER_SCRIPT_PATH`, `MERGE_SCRIPT_PATH`
# Description : Check for missing directories and files
function check_script_for_file_existance {
    if ! [[ -d "${DIRECTORY_CONFIG}" ]]; then
        die "Config directory '$DIRECTORY_CONFIG' does not exist." "${FUNCNAME[0]}"
	fi

    if ! [[ -f "${CONFIG_PATH}" ]]; then
        die "Config file '${CONFIG_PATH}' does not exist." "${FUNCNAME[0]}"
    fi

    if ! [[ -f "${PERL_SCRIPT_PATH}" ]]; then
        die "Perl script '${PERL_SCRIPT_NAME}' does not exist." "${FUNCNAME[0]}"
    fi

    if ! [[ -f "${FILTER_SCRIPT_PATH}" ]]; then
        die "Filter script '${FILTER_SCRIPT_NAME}' does not exist." "${FUNCNAME[0]}"
    fi

    if ! [[ -f "${MERGE_SCRIPT_PATH}" ]]; then
        die "Merge script '${MERGE_SCRIPT_NAME}' does not exist." "${FUNCNAME[0]}"
    fi

    return 0
}

# Arguments : variable_name|account_name|xml_file_path
# Returns : The xml output file for an account
# Usage : return_xml_output_file_for_account --variable "variable_name" --account "name" --xml "my/path/file.xml"
# Requires : Global variable `DIRECTORY_APP`
# Description : Determins a file path for an account's xml output file
# shellcheck disable=SC2317
function return_xml_output_file_for_account {
    local account
    local user_file
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n xml_output_file_for_account="${1}"
                ;;
            --account)
                shift;
                account="${1}"
                ;;
            --xml)
                shift;
                user_file="${1}"
                ;;
        esac
        shift
    done

    if [[ -z "${account}" ]]; then
        die "An account is required to determine the xml output file." "${FUNCNAME[0]}"
    fi

    local default_file
    return_default_xmltv_output_file_path "--variable" default_file "--account" "${account}"

    if [[ -z "${user_file}" ]]; then
        message "INFO: An xml output file for '${account}' was not provided."
        message "INFO: Defaulting to: '${default_file}'"
        user_file="${default_file}"
    fi

    if [[ -f "${user_file}" ]]; then
        message "INFO: File '${user_file}' exists and will be overwritten."
    fi

    if ! [[ -d "$(/usr/bin/dirname "${user_file}")" ]]; then
        message "INFO: Could not access the supplied output file directory for: '${user_file}'"
        message "INFO: Defaulting to: '${default_file}'"
        user_file="${default_file}"
	fi

    if ! [[ -f "${user_file}" ]]; then
        message "INFO: Touching file: '${user_file}'"
        if ! ${mode_debug}; then
            if ! /usr/bin/touch "${user_file}"; then
                die "Could not create output file: '${user_file}'" "${FUNCNAME[0]}"
            fi
        fi
    fi

    if ${named_reference}; then
        # shellcheck disable=SC2034
        xml_output_file_for_account="${user_file}"
        return 0
    fi

    echo "${user_file}"
}

# Arguments : variable_name|account_name|cache_directory_path
# Returns : The cache directory for an account
# Usage : return_cache_directory_for_account --variable "variable_name" --account "name" --cache "my/path/cache"
# Requires : Global variable `DIRECTORY_CACHE`
# Description : Determins the full path for an account's cache directory
# shellcheck disable=SC2317
function return_cache_directory_for_account {
    local account
    local user_cache
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n cache_directory_for_account="${1}"
                ;;
            --account)
                shift;
                account="${1}"
                ;;
            --cache)
                shift;
                user_cache="${1}"
                ;;
        esac
        shift
    done

    if [[ -z "${account}" ]]; then
        die "An account is required to determine the cache directory." "${FUNCNAME[0]}"
    fi

    local default_cache
    return_default_cache_directory_path "--variable" default_cache "--account" "${account}"

    if [[ -z "${user_cache}" ]]; then
        message "INFO: A cache directory for '${account}' was not provided."
        message "INFO: Defaulting to: '${default_cache}'"
        user_cache="${default_cache}"
    fi

    if ! [[ "${user_cache}" =~ '/' ]]; then
        message "INFO: Could not access the supplied cache directory: '${user_cache}'"
        message "INFO: Defaulting to: '${default_cache}'"
        user_file="${default_cache}"
    fi

    if ! [[ -d "${user_cache}" ]]; then
        message "INFO: Creating directory: '${user_cache}'"
        if ! ${mode_debug}; then
            if ! /bin/mkdir --parents "${user_cache}"; then
                die "Could not create directory: '${user_cache}'" "${FUNCNAME[0]}"
            fi
        fi
    fi

    if ${named_reference}; then
        # shellcheck disable=SC2034
        cache_directory_for_account="${user_cache}"
        return 0
    fi

    echo "${user_cache}"
}

# Arguments : cache_directory_path
# Usage : cleanup_stale_cache_files "my/path/cache"
# Description : The perl script does not clean detail files properly, associated with using the -D option. This will remove cache non-detail files that are within x days of today, which will force the current days to be refreshed to current data. It does not touch the detail cache files, so this does not heavily impact the website.
# shellcheck disable=SC2317
function cleanup_stale_cache_files {
    if [[ -z "${1}" ]]; then
        message "INFO: The cache directory was not given. Aborting cache cleanup."
    fi

    local cache="${1}"

    if ! [[ -d "${cache}" ]]; then
        message "INFO: Could not access the supplied cache directory: '${cache}'"
        message "INFO: Aborting cache cleanup."
    fi

    local -i cache_days_to_remove=3
    local -i today_in_seconds
    today_in_seconds="$(date +%s)"
    local -i today_in_milliseconds
    today_in_milliseconds="$(( today_in_seconds * 1000 ))"
    local -i cache_time
    cache_time="$(( today_in_milliseconds + cache_days_to_remove * 24 * 60 * 60 * 1000 ))"

    local html_files
    html_files="$(cd "${cache}" || return; /usr/bin/find -- *gz | /bin/grep --extended-regexp "^[0-9]+")"

    if [[ -n "${html_files}" ]]; then
        message "INFO: Removing cache files older than $cache_days_to_remove days."
    fi

    for file in ${html_files}; do
        local -i file_time
        file_time="$(echo "${file}" | /usr/bin/cut --delimiter '.' --fields 1)"

        if (( file_time < cache_time )); then
            message "INFO: Removing cache file: '${cache}/${file_time}.js.gz'"

            if ! ${mode_debug}; then
                /bin/rm "${cache}/${file_time}.js.gz"
            fi
        fi
    done

    return 0
}

# Arguments : options_variable_name|custom_options_variable_name
# Usage : return_perl_script_options --variable "variable_name" --options "variable_name"
# Returns : A string of arguments for use on the command line
# Description : Breaks the options array into a single line argument
# shellcheck disable=SC2317
function return_perl_script_options {
    local my_options
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n perl_script_options="${1}"
                ;;
            --options)
                shift;
                local -n my_custom_options="${1}"
                ;;
        esac
        shift
    done

    if [[ -z "${my_custom_options[*]}" ]]; then
        local -A my_custom_options=()
    fi

    for argument in "${!my_custom_options[@]}"; do
        if [[ -n "${my_custom_options["${argument}"]}" ]]; then
            my_options="${argument} ${my_custom_options["${argument}"]} ${my_options}"
        fi
        if [[ -z "${my_custom_options["${argument}"]}" ]]; then
            my_options="${argument} ${my_options}"
        fi
    done

    my_options="$(echo "${my_options}" | xargs)"

    if ${named_reference}; then
        # shellcheck disable=SC2034
        perl_script_options="${my_options}"
        return 0
    fi

    echo "${my_options}"
}

# Arguments : variable_name|account_name|xml_output_file_path|cache_directory_path
# Usage : return_temporary_config_options_file_path --variable "variable_name" --account "name" --xml "my/path/file.xml" --cache "my/path/cache"
# Description : Writes some config options into a temporary file. This file contains private data in plaintext format. The file is deleted upon script exit.
# shellcheck disable=SC2317
function return_temporary_config_options_file_path {
    local account="this_account_will_never_exist"
    local cache_directory
    local xml_output_file
    local named_reference=false

    while [[ "${1}" ]]; do
        case "${1}" in
            --variable)
                shift;
                named_reference=true
                local -n temporary_config_options_file_path="${1}"
                ;;
            --account)
                shift;
                account="${1}"
                ;;
            --cache)
                shift;
                cache_directory="${1}"
                ;;
            --xml)
                shift;
                xml_output_file="${1}"
                ;;
        esac
        shift
    done

    local temporary_directory
    return_temporary_directory "--variable" temporary_directory
    local my_tmp_config_file="${temporary_directory}/${account}.config"

    if [[ -f "${my_tmp_config_file}" ]]; then
        die "Temporary config file still exists: '${my_tmp_config_file}'" "${FUNCNAME[0]}"
    fi

    message "INFO: Touching temporary config file: '${my_tmp_config_file}'"
    if ! ${mode_debug}; then
        if ! /usr/bin/touch "${my_tmp_config_file}"; then
            die "Could not create temporary config file: '${my_tmp_config_file}'" "${FUNCNAME[0]}"
        fi
    fi

    local account_config
    return_config_for_account "--variable" account_config "--account" "${account}" "--return" "."

    local account_options
    return_config_section_from_json "--variable" account_options "--read" ".options[]" "--json" "${account_config}"
    if [[ -z "${account_options}" ]]; then
        die "Can't access options for account: '${account}'" "${FUNCNAME[0]}"
    fi

    local config_options
    return_config_data_as_string "--variable" config_options "--json" "${account_options}"

    local account_login
    return_config_section_from_json "--variable" account_login "--read" ".login[]" "--json" "${account_config}"
    if [[ -z "${account_login}" ]]; then
        die "Can't access login for account: '${account}'." "${FUNCNAME[0]}"
    fi

    local main_config
    return_json_if_found "--variable" main_config "--lookup" ".config"
    local secret
    return_config_section_from_json "--variable" secret "--read" ".secret" "--json" "${main_config}"

    local username
    return_config_section_from_json "--variable" username "--read" ".user" "--json" "${account_login}"
    return_decrypted_data "--variable" username "--secret" "${secret}" "--encrypted" "${username}"

    if [[ -n "${username}" ]]; then
        config_options+=$'\n'"user=${username}"
    fi

    local password
    return_config_section_from_json "--variable" password "--read" ".pass" "--json" "${account_login}"
    return_decrypted_data "--variable" password "--secret" "${secret}" "--encrypted" "${password}"

    if [[ -n "${password}" ]]; then
        config_options+=$'\n'"pass=${password}"
    fi

    if [[ -f "${xml_output_file}" ]]; then
        config_options+=$'\n'"outfile=${xml_output_file}"
    fi

    if [[ -d "${cache_directory}" ]]; then
        config_options+=$'\n'"cache=${cache_directory}"
    fi

    message "INFO: Writing config data into temporary file: '${my_tmp_config_file}'"
    if ! $mode_debug; then
        echo "${config_options}" > "${my_tmp_config_file}"
    fi

    if ${named_reference}; then
        # shellcheck disable=SC2034
        temporary_config_options_file_path="${my_tmp_config_file}"
        return 0
    fi

    echo "${my_tmp_config_file}"
}

# Attention : This function modifies a global script variable!
# Arguments : account_name
# Usage : download_guide_data_for_account "naccount_ame"
# Requires : Global variable `xml_files_to_merge` and `PERL_SCRIPT_PATH`
# Description : Downloads new guide data for given account
# shellcheck disable=SC2317
function download_guide_data_for_account {
    local account="this_account_does_not_exist"

    if [[ -n "${1}" ]]; then
        account="${1}"
    fi

    local account_config
    return_config_for_account "--variable" account_config "--account" "${account}" "--return" ".config[]"
    if [[ -z "${account_config}" ]]; then
        die "Can't access config for account: '${account}'" "${FUNCNAME[0]}"
    fi

    message "INFO: Downloading guide data for account: '${account}'"

    local xml_output_file
    return_config_section_from_json "--variable" xml_output_file "--read" ".outfile" "--json" "${account_config}"
    return_xml_output_file_for_account "--variable" xml_output_file "--account" "${account}" "--xml" "${xml_output_file}"

    xml_files_to_merge+=("${xml_output_file}")

    local cache_directory
    return_config_section_from_json "--variable" cache_directory "--read" ".cache" "--json" "${account_config}"
    return_cache_directory_for_account "--variable" cache_directory "--account" "${account}" "--cache" "${cache_directory}"

    local tmp_config_file
    return_temporary_config_options_file_path "--variable" tmp_config_file "--account" "${account}" "--xml" "${xml_output_file}" "--cache" "${cache_directory}"

    # Set perl script options to default values -T -D -S 1
    local -A custom_options=(["-T"]="" ["-S"]="1" ["-C"]="${tmp_config_file}")

    local recent_file
    # Determine if the xml was created in the last 12 hours
    recent_file="$(/usr/bin/find "$(/usr/bin/dirname "${xml_output_file}")" -name "$(/usr/bin/basename "${xml_output_file}")" -mtime -1)"
    if [[ -n "${recent_file}" ]]; then
        # Script was executed recently so do not clean the current day files
        custom_options+=(["-N"]="0")
    else
        cleanup_stale_cache_files "${cache_directory}"
    fi

    local options
    return_perl_script_options "--variable" options "--options" custom_options

    local file_size_before
    file_size_before="$(stat --format %s "${xml_output_file}")"

    # Generate xml file
    message "INFO: Executing zap2xml pearl script with options: '${options}'"
    if ! ${mode_debug}; then
        local log_file
        return_log_file_path "--variable" log_file "--name" "${account}"

        local perl_command="${PERL_SCRIPT_PATH} ${options}"
        eval "${perl_command}" >> "${log_file}" 2>&1
    fi

    local file_size_after
    file_size_after="$(stat --format %s "${xml_output_file}")"

    local generated_file
    # if the xml file was generated, then update it
    generated_file="$(find "${xml_output_file}" -mtime -1)"
    if [[ -z "${generated_file}" ]]; then
        message "ERROR: Could not download guide data for account: '${account}'" "${FUNCNAME[0]}"
    else
        message "INFO: Successfully downloaded guide data for account: '${account}'"

        local file_size_difference_human
        return_human_readable_file_size_difference "--variable" file_size_difference_human "--after" "${file_size_after}" "--before" "${file_size_before}"

        local file_size_after_human
        return_human_readable_bytes "--variable" file_size_after_human "--bytes" "${file_size_after}"

        message "INFO: New xml file size: ${file_size_after_human} (${file_size_difference_human})"
    fi

    return 0
}

# Requires : Global variable `xml_files_to_merge`, `configured_accounts` and `xml_file_to_merge_into`
# Description : Merge guide data for given accounts into a single file
# shellcheck disable=SC2317
function merge_guide_data_into_single_file {
    local accounts_xml_files
    accounts_xml_files="$(printf "%s" "${xml_files_to_merge[*]}")"

    local merge_accounts="${configured_accounts[*]}"

    local tmp_merge_file_name
    tmp_merge_file_name="$(/bin/date '+%Y-%m-%d')-${merge_accounts// /-}-merged.xml"
    local temporary_directory
    return_temporary_directory "--variable" temporary_directory
    local tmp_merge_file_path="${temporary_directory}/${tmp_merge_file_name}"

    local xml_output_file="${xml_file_to_merge_into}"

    if [[ -f "${xml_output_file}" ]]; then
        message "INFO: Merge file exists and will be overwritten: '${xml_output_file}'"
    fi

    if ! [[ -d "$(/usr/bin/dirname "${xml_output_file}")" ]]; then
        die "Could not access the supplied file directory for: '${xml_output_file}'" "${FUNCNAME[0]}"
	fi

    local merge_log_file_name="${merge_accounts// /-}-merge"
    local log_file
    return_log_file_path "--variable" log_file "--name" "${merge_log_file_name}"

    message "INFO: Executing merge script on: '${accounts_xml_files}'"
    message "INFO: Merged data will be stored in: '${tmp_merge_file_path}'"
    if ! ${mode_debug}; then
        local merge_command="${MERGE_SCRIPT_PATH} ${accounts_xml_files} > ${tmp_merge_file_path}"
        eval "${merge_command}" >> "${log_file}" 2>&1
    fi

    if ! [[ -f "${tmp_merge_file_path}" ]]; then
        die "Temporary merge file does not exist: '${tmp_merge_file_path}'" "${FUNCNAME[0]}"
    fi

    message "INFO: Executing category filter script on: '${tmp_merge_file_path}'"
    if ! ${mode_debug}; then
        local filter_command="${FILTER_SCRIPT_PATH} ${tmp_merge_file_path}"
        eval "${filter_command}" >> "${log_file}" 2>&1
    fi

    message "INFO: Copying temporary merge file to: '${xml_output_file}'"
    if ! ${mode_debug}; then
        /bin/cp "${tmp_merge_file_path}" "${xml_output_file}" >> "${log_file}" 2>&1
    fi

    return 0
}

# ---------------- #
# === Commands === #
# ---------------- #

# @command fetch
# Commands : fetch
# Arguments :
# Description : Download the guide data for the account(s) specified
# shellcheck disable=SC2317
function fetch {
    local -a accounts
    accounts=("${configured_accounts[@]}")

    # Check if configured accounts array is populated, if empty, assume we want to fetch all accounts in the config.
    if [[ -z "${accounts[*]}" ]]; then
        local account_names
        return_account_names "--variable" account_names
        accounts=("${account_names[@]}")
    fi

    configured_accounts=("${accounts[@]}")

    for account in "${accounts[@]}"; do
        download_guide_data_for_account "${account}"
    done

    # Check if the merge flag is set, if set, merge all guide data into one single file.
    if [[ -n "${xml_file_to_merge_into}" ]]; then
        merge_guide_data_into_single_file
    fi

    return 0
}

# Description : Checks that the config flag was set on the command line.
# shellcheck disable=SC2317
function pass_config_checks {
    if ! ${mode_config}; then
        die "Use the '-c' flag to enter configuration mode." "${FUNCNAME[0]}"
    fi

    return 0
}

# Requires : Global variable `command_arguments`
# Description : Checks that arguments were supplied on the command line.
# shellcheck disable=SC2317
function pass_config_modification_checks {
    if [[ -z "${command_arguments[*]}" ]]; then
        die "No arguments were passed. Use the '--command-- user=\"bob@mail.com\"' structure." "${FUNCNAME[0]}"
    fi

    return 0
}

# Requires : Global variable `configured_accounts`
# Description : Checks that an account was given on the command line.
# shellcheck disable=SC2317
function pass_account_config_checks {
    if [[ "${#configured_accounts[@]}" -gt 1 ]]; then
        die "You can only modify one account at a time." "${FUNCNAME[0]}"
    fi

    if [[ -z "${configured_accounts[0]}" ]]; then
        die "No account given. Use the '-a name' structure." "${FUNCNAME[0]}"
    fi

    return 0
}

# Attention : This function modifies a global script variable!
# Requires : Global variable `configured_accounts`, `command_keys`, `command_values` and `configuration`
# Description : Changes the values of options in the config for a specified account.
# shellcheck disable=SC2317
function modify_account_config {
    pass_account_config_checks

    local account="${configured_accounts[0]}"

    local account_config
    return_config_for_account "--variable" account_config "--account" "${account}" "--return" "."
    if [[ -z "${account_config}" ]]; then
        die "Can't access config for account: '${account}'" "${FUNCNAME[0]}"
    fi

    local main_config
    return_json_if_found "--variable" main_config "--lookup" ".config"
    local secret
    return_config_section_from_json "--variable" secret "--read" ".secret" "--json" "${main_config}"

    local -a id=()
    id+=(".options[]")
    id+=(".login[]")

    local json="${configuration}"

    local -a keys=("${command_keys[@]}")
    local -a values=("${command_values[@]}")

    local key
    local value
    local config_section
    local search
    local -a login_keys=(user pass)
    local encrypted
    local key_checker

    for k in "${!keys[@]}"; do
        key="${keys[${k}]}"
        value="${values[${k}]}"

        if [[ ${login_keys[*]} =~ ${key} ]]; then
            encrypted=""
            return_encrypted_data "--variable" encrypted "--plaintext" "${value}" "--secret" "${secret}"

            value="${encrypted}"
        fi

        for name in "${!id[@]}"; do
            config_section=""
            return_config_section_from_json "--variable" config_section "--read" "${id["${name}"]}" "--json" "${account_config}"

            key_checker=""
            does_json_contain_key "--variable" key_checker "--key" "${key}" "--json" "${config_section}"

            if ! ${key_checker}; then
                continue;
            fi

            search="(.accounts[] | select(.name==\$search_value))${id[${name}]}.${key} |= \$key"
            message "INFO: Modifying '${key}' for account '${account}' config."

            json="$(/usr/bin/jq \
                --arg key "${value}" \
                --arg search_value "${account}" \
                ''"${search}"'' \
                <<< "${json}")"
            break;
        done
    done

    configuration="${json}"

    return 0
}

# Attention : This function modifies a global script variable!
# Requires : Global variable `command_keys`, `command_values` and `configuration`
# Description : Changes the values of options in the main config
# shellcheck disable=SC2317
function modify_config {
    local json="${configuration}"

    local -a keys=("${command_keys[@]}")
    local -a values=("${command_values[@]}")

    local key
    local value
    local main_config
    local search
    local key_checker

    for k in "${!keys[@]}"; do
        key="${keys[${k}]}"
        value="${values[${k}]}"

        if [[ "secret" == "${key}" ]] && [[ "modify" == "${command}" ]]; then
            message "INFO: Modifying secret directly is forbidden, use secret command instead."
            continue
        fi

        main_config=""
        return_json_if_found "--variable" main_config "--lookup" ".config"

        key_checker=""
        does_json_contain_key "--variable" key_checker "--key" "${key}" "--json" "${main_config}"

        if ${key_checker} ; then
            continue
        fi

        search="(.config).${key} |= \$key"
        message "INFO: Modifying '${key}' for main config."

        json=$(/usr/bin/jq \
            --arg key "${value}" \
            ''"${search}"'' \
            <<< "${json}")
    done

    configuration="${json}"

    return 0
}

# @command modify
# Commands : modify
# Arguments : key_name="value"
# Description : Change value(s) for key(s) in config
# shellcheck disable=SC2317
function modify {
    pass_config_checks
    pass_config_modification_checks

    if [[ -n "${configured_accounts[*]}" ]]; then
        modify_account_config
    else
        modify_config
    fi

    write_changes_to_config

    return 0
}

# @command secret
# Commands : secret
# Arguments :
# Description : Generates a new secret key for your config
# shellcheck disable=SC2317
function secret {
    pass_config_checks

    local main_config
    return_json_if_found "--variable" main_config "--lookup" ".config"

    local previous_secret
    return_config_section_from_json "--variable" previous_secret "--read" ".secret" "--json" "${main_config}"

    local new_secret
    return_random_string "--variable" new_secret "--bits" 64 "--characters" "/a-zA-Z0-9+"

    configured_accounts=()
    command_arguments=(secret="${new_secret}")

    prepare_command_arguments
    modify

    local account_names
    return_account_names "--variable" account_names

    for account in "${account_names[@]}"; do
        configured_accounts=("${account}")

        local account_login
        return_config_for_account "--variable" account_login "--account" "${account}" "--return" ".login[]"
        if [[ -z "${account_login}" ]]; then
            die "Can't access login for account: '${account}'" "${FUNCNAME[0]}"
        fi

        local username
        return_config_section_from_json "--variable" username "--read" ".user" "--json" "${account_login}"
        return_decrypted_data "--variable" username "--secret" "${previous_secret}" "--encrypted" "${username}"

        local password
        return_config_section_from_json "--variable" password "--read" ".pass" "--json" "${account_login}"
        return_decrypted_data "--variable" password "--secret" "${previous_secret}" "--encrypted" "${password}"

        command_arguments=(user="${username}" pass="${password}")

        prepare_command_arguments
        modify
    done

    return 0
}

# @command remove
# Commands : remove
# Arguments :
# Description : Remove specified account(s) in the config
# shellcheck disable=SC2317
function remove {
    pass_config_checks
    pass_account_config_checks

    local account="${configured_accounts[0]}"

    local json="${configuration}"

    search="del(.accounts[] | select(.name==\$search_value))"
    message "INFO: Removing account '${account}' from config."

    json="$(/usr/bin/jq \
        --arg key "${value}" \
        --arg search_value "${account}" \
        ''"${search}"'' \
        <<< "${json}")"

    configuration="${json}"

    write_changes_to_config

    return 0
}

# @command add
# Commands : add
# Arguments : key_name="value"
# Description : Add a new account in the config with or without arguments
# shellcheck disable=SC2317
function add {
    pass_config_checks
    pass_account_config_checks

    local account="${configured_accounts[0]}"

    local account_config
    return_config_for_account "--variable" account_config "--account" "${account}" "--return" "."
    if [[ -n "${account_config}" ]]; then
        die "An account with the name '${account}' already exists." "${FUNCNAME[0]}"
    fi

    local json="${configuration}"

    local cache
    return_default_cache_directory_path "--variable" cache "--account" "${account}"
    local outfile
    return_default_xmltv_output_file_path "--variable" outfile "--account" "${account}"

    message "INFO: Adding new account to config: '${account}'"

    json="$(/usr/bin/jq '.accounts += [{
        "name": "'"${account}"'",
        "options": [
            {
                "days": 12,
                "ncsdays": 2
            }
        ],
        "config": [
            {
                "cache": "'"${cache}"'",
                "outfile": "'"${outfile}"'"
            }
        ],
        "login": [
            {
                "user": "your username",
                "pass": "your password"
            }
        ]
    }]' <<< "${json}")"

    configuration="${json}"

    write_changes_to_config

    if pass_config_modification_checks; then
        modify
    fi

    return 0
}

# @command new
# Commands : new
# Arguments :
# Description : Replaces the current config with a new default config
# shellcheck disable=SC2317
function new {
    pass_config_checks

    local secret
    return_random_string "--variable" secret "--bits" 64 "--characters" "/a-zA-Z0-9+"

    message "INFO: Re-creating the config file from the default settings."

    local json
    json="$(/usr/bin/jq "." <<< '{
        "config": {
            "secret": "'"${secret}"'"
        },
        "accounts": []
    }')"

    configuration="${json}"

    write_changes_to_config

    return 0
}

# @command show
# Commands : show
# Arguments :
# Description : Display the current config
# shellcheck disable=SC2317
function show {
    pass_config_checks

    local main_config
    return_json_if_found "--variable" main_config "--lookup" ".config"

    local config="${main_config}"

    if [[ -n "${configured_accounts[*]}" ]]; then
        pass_account_config_checks

        local account="${configured_accounts[0]}"
        local account_config
        return_config_for_account "--variable" account_config "--account" "${account}" "--return" "."

        config="${account_config}"
    fi

    if [[ -z "${config}" ]]; then
        die "Config could not be found as you requested." "${FUNCNAME[0]}"
    fi

    echo "${config}"
}

# @command list
# Commands : list
# Arguments :
# Description : Display the available config options
# shellcheck disable=SC2317
function list {
    pass_config_checks

    echo "## zap2xml (version ${VERSION}) config options:"
    echo ""
    echo "## Account configuration options:"
    echo -e "#  Key <Value>\t#  Description" | /usr/bin/expand --tabs 35
    echo -e "#  start <integer>\t#  Offset guide data x days." | /usr/bin/expand --tabs 35
    echo -e "#  days <integer>\t#  Download guide data for x days." | /usr/bin/expand --tabs 35
    echo -e "#  ncdays <integer>\t#  Don't cache data for x days from the end." | /usr/bin/expand --tabs 35
    echo -e "#  ncsdays <integer>\t#  Don't cache data for x days from the start." | /usr/bin/expand --tabs 35
    echo -e "#  user <username>\t#  Account login username." | /usr/bin/expand --tabs 35
    echo -e "#  pass <password>\t#  Account login password." | /usr/bin/expand --tabs 35
}

# ------------------- #
# === Main Script === #
# ------------------- #

# If no command line arguments are set, set help as the default argument
if [[ $# -eq 0 ]]; then
    set -- "--help"
fi

create_command_function_variables

# Standardize supplied command line arguments using the getopt tool
command_line_arguments="$(/usr/bin/getopt -n "$0" -o a:m:dhvc -l config,debug,account:,merge:,help,version -- "$@")" || exit 1
eval set -- "${command_line_arguments}"

# Loop through the command line arguments and assign variables if supplied
while true; do
    case "${1}" in
        -d|--debug)
            mode_debug=true
            ;;
        -h|--help)
            help
            exit 0
            ;;
        -v|--version)
            # shellcheck disable=SC2034
            echo "${VERSION}"
            exit 0
            ;;
        -c|--config)
            # shellcheck disable=SC2034
            mode_config=true
            ;;
        -a|--account)
            shift
            configured_accounts+=("${1}")
            ;;
        -m|--merge)
            shift
            # shellcheck disable=SC2034
            xml_file_to_merge_into=${1}
            ;;
        --)
            shift
            command="${1}"
            shift
            # shellcheck disable=SC2034
            command_arguments=("$@")
            break
            ;;
    esac
    shift
done

# If no command is supplied, kill the script
[[ ${command} ]] || die "No command specified"

check_script_path
check_script_for_package_dependencies
check_script_for_file_existance

prepare_command_arguments
load_configuration

# Log basic user supplied command line arguments
message "zap2xml script (${VERSION}) started with ${command_line_arguments}"

# If the command doesn't exist then we don't execute it
for cmd in "${available_command_functions[@]}"; do
    if [[ ${cmd} = "${command}" ]]; then
        ${command} || die "${command} failed."
    fi
done

# Log the command finished time and file size if changed
log_command_running_duration

# If errors exist then log them
if [[ "${errors}" -gt 0 ]]; then
    message "INFO: Script ran with ${errors} errors."
fi

# Exit with the number of errors
exit "${errors}"