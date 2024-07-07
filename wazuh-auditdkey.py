import argparse

def process_file(input_file, output_file):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    processed_lines = []
    for line in lines:
        parts = line.split()
        new_lines = [line.strip()]

        # Process '-p' flag
        if '-p' in parts:
            flag_index = parts.index('-p')
            permissions = parts[flag_index + 1]
            if len(permissions) > 1:
                new_lines = [
                    ' '.join(parts[:flag_index] + ['-p', perm] + parts[flag_index + 2:])
                    for perm in permissions
                ]

        # Process '-S' flag
        if '-S' in parts:
            temp_lines = []
            for l in new_lines:
                parts = l.split()
                flag_index = parts.index('-S')
                syscalls = parts[flag_index + 1]
                if len(syscalls.split(',')) > 1:
                    temp_lines.extend([
                        ' '.join(parts[:flag_index] + ['-S', syscall] + parts[flag_index + 2:])
                        for syscall in syscalls.split(',')
                    ])
                else:
                    temp_lines.append(l)
            new_lines = temp_lines

        processed_lines.extend(new_lines)

    with open(output_file, 'w') as f:
        f.writelines([line + '\n' for line in processed_lines])


def modify_output_file(output_file):
    with open(output_file, 'r') as f:
        lines = f.readlines()

    modified_lines = []
    for line in lines:
        parts = line.strip().split()
        if '-k' in parts:
            flag_index = parts.index('-k')
            key = parts[flag_index + 1]

            if '-p' in parts:
                p_index = parts.index('-p')
                p_value = parts[p_index + 1]
                new_key = f'{key}-{p_value}'
                parts[flag_index + 1] = new_key
            elif '-S' in parts:
                s_index = parts.index('-S')
                s_value = parts[s_index + 1]
                new_key = f'{key}-{s_value}'
                parts[flag_index + 1] = new_key

        modified_lines.append(' '.join(parts))

    with open(output_file, 'w') as f:
        f.writelines([line + '\n' for line in modified_lines])


def extract_keys(modified_output_file, keys_file):
    key_dict = {
        'w': 'write',
        'r': 'read',
        'a': 'attribute',
        'x': 'execute',
        'c': 'command'
    }

    keys = set()
    with open(modified_output_file, 'r') as f:
        lines = f.readlines()

    for line in lines:
        parts = line.strip().split()
        if '-k' in parts:
            flag_index = parts.index('-k')
            key = parts[flag_index + 1]

            if '-' in key:
                value = key.split('-')[-1]
                description = key_dict.get(value, 'execute')
                keys.add(f'{key}:{description}')
            else:
                keys.add(f'{key}:execute')

    with open(keys_file, 'w') as f:
        f.writelines([key + '\n' for key in sorted(keys)])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process flags in a file.')
    parser.add_argument('-f', '--file', required=True, help='Input file')
    parser.add_argument('-o', '--output', default='wazuh-audit.rules', help='Output file')
    parser.add_argument('-k', '--keys', default='audit-keys', help='Keys output file')
    args = parser.parse_args()

    process_file(args.file, args.output)
    modify_output_file(args.output)
    extract_keys(args.output, args.keys)

#  -  wazuhAuditKey
#  -  Author: k0jir0900