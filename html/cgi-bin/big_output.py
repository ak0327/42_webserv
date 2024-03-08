#!/usr/bin/env python3

import os


def header():
    print('Content-Type: text/html')
    print()


def main():
    src_file = os.environ.get('QUERY_STRING', '')
    file = open(f'html/big_size/{src_file}', 'r')
    content = file.read()
    print(content, end='')
    file.close()


if __name__ == "__main__":
    header()
    main()
