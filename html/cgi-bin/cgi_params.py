#!/usr/bin/env python3

import os


def header():
    print("Content-Type: text/plain")
    print()


def main():
    path_info = os.environ.get('PATH_INFO', '')
    query_string = os.environ.get('QUERY_STRING', '')

    print("Content-type: text/html\n")
    print("<html><body>")

    print("<h1>PATH_INFO and QUERY_STRING</h1>")
    print(f"<p>PATH_INFO   : {path_info}</p>")
    print(f"<p>QUERY_STRING: {query_string}</p>")

    print(f"</body></html>")


if __name__ == "__main__":
    header()
    main()
