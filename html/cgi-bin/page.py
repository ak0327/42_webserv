#!/usr/bin/env python3


def header():
    print('Content-Type: text/html')
    print()


def main():
    print('<html>\n'
          ' <head><title>CGI Test Page</title></head>\n'
          ' <body>\n'
          '  <center><h1>CGI Test Page by Python</h1></center>\n'
          ' </body>\n'
          '</html>')


if __name__ == "__main__":
      header()
      main()
