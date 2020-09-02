#!/usr/bin/env python3

import requests


def main():
    resp = requests.get("http://localhost:5000")
    print(resp.text)


if __name__ == "__main__":
    main()
