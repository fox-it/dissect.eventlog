import argparse

from dissect.eventlog import wevt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("wevt_file", metavar="WEVT", nargs="*", help="WEVT file to parse")
    args, rest = parser.parse_known_args()
    if not args.wevt_file:
        parser.print_help()

    for file in args.wevt_file:
        with open(file, "rb") as file:
            crim = wevt.CRIM(file)
            for header in crim.wevt_headers():
                print(header)
                for wevt_type in header:
                    for wevt_obj in wevt_type:
                        print(wevt_obj)
