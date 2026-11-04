"""Export the patched full ARM64 runtime for fresh activation or engine updates."""
import argparse
from build_tools.package_engine import build

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    build(args.output,args.prefix)
